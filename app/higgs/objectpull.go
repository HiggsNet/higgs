package main

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/Catofes/higgs/pkg/core/gossip"
	"github.com/Catofes/higgs/pkg/core/zone"
)

const maxObjectPullConcurrency = 4
const maxObjectPullPerPeerInflight = 2

var objectPullClientLimiter = make(chan struct{}, maxObjectPullConcurrency)
var objectPullPeerLimiter = newObjectPullPeerLimiter(maxObjectPullPerPeerInflight)
var objectPullQuota = newLockedPeerQuotas(gossip.QuotaConfig{
	ByteRate:    8 << 20,
	ByteBurst:   8 << 20,
	ObjectRate:  16,
	ObjectBurst: 16,
})

type objectPullPeerInflight struct {
	limit int
	mu    sync.Mutex
	used  map[string]int
}

func newObjectPullPeerLimiter(limit int) *objectPullPeerInflight {
	return &objectPullPeerInflight{
		limit: limit,
		used:  make(map[string]int),
	}
}

func (l *objectPullPeerInflight) acquire(peerID string) (func(), error) {
	if l == nil || l.limit <= 0 || peerID == "" {
		return func() {}, nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.used[peerID] >= l.limit {
		return nil, fmt.Errorf("object pull per-peer inflight limit reached for %s (%d)", peerID, l.limit)
	}
	l.used[peerID]++
	return func() {
		l.mu.Lock()
		defer l.mu.Unlock()
		l.used[peerID]--
		if l.used[peerID] <= 0 {
			delete(l.used, peerID)
		}
	}, nil
}

type lockedPeerQuotas struct {
	mu     sync.Mutex
	quotas *gossip.PeerQuotas
}

func newLockedPeerQuotas(config gossip.QuotaConfig) *lockedPeerQuotas {
	return &lockedPeerQuotas{quotas: gossip.NewPeerQuotas(config)}
}

func (q *lockedPeerQuotas) allow(peerID string, bytes int64, objects int64, now time.Time) error {
	if q == nil || peerID == "" {
		return nil
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.quotas.Allow(peerID, bytes, objects, now)
}

// objectPullTCPServe starts a minimal TCP server that serves ZoneSnapshot and
// RecordSnapshot objects over length-prefixed msgpack framing.
func objectPullTCPServe(addr string, lookup func(*gossip.ObjectPullRequest) *gossip.ObjectPullResponse) (net.Listener, error) {
	if addr == "" {
		return nil, nil
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				req, err := gossip.DecodeObjectPullRequest(c)
				if err != nil {
					return
				}
				resp := lookup(req)
				if resp == nil {
					resp = &gossip.ObjectPullResponse{Error: "not found"}
				}
				data, err := gossip.EncodeObjectPullResponse(resp)
				if err != nil {
					return
				}
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				_, _ = c.Write(data)
			}(conn)
		}
	}()
	return listener, nil
}

// objectPullTCPAddr derives the default TCP object-pull address from a UDP
// endpoint address. TCP and UDP can share the same numeric port.
func objectPullTCPAddr(udpAddr string) string {
	udp, err := net.ResolveUDPAddr("udp", udpAddr)
	if err != nil {
		return ""
	}
	tcp := &net.TCPAddr{IP: udp.IP, Port: udp.Port}
	return tcp.String()
}

// pullObjectTCP attempts to fetch an object from a peer via TCP.
func pullObjectTCP(addr string, req *gossip.ObjectPullRequest) (*gossip.ObjectPullResponse, error) {
	return pullObjectTCPForPeer("", addr, req)
}

func pullObjectTCPForPeer(peerID, addr string, req *gossip.ObjectPullRequest) (*gossip.ObjectPullResponse, error) {
	select {
	case objectPullClientLimiter <- struct{}{}:
		defer func() { <-objectPullClientLimiter }()
	default:
		return nil, fmt.Errorf("object pull concurrency limit reached (%d)", maxObjectPullConcurrency)
	}
	releasePeer, err := objectPullPeerLimiter.acquire(peerID)
	if err != nil {
		return nil, err
	}
	defer releasePeer()

	data, err := gossip.EncodeObjectPullRequest(req)
	if err != nil {
		return nil, err
	}
	if err := objectPullQuota.allow(peerID, int64(len(data)), 1, time.Now()); err != nil {
		return nil, err
	}
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write(data); err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	resp, err := gossip.DecodeObjectPullResponse(conn)
	if err != nil {
		return nil, err
	}
	if err := objectPullQuota.allow(peerID, int64(encodedObjectPullResponseSize(resp)), 1, time.Now()); err != nil {
		return nil, err
	}
	return resp, nil
}

// objectPullLookup returns a function that can be passed to objectPullTCPServe.
// It accepts a getter so that the daemon can reload state without invalidating
// the closure.
func objectPullLookup(getState func() *stateFile) func(*gossip.ObjectPullRequest) *gossip.ObjectPullResponse {
	return func(req *gossip.ObjectPullRequest) *gossip.ObjectPullResponse {
		state := getState()
		if state == nil || state.Network == nil || req == nil || !req.Zone.Valid() {
			return &gossip.ObjectPullResponse{Error: "invalid request"}
		}
		configureValidation(state.Network)
		now := time.Now()
		switch req.Type {
		case gossip.ObjectPullZone:
			if state.Network.IsZoneRevoked(req.Zone, now) {
				return &gossip.ObjectPullResponse{Error: "zone revoked"}
			}
			snapshot, err := gossip.Snapshot(state.Network, req.Zone)
			if err != nil {
				return &gossip.ObjectPullResponse{Error: err.Error()}
			}
			return &gossip.ObjectPullResponse{OK: true, Snapshot: snapshot}
		case gossip.ObjectPullRecord:
			if req.Key == "" {
				return &gossip.ObjectPullResponse{Error: "missing key"}
			}
			record, err := gossip.RecordSnapshotFor(state.Network, &gossip.FetchRecord{
				Zone:    req.Zone,
				Key:     req.Key,
				Version: req.Version,
			})
			if err != nil {
				return &gossip.ObjectPullResponse{Error: err.Error()}
			}
			return &gossip.ObjectPullResponse{OK: true, Record: record}
		default:
			return &gossip.ObjectPullResponse{Error: "unsupported request type"}
		}
	}
}

// tryObjectPullTCP attempts to pull a zone snapshot over TCP from a peer.
// It derives the TCP address from the peer's discovered or bootstrap UDP address.
func tryObjectPullTCP(state *stateFile, config *syncConfigFile, peerID string, path zone.ZonePath) (*gossip.ZoneSnapshot, error) {
	addr := resolvePeerTCPAddr(state, config, peerID)
	if addr == "" {
		err := fmt.Errorf("no TCP address for peer %s", peerID)
		recordObjectPullResult(state, peerID, "zone", path, "", 0, err, true, time.Now())
		return nil, err
	}
	recordObjectPullAttempt(state, peerID, "zone", path, "", time.Now())
	resp, err := pullObjectTCPForPeer(peerID, addr, &gossip.ObjectPullRequest{
		Type: gossip.ObjectPullZone,
		Zone: path,
	})
	if err != nil {
		recordObjectPullResult(state, peerID, "zone", path, "", 0, err, false, time.Now())
		return nil, err
	}
	respBytes := encodedObjectPullResponseSize(resp)
	if !resp.OK {
		err := fmt.Errorf("object pull failed: %s", resp.Error)
		recordObjectPullResult(state, peerID, "zone", path, "", respBytes, err, false, time.Now())
		return nil, err
	}
	if resp.Snapshot == nil {
		err := fmt.Errorf("object pull returned empty snapshot")
		recordObjectPullResult(state, peerID, "zone", path, "", respBytes, err, false, time.Now())
		return nil, err
	}
	recordObjectPullResult(state, peerID, "zone", path, "", respBytes, nil, false, time.Now())
	return resp.Snapshot, nil
}

// tryObjectPullRecordTCP attempts to pull a single record over TCP from a peer.
func tryObjectPullRecordTCP(state *stateFile, config *syncConfigFile, peerID string, fetch *gossip.FetchRecord) (*gossip.RecordSnapshot, error) {
	if fetch == nil {
		return nil, fmt.Errorf("object pull record selector is nil")
	}
	addr := resolvePeerTCPAddr(state, config, peerID)
	if addr == "" {
		err := fmt.Errorf("no TCP address for peer %s", peerID)
		recordObjectPullResult(state, peerID, "record", fetch.Zone, fetch.Key, 0, err, true, time.Now())
		return nil, err
	}
	recordObjectPullAttempt(state, peerID, "record", fetch.Zone, fetch.Key, time.Now())
	resp, err := pullObjectTCPForPeer(peerID, addr, &gossip.ObjectPullRequest{
		Type:    gossip.ObjectPullRecord,
		Zone:    fetch.Zone,
		Key:     fetch.Key,
		Version: fetch.Version,
	})
	if err != nil {
		recordObjectPullResult(state, peerID, "record", fetch.Zone, fetch.Key, 0, err, false, time.Now())
		return nil, err
	}
	respBytes := encodedObjectPullResponseSize(resp)
	if !resp.OK {
		err := fmt.Errorf("object pull failed: %s", resp.Error)
		recordObjectPullResult(state, peerID, "record", fetch.Zone, fetch.Key, respBytes, err, false, time.Now())
		return nil, err
	}
	if resp.Record == nil {
		err := fmt.Errorf("object pull returned empty record")
		recordObjectPullResult(state, peerID, "record", fetch.Zone, fetch.Key, respBytes, err, false, time.Now())
		return nil, err
	}
	recordObjectPullResult(state, peerID, "record", fetch.Zone, fetch.Key, respBytes, nil, false, time.Now())
	return resp.Record, nil
}

func encodedObjectPullResponseSize(resp *gossip.ObjectPullResponse) int {
	data, err := gossip.EncodeObjectPullResponse(resp)
	if err != nil {
		return 0
	}
	return len(data)
}

func recordObjectPullAttempt(state *stateFile, peerID, object string, zoneName zone.ZonePath, key string, now time.Time) {
	if state == nil || peerID == "" {
		return
	}
	normalizeSyncPeers(state)
	peerState := state.SyncPeers[peerID]
	if peerState.ObjectPullStats == nil {
		peerState.ObjectPullStats = &objectPullStats{}
	}
	peerState.ObjectPullStats.Attempts++
	peerState.ObjectPullStats.LastUnix = now.Unix()
	peerState.ObjectPullStats.LastObject = object
	peerState.ObjectPullStats.LastZone = string(zoneName)
	peerState.ObjectPullStats.LastKey = key
	peerState.ObjectPullStats.LastSourcePeer = peerID
	peerState.ObjectPullStats.LastUnreachable = false
	state.SyncPeers[peerID] = peerState
}

func recordObjectPullResult(state *stateFile, peerID, object string, zoneName zone.ZonePath, key string, bytes int, err error, unreachable bool, now time.Time) {
	if state == nil || peerID == "" {
		return
	}
	normalizeSyncPeers(state)
	peerState := state.SyncPeers[peerID]
	if peerState.ObjectPullStats == nil {
		peerState.ObjectPullStats = &objectPullStats{}
	}
	stats := peerState.ObjectPullStats
	stats.LastUnix = now.Unix()
	stats.LastObject = object
	stats.LastZone = string(zoneName)
	stats.LastKey = key
	stats.LastBytes = bytes
	stats.LastSourcePeer = peerID
	stats.LastUnreachable = unreachable
	if err != nil {
		stats.Failures++
		stats.LastError = err.Error()
		if unreachable {
			stats.LargeObjectUnreachable++
		}
	} else {
		stats.Successes++
		stats.LastError = ""
	}
	state.SyncPeers[peerID] = peerState
}

// resolvePeerTCPAddr returns the best-effort TCP object-pull address for a peer.
func resolvePeerTCPAddr(state *stateFile, config *syncConfigFile, targetPeerID string) string {
	if config == nil || targetPeerID == "" {
		return ""
	}
	// Prefer bootstrap address with the same numeric TCP port.
	for _, peer := range config.Bootstrap {
		if peer.ID == targetPeerID && peer.Addr != "" {
			if tcp := objectPullTCPAddr(peer.Addr); tcp != "" {
				return tcp
			}
		}
	}
	// Fall back to discovered endpoint with the same numeric TCP port.
	if state != nil && state.Network != nil {
		for discoveredID, entries := range gossip.ExtractPeerEndpoints(state.Network) {
			if discoveredID != targetPeerID || len(entries) == 0 {
				continue
			}
			udp := net.JoinHostPort(entries[0].Address, fmt.Sprintf("%d", entries[0].Port))
			if tcp := objectPullTCPAddr(udp); tcp != "" {
				return tcp
			}
		}
	}
	return ""
}

// objectPullListenAddr derives the TCP listen address from the UDP listen addr.
func objectPullListenAddr(listenAddr string) string {
	udp, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return ""
	}
	tcp := &net.TCPAddr{IP: udp.IP, Port: udp.Port}
	return tcp.String()
}

// startObjectPullServer starts the TCP object-pull server for a daemon.
func startObjectPullServer(d *DaemonService) (net.Listener, error) {
	addr := objectPullListenAddr(d.Sync.Config.ListenAddr)
	if addr == "" {
		return nil, nil
	}
	listener, err := objectPullTCPServe(addr, objectPullLookup(func() *stateFile { return d.Sync.State }))
	if err != nil {
		return nil, err
	}
	if listener != nil {
		fmt.Printf("object pull serving on %s\n", listener.Addr())
	}
	return listener, nil
}
