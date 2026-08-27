package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/HiggsNet/photon/internal/observability"
	"github.com/HiggsNet/photon/pkg/core/gossip"
	corehost "github.com/HiggsNet/photon/pkg/core/host"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

const maxObjectPullConcurrency = 4
const maxObjectPullServerConcurrency = 16
const maxObjectPullPerPeerInflight = 2
const objectPullClientDialTimeout = 1500 * time.Millisecond
const objectPullClientIOTimeout = 3 * time.Second
const objectPullServerConnDeadline = 10 * time.Second

var objectPullClientLimiter = make(chan struct{}, maxObjectPullConcurrency)
var objectPullServerLimiter = make(chan struct{}, maxObjectPullServerConcurrency)
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

func acquireObjectPullServerSlot() (func(), bool) {
	select {
	case objectPullServerLimiter <- struct{}{}:
		return func() { <-objectPullServerLimiter }, true
	default:
		return nil, false
	}
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
			release, ok := acquireObjectPullServerSlot()
			if !ok {
				_ = conn.Close()
				continue
			}
			go func(c net.Conn) {
				defer c.Close()
				defer release()
				_ = c.SetDeadline(time.Now().Add(objectPullServerConnDeadline))
				_ = gossip.ServeObjectPull(c, lookup)
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

func pullObjectTCPForPeerUntil(peerID, addr string, req *gossip.ObjectPullRequest, deadline time.Time) (*gossip.ObjectPullResponse, error) {
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
	dialTimeout, err := objectPullClientTimeoutUntil(deadline, objectPullClientDialTimeout)
	if err != nil {
		return nil, err
	}
	conn, err := net.DialTimeout("tcp", addr, dialTimeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	ioDeadline, err := objectPullClientDeadlineUntil(deadline, objectPullClientIOTimeout)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(ioDeadline)
	resp, err := gossip.ExchangeObjectPull(conn, req)
	if err != nil {
		return nil, err
	}
	if err := objectPullQuota.allow(peerID, int64(encodedObjectPullResponseSize(resp)), 1, time.Now()); err != nil {
		return nil, err
	}
	return resp, nil
}

func objectPullClientTimeoutUntil(deadline time.Time, maxTimeout time.Duration) (time.Duration, error) {
	if maxTimeout <= 0 {
		return 0, context.DeadlineExceeded
	}
	if deadline.IsZero() {
		return maxTimeout, nil
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return 0, context.DeadlineExceeded
	}
	if remaining < maxTimeout {
		return remaining, nil
	}
	return maxTimeout, nil
}

func objectPullClientDeadlineUntil(deadline time.Time, maxTimeout time.Duration) (time.Time, error) {
	timeout, err := objectPullClientTimeoutUntil(deadline, maxTimeout)
	if err != nil {
		return time.Time{}, err
	}
	return time.Now().Add(timeout), nil
}

func (d *DaemonService) objectPullResponse(req *gossip.ObjectPullRequest) *gossip.ObjectPullResponse {
	if d == nil || d.StateStore == nil {
		return &gossip.ObjectPullResponse{Error: "invalid request"}
	}
	view := d.StateStore.common.ReadView()
	var network *zone.NetworkState
	if view.State != nil {
		network = view.State.Network
	}
	response := gossip.BuildObjectPullResponse(network, req, time.Now())
	logObjectPullSnapshot(req, response)
	return response
}

func logObjectPullSnapshot(req *gossip.ObjectPullRequest, response *gossip.ObjectPullResponse) {
	if req == nil || response == nil || !response.OK || response.Snapshot == nil {
		return
	}
	logger := newAppLogger(nil)
	logger.Debug("object_pull", "lookup_snapshot", map[string]any{
		"zone":    req.Zone.String(),
		"records": len(response.Snapshot.Records),
		"bytes":   encodedZoneSnapshotSize(response.Snapshot),
	})
}

func tryObjectPullTCPUntil(state *stateFile, config *syncConfigFile, peerID string, path zone.ZonePath, deadline time.Time) (*corestate.ZoneSnapshot, error) {
	addr := resolvePeerTCPAddr(state, config, peerID)
	if addr == "" {
		return nil, fmt.Errorf("no TCP address for peer %s", peerID)
	}
	resp, err := pullObjectTCPForPeerUntil(peerID, addr, &gossip.ObjectPullRequest{
		Type: gossip.ObjectPullZone,
		Zone: path,
	}, deadline)
	if err != nil {
		return nil, err
	}
	if !resp.OK {
		err := fmt.Errorf("object pull failed: %s", resp.Error)
		return nil, err
	}
	if resp.Snapshot == nil {
		err := fmt.Errorf("object pull returned empty snapshot")
		return nil, err
	}
	return resp.Snapshot, nil
}

func encodedObjectPullResponseSize(resp *gossip.ObjectPullResponse) int {
	data, err := gossip.EncodeObjectPullResponse(resp)
	if err != nil {
		return 0
	}
	return len(data)
}

func encodedZoneSnapshotSize(snapshot *corestate.ZoneSnapshot) int {
	data, err := gossip.EncodeZoneSnapshotObject(snapshot)
	if err != nil {
		return 0
	}
	return len(data)
}

func isObjectPullUnreachable(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func recordObjectPullAttempt(store *observability.PeerObservabilityStore, peerID, object string, zoneName zone.ZonePath, key string, now time.Time) {
	if store == nil || peerID == "" {
		return
	}
	store.Update(peerID, now, func(snapshot *observability.PeerDiagnostics) {
		if snapshot.ObjectPullStats == nil {
			snapshot.ObjectPullStats = &objectPullStats{}
		}
		snapshot.ObjectPullStats.Attempts++
		snapshot.ObjectPullStats.LastUnix = now.Unix()
		snapshot.ObjectPullStats.LastObject = object
		snapshot.ObjectPullStats.LastZone = string(zoneName)
		snapshot.ObjectPullStats.LastKey = key
		snapshot.ObjectPullStats.LastSourcePeer = peerID
		snapshot.ObjectPullStats.LastUnreachable = false
	})
}

func recordObjectPullResult(store *observability.PeerObservabilityStore, peerID, object string, zoneName zone.ZonePath, key string, bytes int, err error, unreachable bool, now time.Time) {
	if store == nil || peerID == "" {
		return
	}
	store.Update(peerID, now, func(snapshot *observability.PeerDiagnostics) {
		if snapshot.ObjectPullStats == nil {
			snapshot.ObjectPullStats = &objectPullStats{}
		}
		stats := snapshot.ObjectPullStats
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
	})
}

func (d *DaemonService) observeObjectPullAttempt(peerID string, path zone.ZonePath, now time.Time) {
	if d == nil {
		return
	}
	recordObjectPullAttempt(d.PeerObservability, peerID, "zone", path, "", now)
}

func (d *DaemonService) observeObjectPullResult(result objectPullTransportResult) {
	if d == nil || d.Sync == nil {
		return
	}
	recordObjectPullResult(d.PeerObservability, result.PeerID, "zone", result.Zone, "", result.Bytes, result.Err, result.Unreachable, d.Sync.now())
}

// resolvePeerTCPAddr returns the best-effort TCP object-pull address for a peer.
func resolvePeerTCPAddr(state *stateFile, config *syncConfigFile, targetPeerID string) string {
	if config == nil || targetPeerID == "" {
		return ""
	}
	// Prefer the currently verified observed path. UDP reachability can learn a
	// better public/NAT path than a stale signed or bootstrap endpoint, and TCP
	// object pull uses the same numeric port on that path.
	if state != nil {
		peerState := state.SyncPeers[targetPeerID]
		now := time.Now()
		if observedPathActive(peerState, now) && peerChainVerified(state, targetPeerID, now) {
			if tcp := objectPullTCPAddr(peerState.ObservedAddr); tcp != "" {
				return tcp
			}
		}
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
	var privateTCP string
	if state != nil && state.Network != nil {
		for discoveredID, entries := range gossip.ExtractPeerEndpoints(state.Network) {
			if discoveredID != targetPeerID || len(entries) == 0 {
				continue
			}
			for _, entry := range sortedEndpointEntriesForDial(entries) {
				udp := net.JoinHostPort(entry.Address, fmt.Sprintf("%d", entry.Port))
				tcp := objectPullTCPAddr(udp)
				if tcp == "" {
					continue
				}
				if endpointEntryIsPrivate(entry) {
					if privateTCP == "" {
						privateTCP = tcp
					}
					continue
				}
				return tcp
			}
		}
	}
	if privateTCP != "" {
		return privateTCP
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
	listener, err := objectPullTCPServe(addr, d.objectPullResponse)
	if err != nil {
		return nil, err
	}
	if listener != nil {
		d.logInfo("object_pull", "serve_started", map[string]any{"addr": listener.Addr()})
	}
	return listener, nil
}

// objectPullTransportResult contains Linux transport diagnostics produced alongside a
// common HostRuntime completion. It is never a second event or state channel.
type objectPullTransportResult struct {
	PeerID      string
	Zone        zone.ZonePath
	Snapshot    *corestate.ZoneSnapshot
	Bytes       int
	Unreachable bool
	Err         error
}

type daemonObjectPullWorker struct{ daemon *DaemonService }

func (worker daemonObjectPullWorker) PullGossipObject(ctx context.Context, action gossip.StartObjectPullAction) corehost.GossipObjectPullCompletion {
	result := worker.pull(ctx, action)
	if worker.daemon != nil {
		worker.daemon.observeObjectPullResult(result)
	}
	return corehost.GossipObjectPullCompletion{PeerID: result.PeerID, Zone: result.Zone, Snapshot: result.Snapshot, Err: result.Err}
}

func (worker daemonObjectPullWorker) pull(ctx context.Context, action gossip.StartObjectPullAction) objectPullTransportResult {
	logger := newAppLogger(nil)
	result := objectPullTransportResult{PeerID: action.PeerID, Zone: action.Zone}
	if worker.daemon == nil || worker.daemon.StateStore == nil || worker.daemon.Sync == nil {
		result.Err = errors.New("object pull daemon is not initialized")
		result.Unreachable = true
		return result
	}
	input := worker.daemon.currentGossipDiscoveryInput()
	if input.Network == nil {
		result.Err = fmt.Errorf("no committed state for peer %s", action.PeerID)
		result.Unreachable = true
		return result
	}
	addr := corehost.ResolveGossipObjectPullAddress(input, action.PeerID, worker.daemon.Sync.now())
	if addr == "" {
		result.Err = fmt.Errorf("no TCP address for peer %s", action.PeerID)
		result.Unreachable = true
		logger.Info("object_pull", "worker_no_addr", map[string]any{"peer_id": action.PeerID, "zone": action.Zone.String()})
		return result
	}
	worker.daemon.observeObjectPullAttempt(action.PeerID, action.Zone, worker.daemon.Sync.now())
	logger.Debug("object_pull", "worker_start", map[string]any{"peer_id": action.PeerID, "zone": action.Zone.String(), "addr": addr})
	deadline, _ := ctx.Deadline()
	resp, err := pullObjectTCPForPeerUntil(action.PeerID, addr, &gossip.ObjectPullRequest{
		Type: gossip.ObjectPullZone,
		Zone: action.Zone,
	}, deadline)
	respBytes := 0
	if resp != nil {
		respBytes = encodedObjectPullResponseSize(resp)
	}
	result.Bytes = respBytes
	logger.Debug("object_pull", "worker_done", map[string]any{"peer_id": action.PeerID, "zone": action.Zone.String(), "ok": err == nil && resp != nil && resp.OK && resp.Snapshot != nil, "bytes": respBytes, "error": errString(err)})
	unreachable := isObjectPullUnreachable(err)
	if err != nil {
		result.Unreachable = unreachable
		result.Err = err
		return result
	}
	if resp == nil || !resp.OK {
		if resp == nil {
			result.Err = errors.New("object pull returned empty response")
		} else {
			result.Err = fmt.Errorf("object pull failed: %s", resp.Error)
		}
		return result
	}
	if resp.Snapshot == nil {
		result.Err = errors.New("object pull returned empty snapshot")
		return result
	}
	result.Snapshot = resp.Snapshot
	return result
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
