package main

import (
	"fmt"
	"net"
	"time"

	"github.com/Catofes/higgs/pkg/core/gossip"
	"github.com/Catofes/higgs/pkg/core/zone"
)

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
// endpoint address by incrementing the port by one.
func objectPullTCPAddr(udpAddr string) string {
	udp, err := net.ResolveUDPAddr("udp", udpAddr)
	if err != nil {
		return ""
	}
	tcp := &net.TCPAddr{IP: udp.IP, Port: udp.Port + 1}
	return tcp.String()
}

// pullObjectTCP attempts to fetch an object from a peer via TCP.
func pullObjectTCP(addr string, req *gossip.ObjectPullRequest) (*gossip.ObjectPullResponse, error) {
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	data, err := gossip.EncodeObjectPullRequest(req)
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write(data); err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	return gossip.DecodeObjectPullResponse(conn)
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
		return nil, fmt.Errorf("no TCP address for peer %s", peerID)
	}
	resp, err := pullObjectTCP(addr, &gossip.ObjectPullRequest{
		Type: gossip.ObjectPullZone,
		Zone: path,
	})
	if err != nil {
		return nil, err
	}
	if !resp.OK {
		return nil, fmt.Errorf("object pull failed: %s", resp.Error)
	}
	if resp.Snapshot == nil {
		return nil, fmt.Errorf("object pull returned empty snapshot")
	}
	return resp.Snapshot, nil
}

// tryObjectPullRecordTCP attempts to pull a single record over TCP from a peer.
func tryObjectPullRecordTCP(state *stateFile, config *syncConfigFile, peerID string, fetch *gossip.FetchRecord) (*gossip.RecordSnapshot, error) {
	addr := resolvePeerTCPAddr(state, config, peerID)
	if addr == "" {
		return nil, fmt.Errorf("no TCP address for peer %s", peerID)
	}
	resp, err := pullObjectTCP(addr, &gossip.ObjectPullRequest{
		Type:    gossip.ObjectPullRecord,
		Zone:    fetch.Zone,
		Key:     fetch.Key,
		Version: fetch.Version,
	})
	if err != nil {
		return nil, err
	}
	if !resp.OK {
		return nil, fmt.Errorf("object pull failed: %s", resp.Error)
	}
	if resp.Record == nil {
		return nil, fmt.Errorf("object pull returned empty record")
	}
	return resp.Record, nil
}

// resolvePeerTCPAddr returns the best-effort TCP object-pull address for a peer.
func resolvePeerTCPAddr(state *stateFile, config *syncConfigFile, targetPeerID string) string {
	if config == nil || targetPeerID == "" {
		return ""
	}
	// Prefer bootstrap address with port+1.
	for _, peer := range config.Bootstrap {
		if peer.ID == targetPeerID && peer.Addr != "" {
			if tcp := objectPullTCPAddr(peer.Addr); tcp != "" {
				return tcp
			}
		}
	}
	// Fall back to discovered endpoint with port+1.
	if state != nil && state.Network != nil {
		for discoveredID, entries := range gossip.ExtractPeerEndpoints(state.Network) {
			if discoveredID != targetPeerID || len(entries) == 0 {
				continue
			}
			if tcp := objectPullTCPAddr(entries[0].Address); tcp != "" {
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
	tcp := &net.TCPAddr{IP: udp.IP, Port: udp.Port + 1}
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
