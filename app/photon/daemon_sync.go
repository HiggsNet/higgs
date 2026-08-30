package main

import (
	"context"
	"errors"
	"net"
	"strings"

	photonlinux "github.com/HiggsNet/photon/internal/photonlinux"
	"github.com/HiggsNet/photon/pkg/core/gossip"
	corehost "github.com/HiggsNet/photon/pkg/core/host"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
)

// EnableEventLoopSync configures the event-loop gossip.SyncSession clock. The
// objectPullTCPAddr derives the TCP object-pull address from a gossip UDP
// endpoint. TCP and UDP intentionally share the numeric port.
func objectPullTCPAddr(udpAddr string) string {
	udp, err := net.ResolveUDPAddr("udp", udpAddr)
	if err != nil {
		return ""
	}
	return (&net.TCPAddr{IP: udp.IP, Port: udp.Port}).String()
}

func (d *DaemonService) objectPullResponse(req *gossip.ObjectPullRequest) *gossip.ObjectPullResponse {
	if d == nil || d.hostRuntime == nil {
		return &gossip.ObjectPullResponse{Error: "invalid request"}
	}
	response := d.hostRuntime.GossipObjectPullResponse(req, d.Sync.now())
	if req != nil && response != nil && response.OK && response.Snapshot != nil {
		encoded, _ := gossip.EncodeZoneSnapshotObject(response.Snapshot)
		d.logDebug("object_pull", "lookup_snapshot", map[string]any{
			"zone": req.Zone.String(), "records": len(response.Snapshot.Records), "bytes": len(encoded),
		})
	}
	return response
}

func newDaemonObjectPullExecutor(d *DaemonService) *corehost.GossipObjectPullExecutor {
	return corehost.NewGossipObjectPullExecutor(corehost.GossipObjectPullExecutorConfig{
		Client: photonlinux.GossipObjectPullClient{},
		Discovery: func() corehost.GossipDiscoveryInput {
			return d.hostRuntime.GossipDiscoveryInput(d.currentGossipSuppressions())
		},
		Now: d.Sync.now,
	})
}

// startObjectPullServer binds the platform listener and gives its lifecycle to
// HostRuntime.
func startObjectPullServer(ctx context.Context, d *DaemonService) error {
	if d == nil || d.Sync == nil || d.Sync.Transport == nil || d.hostRuntime == nil {
		return errors.New("object-pull server runtime is not configured")
	}
	addr := objectPullTCPAddr(d.Sync.Transport.LocalAddr().String())
	if addr == "" {
		return nil
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	if err := d.hostRuntime.StartGossipObjectPullServer(ctx, listener, d.objectPullResponse, 0, 0); err != nil {
		_ = listener.Close()
		return err
	}
	d.logInfo("object_pull", "serve_started", map[string]any{"addr": listener.Addr()})
	return nil
}

// event-loop sync path is the only daemon sync path; this helper remains for
// tests that need a fake clock.
func (d *DaemonService) EnableEventLoopSync(clock corehost.Clock) {
	if clock == nil {
		if d.Sync != nil && d.Sync.App != nil && d.Sync.App.Clock != nil {
			clock = corehost.NewClock(d.Sync.App.Clock)
		} else {
			clock = corehost.NewClock(nil)
		}
	}
	if d.hostRuntime == nil {
		d.hostRuntime = corehost.NewRuntime(clock, corehost.DefaultEventBuffer, d.StateStore, gossipHostRuntimeConfig(d.Sync.Config))
		return
	}
	d.hostRuntime.ResetScheduler(clock)
}

func (d *DaemonService) handleSyncTimerEvent(ctx context.Context, force bool) error {
	if d == nil || d.Sync == nil {
		return nil
	}
	now := d.Sync.now()
	input := d.hostRuntime.GossipDiscoveryInput(d.currentGossipSuppressions())
	peers := corehost.GossipOutboundPeers(input, now)
	if len(peers) == 0 {
		return nil
	}
	summary := corestate.CatalogSummaryFor(input.Network)
	d.logDebug("sync", "event_loop_timer", map[string]any{
		"peer_count": len(peers),
		"force":      force,
	})
	for _, peerID := range peers {
		if !force && corehost.GossipBackoffRemaining(input.Peers[peerID], now) > 0 {
			d.logDebug("sync", "event_loop_skipped", map[string]any{
				"peer_id": peerID,
				"reason":  "backoff",
			})
			continue
		}
		if d.hostRuntime.Gossip.HasActiveSession(peerID) {
			d.logDebug("sync", "event_loop_skipped", map[string]any{
				"peer_id": peerID,
				"reason":  "session_active",
			})
			continue
		}
		d.hostRuntime.Gossip.NewSession(peerID)
		event := &gossip.SyncTimerEvent{
			PeerID:       peerID,
			LocalSummary: summary,
		}
		// This function already runs on the daemon event-loop goroutine. Execute
		// the initial event directly so a saturated internal event queue cannot
		// leave an idle session behind forever. Such a zombie session suppresses
		// every later periodic/bootstrap retry as "session_active".
		d.handleSyncEvent(ctx, event)
	}
	return nil
}

func (d *DaemonService) processPacketEvent(packet *gossip.Packet, ctx context.Context) error {
	if packet == nil || packet.Message == nil {
		return errors.New("packet event is nil")
	}
	_, err := d.hostRuntime.HandleGossipHostEvent(ctx, corehost.GossipPacketReceived{Packet: packet}, d.Sync.now(), d.currentGossipSuppressions())
	return err
}

func (d *DaemonService) postSyncEvent(event gossip.SyncEvent) error {
	return d.hostRuntime.PostGossip(event)
}

func (d *DaemonService) handleSyncEvent(ctx context.Context, event gossip.SyncEvent) bool {
	eventNow := d.Sync.now()
	hostResult, err := d.hostRuntime.HandleGossipHostEvent(ctx, corehost.GossipEvent{Value: event}, eventNow, d.currentGossipSuppressions())
	if err != nil {
		return false
	}
	return d.observeSyncEventResult(hostResult.Session)
}

func (d *DaemonService) handleHostRuntimeGossipEvent(ctx context.Context, hostEvent corehost.Event) (corehost.GossipHostEventResult, error) {
	now := d.Sync.now()
	result, err := d.hostRuntime.HandleGossipHostEvent(ctx, hostEvent, now, d.currentGossipSuppressions())
	if result.Session.PeerID != "" && err == nil {
		d.observeSyncEventResult(result.Session)
	}
	return result, err
}

func (d *DaemonService) observeSyncEventResult(result corehost.GossipEventResult) bool {
	peerID := result.PeerID
	if result.Done {
		// Address health and the ephemeral reply route belong to the platform
		// transport. The common Runtime has already removed the session, queued
		// any deferred hint and scheduled relay work before returning here.
		if result.TerminalErr != nil && d.Sync.Transport != nil && strings.Contains(result.TerminalErr.Error(), "timeout") {
			if lastAddr := d.Sync.Transport.LastSendAddr(peerID); lastAddr != nil {
				d.Sync.Transport.RecordAddrFailure(peerID, lastAddr)
			}
		}
		if result.NetworkChanged {
			if d.Sync.Transport != nil {
				d.updateDiscoveredPeers()
			}
			d.notifyStateChanged()
		}
	}
	return result.NetworkChanged
}
