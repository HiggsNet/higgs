package main

import (
	"context"
	"encoding/hex"
	"errors"
	"net"
	"strings"
	"time"

	photonlinux "github.com/HiggsNet/photon/internal/photonlinux"
	"github.com/HiggsNet/photon/pkg/core/gossip"
	corehost "github.com/HiggsNet/photon/pkg/core/host"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
)

// EnableEventLoopSync configures the event-loop gossip.SyncSession clock. The
const syncIngressRouteTTL = time.Minute

type syncIngressRoute struct {
	addr  *net.UDPAddr
	until time.Time
}

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
	controller := &daemonGossipIO{
		daemon: d,
	}
	_, err := d.hostRuntime.HandleGossipHostEvent(ctx, corehost.GossipPacketReceived{Packet: packet}, d.Sync.now(), controller)
	return err
}

func (d *DaemonService) recordVerifiedObservedCheckpoint(peerID string, addr *net.UDPAddr, now time.Time) bool {
	if d == nil || d.StateStore == nil || addr == nil || peerID == "" {
		return false
	}
	committed, err := d.hostRuntime.RecordGossipObservedPath(context.Background(), peerID, addr.String(), d.currentGossipSuppressions(), now)
	if err != nil {
		d.logWarn("sync", "observed_checkpoint_commit_failed", map[string]any{"peer_id": peerID, "error": err})
		return false
	}
	return committed
}

func (d *DaemonService) postSyncEvent(event gossip.SyncEvent) error {
	return d.hostRuntime.PostGossip(event)
}

func (d *DaemonService) handleSyncEvent(ctx context.Context, event gossip.SyncEvent) bool {
	eventNow := d.Sync.now()
	controller := &daemonGossipIO{
		daemon: d,
	}
	hostResult, err := d.hostRuntime.HandleGossipHostEvent(ctx, corehost.GossipEvent{Value: event}, eventNow, controller)
	if err != nil {
		return false
	}
	return d.observeSyncEventResult(hostResult.Session)
}

func (d *DaemonService) handleHostRuntimeGossipEvent(ctx context.Context, hostEvent corehost.Event) (corehost.GossipHostEventResult, error) {
	now := d.Sync.now()
	controller := &daemonGossipIO{daemon: d}
	result, err := d.hostRuntime.HandleGossipHostEvent(ctx, hostEvent, now, controller)
	if result.Session.PeerID != "" && err == nil {
		d.observeSyncEventResult(result.Session)
	}
	return result, err
}

func (d *DaemonService) observeSyncEventResult(result corehost.GossipEventResult) bool {
	peerID := result.PeerID
	session := d.hostRuntime.Gossip.Session(peerID)
	if result.Done {
		d.completeSyncSessionAfterPeerState(session, session.NetworkChanged())
	}
	return result.NetworkChanged
}

type daemonGossipIO struct {
	daemon    *DaemonService
	replyAddr *net.UDPAddr
}

func (controller *daemonGossipIO) PrepareGossipInbound(_ context.Context, packet *gossip.Packet, now time.Time) error {
	controller.replyAddr = nil
	if packet == nil || packet.Message == nil {
		return nil
	}
	controller.replyAddr = packet.Addr
	msg := packet.Message
	controller.daemon.rememberSyncIngressRoute(msg.PeerID, packet.Addr, now)
	if controller.daemon.recordVerifiedObservedCheckpoint(msg.PeerID, packet.Addr, now) {
		recordObservedSource(controller.daemon.hostRuntime.Observability, msg.PeerID, msg.Type, now)
	}
	controller.daemon.seedObservedPeerPath(msg.PeerID)
	return nil
}

func (controller *daemonGossipIO) GossipDatagramBudget() int {
	return controller.daemon.syncDatagramBudget()
}

func (controller *daemonGossipIO) SendGossip(_ context.Context, outbound gossip.OutboundMessage) error {
	if controller.replyAddr != nil {
		return controller.daemon.sendSyncMessageTo(outbound.PeerID, controller.replyAddr, outbound.Message)
	}
	return controller.daemon.sendSyncSessionMessage(outbound.PeerID, outbound.Message)
}

func (d *DaemonService) syncDatagramBudget() int {
	budget := gossip.DefaultMaxMessage
	if d != nil && d.Sync != nil && d.Sync.Transport != nil {
		if m := d.Sync.Transport.MaxMessageBytes(); m > 0 {
			budget = m
		}
	}
	return budget
}

// rememberSyncIngressRoute keeps the source of a recently accepted inbound
// packet as an ephemeral route for the active pull it triggered. The route is
// never persisted or promoted to a verified observed path here.
func (d *DaemonService) rememberSyncIngressRoute(peerID string, addr *net.UDPAddr, now time.Time) {
	if d == nil || peerID == "" || addr == nil {
		return
	}
	if d.syncIngressRoutes == nil {
		d.syncIngressRoutes = make(map[string]syncIngressRoute)
	}
	copied := *addr
	d.syncIngressRoutes[peerID] = syncIngressRoute{addr: &copied, until: now.Add(syncIngressRouteTTL)}
}

func (d *DaemonService) syncIngressRouteAddr(peerID string, now time.Time) *net.UDPAddr {
	if d == nil || peerID == "" || d.syncIngressRoutes == nil {
		return nil
	}
	route, ok := d.syncIngressRoutes[peerID]
	if !ok || route.addr == nil || !now.Before(route.until) {
		delete(d.syncIngressRoutes, peerID)
		return nil
	}
	copied := *route.addr
	return &copied
}

func (d *DaemonService) clearSyncIngressRoute(peerID string) {
	if d == nil || d.syncIngressRoutes == nil {
		return
	}
	delete(d.syncIngressRoutes, peerID)
}

func (d *DaemonService) sendSyncSessionMessage(peerID string, msg *gossip.Message) error {
	var replyAddr *net.UDPAddr
	if d != nil && d.Sync != nil {
		replyAddr = d.syncIngressRouteAddr(peerID, d.Sync.now())
	}
	return d.sendSyncMessageTo(peerID, replyAddr, msg)
}

func (d *DaemonService) sendSyncMessageTo(peerID string, replyAddr *net.UDPAddr, msg *gossip.Message) error {
	if d.Sync == nil || d.Sync.Transport == nil {
		return nil
	}
	budget := d.syncDatagramBudget()
	size, sizeErr := gossip.WireEncodeSizeForPeer(msg, d.Sync.Transport.PeerID())
	if sizeErr != nil {
		return sizeErr
	}
	if size > budget {
		object := string(msg.Type)
		recordDatagramTooLarge(d.hostRuntime.Observability, peerID, "send", object, "", "", size, budget, d.Sync.now())
		d.logWarn("transport", "datagram_too_large", map[string]any{
			"peer_id": peerID,
			"type":    msg.Type,
			"bytes":   size,
			"limit":   budget,
			"action":  "drop",
		})
		return gossip.ErrMessageTooLarge
	}
	var err error
	if replyAddr != nil {
		err = d.Sync.Transport.SendTo(peerID, replyAddr, msg)
	} else {
		err = d.Sync.Transport.Send(peerID, msg)
	}
	if err != nil {
		replyAddrText := ""
		if replyAddr != nil {
			replyAddrText = replyAddr.String()
		}
		d.logDebug("sync", "send_failed", map[string]any{
			"peer_id":    peerID,
			"type":       msg.Type,
			"reply_addr": replyAddrText,
			"error":      err,
		})
	}
	return err
}

func (d *DaemonService) completeSyncSessionAfterPeerState(session *gossip.SyncSession, changed bool) {
	if session == nil {
		return
	}
	peerID := session.PeerID
	d.hostRuntime.CancelGossipTimers(peerID)
	// Only mark the last-used address as failing for timeout-like errors; do
	// not penalize the address for internal/event handling failures.
	if session.LastError() != nil && d.Sync.Transport != nil && strings.Contains(session.LastError().Error(), "timeout") {
		if lastAddr := d.Sync.Transport.LastSendAddr(peerID); lastAddr != nil {
			d.Sync.Transport.RecordAddrFailure(peerID, lastAddr)
		}
	}
	if session.State == gossip.SyncSessionCompleted && changed {
		if d.Sync.Transport != nil {
			d.updateDiscoveredPeers()
		}
		d.notifyStateChanged()
		d.relaySyncToPeers(peerID)
	}
	d.hostRuntime.Gossip.RemoveSession(peerID)
	if d.hostRuntime.Gossip.TakePendingHint(peerID) {
		_ = d.hostRuntime.StartGossipSession(peerID, "announce_hint_followup")
		return
	}
	d.clearSyncIngressRoute(peerID)
}

func (d *DaemonService) relaySyncToPeers(sourcePeerID string) {
	if d == nil || d.Sync == nil {
		return
	}
	now := d.Sync.now()
	relayed := 0
	input := d.hostRuntime.GossipDiscoveryInput(d.currentGossipSuppressions())
	summary := corestate.CatalogSummaryFor(input.Network)
	if summary == nil {
		return
	}
	peers := corehost.GossipOutboundPeers(input, now)
	catalogRoot := hex.EncodeToString(summary.CatalogRoot)
	for _, peerID := range peers {
		if peerID == sourcePeerID {
			continue
		}
		if relayed >= maxRelayFanoutPerUpdate {
			recordRelaySuppression(d.hostRuntime.Observability, peerID, "relay_fanout_limited", now)
			continue
		}
		allowed, reason := corehost.ShouldRelayGossipUpdate(input.Peers[peerID], peerID, sourcePeerID, catalogRoot, now)
		if !allowed {
			recordRelaySuppression(d.hostRuntime.Observability, peerID, reason, now)
			continue
		}
		relayed++
		if d.hostRuntime.Gossip.HasActiveSession(peerID) {
			continue
		}
		d.hostRuntime.Gossip.NewSession(peerID)
		if err := d.hostRuntime.PostGossip(&gossip.SyncTimerEvent{
			PeerID:       peerID,
			LocalSummary: summary,
		}); err != nil {
			d.logWarn("sync", "relay_event_full", map[string]any{"peer_id": peerID, "source_peer": sourcePeerID})
			d.hostRuntime.Gossip.RemoveSession(peerID)
			continue
		}
		committed, err := d.hostRuntime.RecordGossipRelay(context.Background(), peerID, catalogRoot, now)
		if err != nil {
			d.logWarn("sync", "relay_checkpoint_commit_failed", map[string]any{"peer_id": peerID, "error": err})
		}
		if committed {
			recordRelaySuccessDiagnostics(d.hostRuntime.Observability, peerID, sourcePeerID, now)
		}
	}
}
