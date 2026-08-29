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
	"github.com/HiggsNet/photon/pkg/core/zone"
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
		ObserveAttempt: func(peerID string, path zone.ZonePath, now time.Time) {
			d.observeObjectPullAttempt(peerID, path, now)
			d.logDebug("object_pull", "worker_start", map[string]any{"peer_id": peerID, "zone": path.String()})
		},
		ObserveResult: func(result corehost.GossipObjectPullDiagnostics) {
			d.observeObjectPullResult(result)
			errorText := ""
			if result.Err != nil {
				errorText = result.Err.Error()
			}
			d.logDebug("object_pull", "worker_done", map[string]any{
				"peer_id": result.PeerID, "zone": result.Zone.String(), "ok": result.Err == nil,
				"bytes": result.Bytes, "error": errorText,
			})
		},
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
	controller := &daemonGossipActionController{
		daemon: d,
		now:    d.Sync.now(),
		limits: syncLimits(d.Sync.Config),
	}
	_, err := d.hostRuntime.HandleGossipHostEvent(ctx, corehost.GossipPacketReceived{Packet: packet}, controller.now, controller)
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

func (d *DaemonService) handleAnnounceHint(peerID string) error {
	if d == nil || d.Sync == nil || peerID == "" {
		return nil
	}
	now := d.Sync.now()
	if d.hostRuntime.Gossip.HasActiveSession(peerID) {
		d.hostRuntime.Gossip.DeferHint(peerID)
		recordSyncHint(d.PeerObservability, peerID, "announce_hint", "session_active", false, now)
		d.logDebug("sync", "announce_hint_suppressed", map[string]any{
			"peer_id": peerID,
			"reason":  "session_active",
		})
		return nil
	}
	return d.startHintedSyncSession(peerID, "announce_hint")
}

func (d *DaemonService) startHintedSyncSession(peerID, reason string) error {
	if d == nil || d.Sync == nil || peerID == "" {
		return nil
	}
	now := d.Sync.now()
	summary := d.hostRuntime.GossipCatalogSummary()
	if summary == nil {
		return nil
	}
	session := d.hostRuntime.Gossip.NewSession(peerID)
	if err := d.hostRuntime.PostGossip(&gossip.SyncTimerEvent{
		PeerID:       peerID,
		LocalSummary: summary,
	}); err != nil {
		d.logWarn("sync", "event_dropped", map[string]any{"reason": "sync_events_full"})
		d.hostRuntime.Gossip.RemoveSession(peerID)
		return err
	}
	recordSyncHint(d.PeerObservability, peerID, reason, "", true, now)
	recordSyncActivePull(d.PeerObservability, peerID, "hint_queued", session, now)
	d.logDebug("sync", "hinted_sync_started", map[string]any{
		"peer_id": peerID,
		"reason":  reason,
	})
	return nil
}
func (d *DaemonService) postSyncEvent(event gossip.SyncEvent) error {
	return d.hostRuntime.PostGossip(event)
}

func (d *DaemonService) respondFetchZoneTo(peerID string, path zone.ZonePath, replyAddr *net.UDPAddr) error {
	if d == nil || d.Sync == nil {
		return nil
	}
	budget := d.syncDatagramBudget()
	response := d.hostRuntime.GossipFetchZoneResponse(path, budget, d.Sync.now())
	if !response.Found {
		d.logDebug("sync", "fetch_zone_snapshot_missing", map[string]any{
			"peer_id": peerID,
			"zone":    path,
			"error":   zone.ErrZoneNotFound,
			"via":     "responder",
		})
		return nil
	}
	return d.respondAnnouncePlanTo(peerID, response.Plan, budget, replyAddr)
}

func (d *DaemonService) respondFetchZoneChunksTo(peerID string, path zone.ZonePath, replyAddr *net.UDPAddr) error {
	if d == nil || d.Sync == nil || d.Sync.Transport == nil {
		return nil
	}
	now := d.Sync.now()
	response := d.hostRuntime.GossipFetchZoneResponse(path, d.syncDatagramBudget(), now)
	if response.Snapshot == nil {
		return nil
	}
	diag, err := sendDetachedSnapshotWithDiagnosticsTo(response.Snapshot, response.Plan, d.Sync.Transport, peerID, replyAddr, now, d.Sync.logger())
	recordDatagramSendDiagnostics(d.PeerObservability, peerID, diag, d.syncDatagramBudget(), now)
	return err
}

func (d *DaemonService) respondAnnouncePlanTo(peerID string, plan gossip.DatagramPlan, budget int, replyAddr *net.UDPAddr) error {
	if d == nil || d.Sync == nil {
		return nil
	}
	for _, oversized := range plan.Oversized {
		recordDatagramTooLarge(d.PeerObservability, peerID, "send", oversized.Object, oversized.Zone, oversized.Key, oversized.Size, budget, d.Sync.now())
		d.logDebug("transport", "datagram_too_large", map[string]any{
			"peer_id": peerID,
			"object":  oversized.Object,
			"zone":    oversized.Zone,
			"key":     oversized.Key,
			"bytes":   oversized.Size,
			"limit":   budget,
			"via":     "responder",
		})
	}
	for _, announce := range plan.Announces {
		if announce == nil {
			continue
		}
		d.logInfo("sync", "sending_announce", map[string]any{
			"peer_id": peerID,
			"digests": len(announce.Zones),
			"via":     "responder",
		})
		d.sendSyncMessageTo(peerID, replyAddr, &gossip.Message{
			Type:     gossip.MessageAnnounce,
			Announce: announce,
		})
	}
	return nil
}

func (d *DaemonService) handleSyncEvent(ctx context.Context, event gossip.SyncEvent) bool {
	eventNow := d.Sync.now()
	controller := &daemonGossipActionController{
		daemon: d, now: eventNow, limits: syncLimits(d.Sync.Config),
	}
	result, err := d.hostRuntime.HandleGossipEvent(ctx, event, eventNow, controller)
	if err != nil {
		return false
	}
	return d.observeSyncEventResult(event, result, eventNow)
}

func (d *DaemonService) handleHostRuntimeGossipEvent(ctx context.Context, hostEvent corehost.Event) (corehost.GossipHostEventResult, error) {
	now := d.Sync.now()
	controller := &daemonGossipActionController{daemon: d, now: now, limits: syncLimits(d.Sync.Config)}
	result, err := d.hostRuntime.HandleGossipHostEvent(ctx, hostEvent, now, controller)
	if result.Event != nil && err == nil {
		d.observeSyncEventResult(result.Event, result.Session, now)
	}
	return result, err
}

func (d *DaemonService) observeSyncEventResult(event gossip.SyncEvent, result corehost.GossipEventResult, eventNow time.Time) bool {
	peerID := result.PeerID
	session := d.hostRuntime.Gossip.Session(peerID)
	eventName := gossip.SyncEventName(event)
	activeSession := &gossip.SyncSession{State: session.State}
	recordSyncActivePull(d.PeerObservability, peerID, eventName, activeSession, eventNow)
	if result.Done {
		d.completeSyncSessionAfterPeerState(session, session.NetworkChanged())
	}
	return result.NetworkChanged
}

func snapshotApplyVia(action gossip.ApplySnapshotAction) string {
	if action.Via != "" {
		return action.Via
	}
	return "event_loop"
}

type daemonGossipActionController struct {
	daemon    *DaemonService
	now       time.Time
	limits    corestate.SyncLimits
	replyAddr *net.UDPAddr
}

func (controller *daemonGossipActionController) ObserveGossipInbound(_ context.Context, packet *gossip.Packet, now time.Time) error {
	controller.now = now
	controller.replyAddr = nil
	if packet == nil || packet.Message == nil {
		return nil
	}
	controller.replyAddr = packet.Addr
	msg := packet.Message
	controller.daemon.rememberSyncIngressRoute(msg.PeerID, packet.Addr, now)
	if controller.daemon.recordVerifiedObservedCheckpoint(msg.PeerID, packet.Addr, now) {
		recordObservedSource(controller.daemon.PeerObservability, msg.PeerID, msg.Type, now)
	}
	controller.daemon.seedObservedPeerPath(msg.PeerID)
	return nil
}

func (controller *daemonGossipActionController) GossipDatagramBudget() int {
	return controller.daemon.syncDatagramBudget()
}

func (controller *daemonGossipActionController) ObserveGossipCatalogSummary(peerID string, summary *corestate.CatalogSummary) {
	recordCatalogSummary(controller.daemon.PeerObservability, peerID, summary, controller.now)
}

func (controller *daemonGossipActionController) ObserveGossipCatalogPage(peerID string, page *corestate.CatalogPage) {
	recordCatalogPage(controller.daemon.PeerObservability, peerID, page, controller.now)
	recordReadOnlyResponder(controller.daemon.PeerObservability, peerID, "catalog_page", "", controller.now)
}

func (controller *daemonGossipActionController) ObserveGossipChunkRepair(peerID string) {
	recordDatagramRepairNACK(controller.daemon.PeerObservability, peerID, false, controller.now)
}

func (controller *daemonGossipActionController) ObserveGossipCatalogReject(peerID, cursor string, err error) {
	budget := controller.GossipDatagramBudget()
	recordDatagramTooLarge(controller.daemon.PeerObservability, peerID, "send", "catalog_page", "", "", 0, budget, controller.now)
	recordCatalogReject(controller.daemon.PeerObservability, peerID, cursor, gossip.RejectReason(err), controller.now)
	controller.daemon.logWarn("sync", "catalog_page_failed", map[string]any{
		"peer_id": peerID,
		"cursor":  cursor,
		"error":   err,
		"via":     "responder",
	})
}

func (controller *daemonGossipActionController) ObserveGossipSummaryMatch(peerID string) {
	recordSyncHint(controller.daemon.PeerObservability, peerID, "ping_summary_match", "", true, controller.now)
	controller.daemon.logDebug("sync", "ping_summary_shortcut", map[string]any{
		"peer_id": peerID,
		"reason":  "catalog_root_match",
	})
}

func (controller *daemonGossipActionController) HandleGossipAnnounceHint(_ context.Context, peerID string) error {
	return controller.daemon.handleAnnounceHint(peerID)
}

func (controller *daemonGossipActionController) RespondGossipFetchZone(_ context.Context, peerID string, request *gossip.FetchZone) error {
	if request == nil {
		return nil
	}
	if request.ChunkFallback {
		recordReadOnlyResponder(controller.daemon.PeerObservability, peerID, "chunk_fallback", request.Zone, controller.now)
		return controller.daemon.respondFetchZoneChunksTo(peerID, request.Zone, controller.replyAddr)
	}
	recordReadOnlyResponder(controller.daemon.PeerObservability, peerID, "fetch_zone", request.Zone, controller.now)
	return controller.daemon.respondFetchZoneTo(peerID, request.Zone, controller.replyAddr)
}

func (controller *daemonGossipActionController) ObserveGossipObjectChunk(result corehost.GossipObjectChunkResult) {
	if result.CheckpointErr != nil {
		controller.daemon.logWarn("sync", "chunk_reject_state_commit_failed", map[string]any{
			"peer_id": result.PeerID,
			"zone":    result.Zone,
			"error":   result.CheckpointErr,
		})
	}
	if result.ChunkFallback {
		recordDatagramChunkFallback(controller.daemon.PeerObservability, result.PeerID, controller.now)
	}
}

func (controller *daemonGossipActionController) HandleGossipObjectChunkNACK(_ context.Context, message *gossip.Message) error {
	return controller.daemon.Sync.handleObjectChunkNACKFrom(message, controller.replyAddr)
}

func (controller *daemonGossipActionController) ObserveGossipSnapshot(observation corehost.GossipSnapshotObservation) {
	action := observation.Action
	if action.Snapshot == nil {
		return
	}
	if observation.SkippedOwnZone {
		controller.daemon.logDebug("sync", "skipping_own_zone_snapshot", map[string]any{
			"peer_id": observation.PeerID,
			"zone":    action.Snapshot.Zone,
		})
		return
	}
	outcome := observation.Outcome
	if outcome.Err != nil {
		controller.daemon.logWarn("sync", "zone_apply_failed", map[string]any{
			"peer_id": observation.PeerID,
			"zone":    action.Snapshot.Zone,
			"reason":  gossip.RejectReason(outcome.Err),
			"error":   outcome.Err,
		})
		return
	}
	if outcome.ManagedZoneAdopted {
		controller.daemon.logInfo("auto_join", "adopted", map[string]any{
			"peer_id": observation.PeerID,
			"zone":    observation.ManagedZone,
			"via":     "event_loop",
		})
	}
	if outcome.AuthorityRefreshed {
		controller.daemon.logInfo("authority", "managed_zone_refreshed", map[string]any{
			"peer_id": observation.PeerID,
			"zone":    observation.ManagedZone,
		})
	}
	if outcome.Result == nil || (!outcome.Result.NetworkChanged && !outcome.ManagedZoneAdopted && !outcome.AuthorityRefreshed) {
		return
	}
	controller.daemon.logInfo("sync", "zone_applied", map[string]any{
		"peer_id":     observation.PeerID,
		"zone":        action.Snapshot.Zone,
		"records":     outcome.Result.Records,
		"delegations": outcome.Result.Delegation,
		"via":         snapshotApplyVia(action),
	})
}

func (controller *daemonGossipActionController) SendGossip(_ context.Context, outbound gossip.OutboundMessage) error {
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
		recordDatagramTooLarge(d.PeerObservability, peerID, "send", object, "", "", size, budget, d.Sync.now())
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
		_ = d.startHintedSyncSession(peerID, "announce_hint_followup")
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
			recordRelaySuppression(d.PeerObservability, peerID, "relay_fanout_limited", now)
			continue
		}
		allowed, reason := corehost.ShouldRelayGossipUpdate(input.Peers[peerID], peerID, sourcePeerID, catalogRoot, now)
		if !allowed {
			recordRelaySuppression(d.PeerObservability, peerID, reason, now)
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
			recordRelaySuccessDiagnostics(d.PeerObservability, peerID, sourcePeerID, now)
		}
	}
}
