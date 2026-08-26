package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

// runtimeClock wraps a Runtime-style func() time.Time into the Clock interface.
type runtimeClock struct {
	now func() time.Time
}

const syncIngressRouteTTL = time.Minute

type syncIngressRoute struct {
	addr  *net.UDPAddr
	until time.Time
}

func (c *runtimeClock) Now() time.Time { return c.now() }

func (c *runtimeClock) NewTimer(d time.Duration) Timer {
	return &realTimer{Timer: time.NewTimer(d)}
}

// EnableEventLoopSync configures the event-loop SyncSession clock. The
// event-loop sync path is the only daemon sync path; this helper remains for
// tests that need a fake clock.
func (d *DaemonService) EnableEventLoopSync(clock Clock) {
	if clock == nil {
		if d.Sync != nil && d.Sync.App != nil && d.Sync.App.Clock != nil {
			clock = &runtimeClock{now: d.Sync.App.Clock}
		} else {
			clock = NewRealClock()
		}
	}
	if d.timerManager != nil {
		d.timerManager.Stop()
	}
	d.timerManager = NewTimerManager(clock, d.syncEvents)
}

func (d *DaemonService) handleSyncTimerEventLoop(ctx context.Context, force bool) error {
	if d == nil || d.Sync == nil {
		return nil
	}
	now := d.Sync.now()
	projection := d.StateStore.syncTimerProjection(d.Sync.Config, now, d.syncDatagramBudget())
	peers := projection.peers
	if len(peers) == 0 {
		return nil
	}
	d.logDebug("sync", "event_loop_timer", map[string]any{
		"peer_count": len(peers),
		"force":      force,
	})
	if projection.err != nil {
		d.logWarn("sync", "catalog_summary_failed", map[string]any{"error": projection.err})
		return nil
	}
	for _, peerID := range peers {
		if !force && backoffRemaining(projection.peerStates[peerID], now) > 0 {
			d.logDebug("sync", "event_loop_skipped", map[string]any{
				"peer_id": peerID,
				"reason":  "backoff",
			})
			continue
		}
		if existing, ok := d.syncSessions[peerID]; ok && !existing.Done() {
			d.logDebug("sync", "event_loop_skipped", map[string]any{
				"peer_id": peerID,
				"reason":  "session_active",
			})
			continue
		}
		d.syncSessions[peerID] = NewSyncSession(peerID)
		event := &SyncTimerEvent{
			PeerID:       peerID,
			LocalDigests: projection.digests,
			LocalSummary: projection.summary,
		}
		// This function already runs on the daemon event-loop goroutine. Execute
		// the initial event directly so a saturated internal event queue cannot
		// leave an idle session behind forever. Such a zombie session suppresses
		// every later periodic/bootstrap retry as "session_active".
		d.handleSyncEvent(ctx, event)
	}
	return nil
}

func (d *DaemonService) handlePacketEventSyncSession(packet *gossip.Packet, _ context.Context) error {
	if packet != nil && packet.Message != nil && d != nil && d.Sync != nil {
		msg := packet.Message
		now := d.Sync.now()
		d.rememberSyncIngressRoute(msg.PeerID, packet.Addr, now)
		mutations := []func(*stateFile){
			func(state *stateFile) {
				recordVerifiedObservedPath(state, msg.PeerID, packet.Addr, msg.Type, now)
			},
		}
		label := "observed_path"
		if kind, zoneName, ok := packetReadOnlyResponder(msg); ok &&
			(kind != "chunk_fallback" || d.Sync.Transport != nil) {
			label += ",read_only_responder"
			mutations = append(mutations, func(state *stateFile) {
				recordReadOnlyResponder(state, msg.PeerID, kind, zoneName, now)
			})
		}
		d.recordPacketPeerStateBatch(msg.PeerID, label, mutations...)
		d.seedObservedPeerPath(msg.PeerID)
	}
	event := routePacket(packet, d.syncSessions)
	switch ev := event.(type) {
	case *PacketEvent:
		msg := ev.Packet.Message
		switch msg.Type {
		case gossip.MessagePing:
			// A inbound ping carries the peer's zone digests, which is enough
			// for our active session to decide what to pull. This is important
			// when the local session's own initial ping was lost (e.g. the peer
			// was not yet listening): without this, the session would stay in
			// ping_sent until the round timer fires and never converge.
			if msg.Ping != nil {
				if msg.Ping.Summary != nil {
					_ = d.postSyncEvent(&CatalogSummaryReceivedEvent{
						PeerID:  msg.PeerID,
						Summary: msg.Ping.Summary,
					})
				}
			}
			return d.respondPingTo(msg.PeerID, msg.Ping, ev.Packet.Addr)
		case gossip.MessagePong:
			if msg.Pong == nil {
				return nil
			}
			return d.postSyncEvent(&PongReceivedEvent{
				PeerID: msg.PeerID,
				Pong:   msg.Pong,
			})
		case gossip.MessageFetchZone:
			if msg.FetchZone == nil {
				return nil
			}
			// Chunk fallback requests split detached zone snapshots into UDP
			// object chunks.
			// Keep them out of the active pull FSM as a read-only responder path.
			if msg.FetchZone.ChunkFallback {
				return d.respondFetchZoneChunksTo(msg.PeerID, msg.FetchZone.Zone, ev.Packet.Addr)
			}
			return d.respondFetchZoneTo(msg.PeerID, msg.FetchZone.Zone, ev.Packet.Addr)
		case gossip.MessageFetchCatalogPage:
			if msg.FetchCatalogPage == nil {
				return nil
			}
			return d.respondFetchCatalogPageTo(msg.PeerID, msg.FetchCatalogPage.Cursor, ev.Packet.Addr)
		case gossip.MessageCatalogPage:
			if msg.CatalogPage == nil {
				return nil
			}
			return d.postSyncEvent(&CatalogPageReceivedEvent{
				PeerID: msg.PeerID,
				Page:   msg.CatalogPage,
			})
		case gossip.MessageAnnounce:
			return d.handleAnnounceHint(msg.PeerID)
		case gossip.MessageObjectChunk:
			return d.handleObjectChunkFrom(msg, ev.Packet.Addr, syncLimits(d.Sync.Config))
		case gossip.MessageObjectChunkNACK:
			return d.Sync.handleObjectChunkNACKFrom(msg, ev.Packet.Addr)
		default:
			return nil
		}
	case *UnsolicitedPacketEvent:
		if packet == nil || packet.Message == nil {
			return nil
		}
		msg := packet.Message
		switch msg.Type {
		case gossip.MessagePing:
			if msg.Ping == nil {
				return nil
			}
			localSummary, err := d.respondPingWithSummaryTo(msg.PeerID, msg.Ping, packet.Addr)
			if err != nil {
				return err
			}
			if msg.Ping.Summary != nil {
				return d.maybeShortcutSyncFromPingSummaryWithLocal(msg.PeerID, msg.Ping.Summary, localSummary)
			}
			return nil
		case gossip.MessageFetchZone:
			if msg.FetchZone == nil {
				return nil
			}
			if msg.FetchZone.ChunkFallback {
				return d.respondFetchZoneChunksTo(msg.PeerID, msg.FetchZone.Zone, packet.Addr)
			}
			return d.respondFetchZoneTo(msg.PeerID, msg.FetchZone.Zone, packet.Addr)
		case gossip.MessageFetchCatalogPage:
			if msg.FetchCatalogPage == nil {
				return nil
			}
			return d.respondFetchCatalogPageTo(msg.PeerID, msg.FetchCatalogPage.Cursor, packet.Addr)
		case gossip.MessageAnnounce:
			return d.handleAnnounceHint(msg.PeerID)
		case gossip.MessageObjectChunkNACK:
			return d.Sync.handleObjectChunkNACKFrom(msg, packet.Addr)
		default:
			return nil
		}
	default:
		return nil
	}
}

func packetReadOnlyResponder(msg *gossip.Message) (string, zone.ZonePath, bool) {
	if msg == nil {
		return "", "", false
	}
	switch msg.Type {
	case gossip.MessageFetchZone:
		if msg.FetchZone == nil {
			return "", "", false
		}
		if msg.FetchZone.ChunkFallback {
			return "chunk_fallback", msg.FetchZone.Zone, true
		}
		return "fetch_zone", msg.FetchZone.Zone, true
	case gossip.MessageFetchCatalogPage:
		if msg.FetchCatalogPage != nil {
			return "catalog_page", "", true
		}
	}
	return "", "", false
}

func (d *DaemonService) respondPing(peerID string, ping *gossip.Ping) error {
	return d.respondPingTo(peerID, ping, nil)
}

func (d *DaemonService) respondPingTo(peerID string, ping *gossip.Ping, replyAddr *net.UDPAddr) error {
	_, err := d.respondPingWithSummaryTo(peerID, ping, replyAddr)
	return err
}

func (d *DaemonService) respondPingWithSummary(peerID string, ping *gossip.Ping) (*gossip.CatalogSummary, error) {
	return d.respondPingWithSummaryTo(peerID, ping, nil)
}

func (d *DaemonService) respondPingWithSummaryTo(peerID string, ping *gossip.Ping, replyAddr *net.UDPAddr) (*gossip.CatalogSummary, error) {
	if d == nil || d.Sync == nil || ping == nil {
		return nil, nil
	}
	summary, err := d.StateStore.catalogSummaryProjection(d.syncDatagramBudget())
	if err != nil {
		return nil, err
	}
	if summary == nil {
		return nil, nil
	}
	if d.Sync.Transport == nil {
		return summary, nil
	}
	recordCatalogSummary(d.PeerObservability, peerID, summary, d.Sync.now())
	d.sendSyncMessageTo(peerID, replyAddr, &gossip.Message{
		Type: gossip.MessagePong,
		Pong: &gossip.Pong{Summary: summary},
	})
	if ping.Summary != nil && !bytes.Equal(ping.Summary.CatalogRoot, summary.CatalogRoot) {
		d.sendSyncMessageTo(peerID, replyAddr, &gossip.Message{
			Type:             gossip.MessageFetchCatalogPage,
			FetchCatalogPage: &gossip.FetchCatalogPage{},
		})
	}
	return summary, nil
}

// maybeShortcutSyncFromPingSummaryWithLocal checks whether an unsolicited
// ping's catalog summary already matches the local catalog root. If it does, we
// record the peer sync state and skip creating a SyncSession, avoiding a
// redundant ping-pong round. If roots differ, it falls back to
// handleAnnounceHint.
func (d *DaemonService) maybeShortcutSyncFromPingSummaryWithLocal(peerID string, remoteSummary, localSummary *gossip.CatalogSummary) error {
	if localSummary == nil {
		return nil
	}
	if !bytes.Equal(remoteSummary.CatalogRoot, localSummary.CatalogRoot) {
		return d.handleAnnounceHint(peerID)
	}
	now := d.Sync.now()
	d.recordSyncPeerStateBatch(peerID, "sync_hint,peer_sync",
		func(state *stateFile) {
			recordSyncHint(state, peerID, "ping_summary_match", "", true, now)
		},
		func(state *stateFile) {
			recordPeerSyncAt(state, peerID, nil, now)
		},
	)
	d.logDebug("sync", "ping_summary_shortcut", map[string]any{
		"peer_id": peerID,
		"reason":  "catalog_root_match",
	})
	return nil
}

func (d *DaemonService) handleAnnounceHint(peerID string) error {
	if d == nil || d.Sync == nil || peerID == "" {
		return nil
	}
	now := d.Sync.now()
	if existing, ok := d.syncSessions[peerID]; ok && existing != nil && !existing.Done() {
		if d.pendingSyncHints == nil {
			d.pendingSyncHints = make(map[string]bool)
		}
		d.pendingSyncHints[peerID] = true
		d.recordSyncPeerState(peerID, "sync_hint", func(state *stateFile) {
			recordSyncHint(state, peerID, "announce_hint", "session_active", false, now)
		})
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
	summary, digests, err := d.StateStore.catalogStateProjection(d.syncDatagramBudget())
	if err != nil {
		d.logWarn("sync", "catalog_summary_failed", map[string]any{
			"peer_id": peerID,
			"reason":  reason,
			"error":   err,
		})
		return nil
	}
	if summary == nil {
		return nil
	}
	d.syncSessions[peerID] = NewSyncSession(peerID)
	if err := d.postSyncEvent(&SyncTimerEvent{
		PeerID:       peerID,
		LocalDigests: digests,
		LocalSummary: summary,
	}); err != nil {
		delete(d.syncSessions, peerID)
		return err
	}
	d.recordSyncPeerStateBatch(peerID, "sync_hint,active_pull",
		func(state *stateFile) {
			recordSyncHint(state, peerID, reason, "", true, now)
		},
		func(state *stateFile) {
			recordSyncActivePull(state, peerID, "hint_queued", d.syncSessions[peerID], now)
		},
	)
	d.logDebug("sync", "hinted_sync_started", map[string]any{
		"peer_id": peerID,
		"reason":  reason,
	})
	return nil
}

func (d *DaemonService) postSyncEvent(event SyncEvent) error {
	select {
	case d.syncEvents <- event:
		return nil
	default:
		d.logWarn("sync", "event_dropped", map[string]any{"reason": "sync_events_full"})
		return errors.New("sync event channel full")
	}
}

func (d *DaemonService) respondFetchCatalogPage(peerID, cursor string) error {
	return d.respondFetchCatalogPageTo(peerID, cursor, nil)
}

func (d *DaemonService) respondFetchCatalogPageTo(peerID, cursor string, replyAddr *net.UDPAddr) error {
	if d == nil || d.Sync == nil {
		return nil
	}
	budget := d.syncDatagramBudget()
	page, err := d.StateStore.catalogPageProjection(cursor, budget, d.Sync.Config.PeerID)
	if err != nil {
		now := d.Sync.now()
		recordDatagramTooLarge(d.PeerObservability, peerID, "send", "catalog_page", "", "", 0, budget, now)
		recordCatalogReject(d.PeerObservability, peerID, cursor, gossip.RejectReason(err), now)
		d.logWarn("sync", "catalog_page_failed", map[string]any{
			"peer_id": peerID,
			"cursor":  cursor,
			"error":   err,
			"via":     "responder",
		})
		return nil
	}
	if page == nil {
		return nil
	}
	recordCatalogPage(d.PeerObservability, peerID, page, d.Sync.now())
	if err := d.sendSyncMessageTo(peerID, replyAddr, &gossip.Message{
		Type:        gossip.MessageCatalogPage,
		CatalogPage: page,
	}); err != nil {
		now := d.Sync.now()
		recordCatalogReject(d.PeerObservability, peerID, cursor, gossip.RejectReason(err), now)
		d.logWarn("sync", "catalog_page_send_failed", map[string]any{
			"peer_id": peerID,
			"cursor":  cursor,
			"error":   err,
			"via":     "responder",
		})
	}
	return nil
}

func (d *DaemonService) respondFetchZone(peerID string, path zone.ZonePath) error {
	return d.respondFetchZoneTo(peerID, path, nil)
}

func (d *DaemonService) respondFetchZoneTo(peerID string, path zone.ZonePath, replyAddr *net.UDPAddr) error {
	if d == nil || d.Sync == nil {
		return nil
	}
	budget := d.syncDatagramBudget()
	plan, err := d.StateStore.fetchZonePlanProjection(path, budget, d.Sync.now())
	if err != nil {
		d.logDebug("sync", "fetch_zone_snapshot_missing", map[string]any{
			"peer_id": peerID,
			"zone":    path,
			"error":   err,
			"via":     "responder",
		})
		return nil
	}
	return d.respondAnnouncePlanTo(peerID, plan, budget, replyAddr)
}

func (d *DaemonService) respondFetchZoneChunks(peerID string, path zone.ZonePath) error {
	return d.respondFetchZoneChunksTo(peerID, path, nil)
}

func (d *DaemonService) respondFetchZoneChunksTo(peerID string, path zone.ZonePath, replyAddr *net.UDPAddr) error {
	if d == nil || d.Sync == nil || d.Sync.Transport == nil {
		return nil
	}
	now := d.Sync.now()
	plan, snapshot, err := d.StateStore.fetchZoneChunkProjection(path, d.syncDatagramBudget(), now)
	if err != nil || snapshot == nil {
		return nil
	}
	diag, err := sendDetachedSnapshotWithDiagnosticsTo(snapshot, plan, d.Sync.Transport, peerID, replyAddr, now, d.Sync.logger())
	recordDatagramSendDiagnostics(d.PeerObservability, peerID, diag, d.syncDatagramBudget(), now)
	return err
}

func (d *DaemonService) respondAnnouncePlan(peerID string, plan snapshotDatagramPlan, budget int) error {
	return d.respondAnnouncePlanTo(peerID, plan, budget, nil)
}

func (d *DaemonService) respondAnnouncePlanTo(peerID string, plan snapshotDatagramPlan, budget int, replyAddr *net.UDPAddr) error {
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

func (d *DaemonService) handleSyncEvent(ctx context.Context, event SyncEvent) bool {
	peerID := syncEventPeerID(event)
	if peerID == "" {
		d.logDebug("sync", "event_dropped", map[string]any{"reason": "no_peer_id"})
		return false
	}
	session := d.syncSessions[peerID]
	if session == nil {
		d.logDebug("sync", "event_dropped", map[string]any{
			"peer_id": peerID,
			"reason":  "no_session",
		})
		return false
	}
	// Enrich packet-derived events with current-state derivations right before
	// the FSM consumes them, so stale snapshots are not used after state changes
	// (e.g. a record_put that arrived while the event was queued).
	switch e := event.(type) {
	case *PongReceivedEvent:
		if e.Pong != nil {
			if e.Pong.Summary != nil {
				recordCatalogSummary(d.PeerObservability, peerID, e.Pong.Summary, d.Sync.now())
			}
		}
	case *CatalogSummaryReceivedEvent:
		recordCatalogSummary(d.PeerObservability, peerID, e.Summary, d.Sync.now())
	case *CatalogPageReceivedEvent:
		e.LocalEntries, e.Page = d.StateStore.filteredCatalogProjection(peerID, e.Page, d.Sync.now())
		recordCatalogPage(d.PeerObservability, peerID, e.Page, d.Sync.now())
	}
	oldState := session.State
	if _, ok := event.(*RoundTimeoutEvent); ok {
		udpChunkAssemblies.dropPeer(peerID)
	}
	actions, err := session.OnEvent(event, d.Sync.now())
	if err != nil {
		d.logWarn("sync", "session_event_error", map[string]any{
			"peer_id": peerID,
			"error":   err,
		})
		session.State = SyncSessionFailed
		session.lastError = err
	}
	eventName := syncEventName(event)
	eventNow := d.Sync.now()
	activeSession := &SyncSession{State: session.State}
	mutations := newSyncPeerStateMutationBatch(peerID)
	mutations.add("active_pull", func(state *stateFile) {
		recordSyncActivePull(state, peerID, eventName, activeSession, eventNow)
	})
	if session.State != oldState {
		d.logDebug("sync", "session_state_changed", map[string]any{
			"peer_id":   peerID,
			"event":     fmt.Sprintf("%T", event),
			"old_state": oldState,
			"new_state": session.State,
			"pending":   len(session.pendingZones),
			"inflight":  len(session.objectPullInflight),
		})
	}
	networkChanged := d.executeSyncActionsWithMutations(ctx, session, actions, mutations)
	session.networkChanged = session.networkChanged || networkChanged
	if session.Done() {
		mutations.addCompletion(session, eventNow)
	}
	mutations.commit(d)
	if session.Done() {
		d.completeSyncSessionAfterPeerState(session, session.networkChanged)
	}
	return networkChanged
}

func syncEventName(event SyncEvent) string {
	switch event.(type) {
	case *SyncTimerEvent:
		return "sync_timer"
	case *PongReceivedEvent:
		return "pong"
	case *CatalogSummaryReceivedEvent:
		return "catalog_summary"
	case *CatalogPageReceivedEvent:
		return "catalog_page"
	case *CatalogPageTimeoutEvent:
		return "catalog_page_timeout"
	case *RoundTimeoutEvent:
		return "round_timeout"
	case *ObjectPullResultEvent:
		return "object_pull_result"
	case *ObjectChunkEvent:
		return "object_chunk"
	case *SnapshotAppliedEvent:
		return "snapshot_applied"
	default:
		return fmt.Sprintf("%T", event)
	}
}

func filterRemoteCatalogPage(state *stateFile, peerID string, page *gossip.CatalogPage, now time.Time) *gossip.CatalogPage {
	if page == nil || state == nil || len(page.Entries) == 0 {
		return page
	}
	filtered := *page
	filtered.Entries = make([]gossip.ZoneDigest, 0, len(page.Entries))
	for _, entry := range page.Entries {
		if shouldSkipRemoteZone(state, peerID, entry.Zone, entry.RootHash, now) {
			continue
		}
		filtered.Entries = append(filtered.Entries, entry)
	}
	return &filtered
}

func syncEventPeerID(event SyncEvent) string {
	switch e := event.(type) {
	case *SyncTimerEvent:
		return e.PeerID
	case *PongReceivedEvent:
		return e.PeerID
	case *CatalogSummaryReceivedEvent:
		return e.PeerID
	case *CatalogPageReceivedEvent:
		return e.PeerID
	case *CatalogPageTimeoutEvent:
		return e.PeerID
	case *RoundTimeoutEvent:
		return e.PeerID
	case *ObjectPullResultEvent:
		return e.PeerID
	case *ObjectChunkEvent:
		return e.PeerID
	case *SnapshotAppliedEvent:
		return e.PeerID
	}
	return ""
}

func (d *DaemonService) recordSyncPeerState(peerID, label string, fn func(*stateFile)) {
	d.recordSyncPeerStateBatch(peerID, label, fn)
}

func (d *DaemonService) recordSyncPeerStateBatch(peerID, label string, fns ...func(*stateFile)) {
	if d == nil || d.Sync == nil || d.StateStore == nil || len(fns) == 0 {
		return
	}
	if _, err := d.StateStore.UpdateSyncPeer(peerID, func(peer *syncPeerState) error {
		state := &stateFile{SyncPeers: map[string]syncPeerState{peerID: *peer}}
		for _, fn := range fns {
			if fn != nil {
				fn(state)
			}
		}
		*peer = state.SyncPeers[peerID]
		return nil
	}); err != nil {
		d.logWarn("sync", "sync_peer_state_commit_failed", map[string]any{
			"peer_id": peerID,
			"label":   label,
			"error":   err,
		})
		return
	}
	d.markMetadataCheckpointDirty()
}

func (d *DaemonService) recordPacketPeerStateBatch(peerID, label string, fns ...func(*stateFile)) {
	if d == nil || d.Sync == nil || d.StateStore == nil || len(fns) == 0 {
		return
	}
	if _, err := d.StateStore.updateSyncPeerWithView(peerID, func(view syncPeerMutationView, peer *syncPeerState) error {
		state := &stateFile{
			ManagedZone: view.ManagedZone,
			Network:     view.Network,
			SyncPeers:   map[string]syncPeerState{peerID: *peer},
		}
		for _, fn := range fns {
			if fn != nil {
				fn(state)
			}
		}
		*peer = state.SyncPeers[peerID]
		return nil
	}); err != nil {
		d.logWarn("sync", "sync_peer_state_commit_failed", map[string]any{
			"peer_id": peerID,
			"label":   label,
			"error":   err,
		})
		return
	}
	d.markMetadataCheckpointDirtyWithin(verifiedPacketMetadataCheckpointMaxDelay)
}

type syncPeerStateMutation struct {
	label string
	apply func(*stateFile)
}

// syncPeerStateMutationBatch collects the control-state changes caused by one
// sync event. It preserves mutation order and flushes before persistence, while
// avoiding a complete state-store transaction for every individual field
// family.
type syncPeerStateMutationBatch struct {
	peerID             string
	pending            []syncPeerStateMutation
	completionRecorded bool
}

func newSyncPeerStateMutationBatch(peerID string) *syncPeerStateMutationBatch {
	return &syncPeerStateMutationBatch{peerID: peerID}
}

func (b *syncPeerStateMutationBatch) add(label string, fn func(*stateFile)) {
	if b == nil || fn == nil {
		return
	}
	b.pending = append(b.pending, syncPeerStateMutation{label: label, apply: fn})
}

func (b *syncPeerStateMutationBatch) addCompletion(session *SyncSession, now time.Time) {
	if b == nil || session == nil || b.completionRecorded {
		return
	}
	peerID := session.PeerID
	lastError := session.lastError
	b.add("peer_sync", func(state *stateFile) {
		recordPeerSyncAt(state, peerID, lastError, now)
	})
	b.completionRecorded = true
}

func (b *syncPeerStateMutationBatch) commit(d *DaemonService) {
	if b == nil || len(b.pending) == 0 || d == nil {
		return
	}
	pending := b.pending
	b.pending = nil
	labels := make([]string, 0, len(pending))
	fns := make([]func(*stateFile), 0, len(pending))
	for _, mutation := range pending {
		labels = append(labels, mutation.label)
		fns = append(fns, mutation.apply)
	}
	d.recordSyncPeerStateBatch(b.peerID, strings.Join(labels, ","), fns...)
}

type syncSnapshotApply struct {
	action ApplySnapshotAction
	limits gossip.SyncLimits
}

func snapshotApplyVia(action ApplySnapshotAction) string {
	if action.Via != "" {
		return action.Via
	}
	return "event_loop"
}

type syncSnapshotOutcome struct {
	result         *gossip.ApplyResult
	applyErr       error
	networkChanged bool
	adopted        bool
	adoptionErr    error
	refreshed      bool
	refreshErr     error
	managedZone    zone.ZonePath
}

// syncSnapshotCommit separates publication of the detached state workspace
// from a real Network transition. A successful snapshot may still commit
// peer/admission metadata while leaving every relevant Zone root unchanged.
type syncSnapshotCommit struct {
	StateCommitted bool
	NetworkChanged bool
}

var errSnapshotRootMismatch = errors.New("snapshot root does not match advertised catalog digest")

const verifiedPacketMetadataCheckpointMaxDelay = 250 * time.Millisecond

// applySyncSnapshotBatch gives every action an independent target-zone COW
// savepoint, then publishes the final working root once. The callback body is
// pure with respect to external effects, so an unexpected stale revision can
// discard and recompute the complete batch safely.
func (d *DaemonService) applySyncSnapshotBatch(peerID string, applies []syncSnapshotApply, now time.Time) ([]syncSnapshotOutcome, syncSnapshotCommit, error) {
	if d == nil || d.Sync == nil || d.StateStore == nil {
		return nil, syncSnapshotCommit{}, errors.New("daemon service is not initialized")
	}
	for range maxSyncPeerUpdateAttempts {
		state, revision := d.StateStore.snapshotApplyWorkspace()
		if state == nil || state.Network == nil {
			return nil, syncSnapshotCommit{}, errors.New("daemon state network is nil")
		}
		beforeRoots := make(map[zone.ZonePath][]byte, len(applies)+1)
		for _, apply := range applies {
			if snapshot := apply.action.Snapshot; snapshot != nil {
				beforeRoots[snapshot.Zone] = append([]byte(nil), gossip.ZoneRoot(state.Network.Zones[snapshot.Zone])...)
			}
		}
		if state.ManagedZone.Valid() {
			beforeRoots[state.ManagedZone] = append([]byte(nil), gossip.ZoneRoot(state.Network.Zones[state.ManagedZone])...)
		}
		outcomes := make([]syncSnapshotOutcome, len(applies))
		dirty := false
		for i, apply := range applies {
			snapshot := apply.action.Snapshot
			if snapshot == nil {
				continue
			}
			outcome := &outcomes[i]
			outcome.managedZone = state.ManagedZone
			if len(apply.action.ExpectedRoot) > 0 {
				actualRoot := digestForSnapshot(snapshot).RootHash
				if !bytes.Equal(actualRoot, apply.action.ExpectedRoot) {
					outcome.applyErr = fmt.Errorf("%w for %s: expected %x, received %x", errSnapshotRootMismatch, snapshot.Zone, apply.action.ExpectedRoot, actualRoot)
					recordRejectedDigest(state, peerID, gossip.ZoneDigest{Zone: snapshot.Zone, RootHash: apply.action.ExpectedRoot}, gossip.RejectReason(outcome.applyErr), now)
					dirty = true
					continue
				}
			}
			nextNetwork, result, err := gossip.ApplySnapshot(state.Network, snapshot, now, apply.limits)
			if err != nil {
				outcome.applyErr = err
				recordRejectedDigest(state, peerID, digestForSnapshot(snapshot), gossip.RejectReason(err), now)
				dirty = true
				continue
			}

			// A parent snapshot can carry a newer authority for our managed
			// Zone. Apply that authority envelope in the same savepoint while
			// preserving all locally-owned Zone contents.
			previousNetwork := state.Network
			state.Network = nextNetwork
			// ApplySnapshot detaches only snapshot.Zone. Authority adoption and
			// refresh may mutate ManagedZone as a secondary effect, so detach it
			// as well before entering those helpers.
			if state.ManagedZone.Valid() && state.ManagedZone != snapshot.Zone {
				state.Network = zone.CloneNetworkStateForZone(state.Network, state.ManagedZone)
			}
			outcome.adopted, outcome.adoptionErr = tryAdoptAutoJoinDelegation(state, now)
			if outcome.adoptionErr == nil {
				outcome.refreshed, outcome.refreshErr = tryRefreshManagedZoneAuthority(state, now)
			}
			if outcome.refreshErr != nil {
				state.Network = previousNetwork
				outcome.applyErr = fmt.Errorf("refresh managed zone authority: %w", outcome.refreshErr)
				recordRejectedDigest(state, peerID, digestForSnapshot(snapshot), gossip.RejectReason(outcome.applyErr), now)
				dirty = true
				continue
			}

			// Successful action: advancing state.Network is this action's
			// savepoint commit. A later rejected action cannot mutate it.
			outcome.result = result
			outcome.networkChanged = result.NetworkChanged || outcome.adopted || outcome.refreshed
			peerState := state.SyncPeers[peerID]
			_, hadRejectedDigest := peerState.RejectedDigests[rejectedDigestKey(snapshot.Zone)]
			if !hadRejectedDigest {
				_, hadRejectedDigest = peerState.RejectedDigests[snapshot.Zone.String()]
			}
			clearRejectedDigest(state, peerID, snapshot.Zone)
			metadataChanged := hadRejectedDigest
			if outcome.adopted || outcome.adoptionErr != nil {
				recordAdoptionResult(state, outcome.adopted, outcome.adoptionErr, now)
				metadataChanged = true
			}
			if !outcome.adopted && outcome.adoptionErr == nil && state.Admission != nil && state.Admission.Pending && isBootstrapPeer(d.Sync.Config, peerID) {
				recordBootstrapSyncSuccess(state, peerID, d.Sync.Config, now)
				metadataChanged = true
			}
			dirty = dirty || outcome.networkChanged || metadataChanged
		}
		if !dirty {
			return outcomes, syncSnapshotCommit{}, nil
		}
		if _, committed := d.StateStore.commitSnapshotApplyIfRevision(revision, state); committed {
			commit := syncSnapshotCommit{StateCommitted: true}
			for path, beforeRoot := range beforeRoots {
				if !bytes.Equal(beforeRoot, gossip.ZoneRoot(state.Network.Zones[path])) {
					commit.NetworkChanged = true
					break
				}
			}
			return outcomes, commit, nil
		}
	}
	return nil, syncSnapshotCommit{}, errDaemonStateRevisionStale
}

func (d *DaemonService) logSnapshotAdoption(peerID string, outcome syncSnapshotOutcome) {
	if outcome.adoptionErr != nil {
		d.logWarn("auto_join", "adopt_failed", map[string]any{
			"peer_id": peerID,
			"zone":    outcome.managedZone,
			"via":     "event_loop",
			"error":   outcome.adoptionErr,
		})
	} else if outcome.adopted {
		d.logInfo("auto_join", "adopted", map[string]any{
			"peer_id": peerID,
			"zone":    outcome.managedZone,
			"via":     "event_loop",
		})
	}
	if outcome.refreshErr != nil {
		d.logWarn("authority", "managed_zone_refresh_failed", map[string]any{
			"peer_id": peerID,
			"zone":    outcome.managedZone,
			"error":   outcome.refreshErr,
		})
	} else if outcome.refreshed {
		d.logInfo("authority", "managed_zone_refreshed", map[string]any{
			"peer_id": peerID,
			"zone":    outcome.managedZone,
		})
	}
}

func (d *DaemonService) applySyncSnapshotAction(peerID string, action ApplySnapshotAction, limits gossip.SyncLimits, now time.Time) (*gossip.ApplyResult, syncSnapshotCommit, error) {
	if action.Snapshot == nil {
		return nil, syncSnapshotCommit{}, nil
	}
	outcomes, commit, err := d.applySyncSnapshotBatch(peerID, []syncSnapshotApply{{action: action, limits: limits}}, now)
	if err != nil {
		return nil, syncSnapshotCommit{}, err
	}
	if !commit.StateCommitted || len(outcomes) == 0 {
		return nil, commit, nil
	}
	outcome := outcomes[0]
	if outcome.applyErr != nil {
		return nil, commit, outcome.applyErr
	}
	d.logSnapshotAdoption(peerID, outcome)
	return outcome.result, commit, nil
}

func (d *DaemonService) executeSyncActionsWithMutations(ctx context.Context, session *SyncSession, actions []SyncAction, mutations *syncPeerStateMutationBatch) bool {
	if len(actions) == 0 {
		return false
	}
	peerID := session.PeerID
	now := d.Sync.now()
	stateProjection := d.StateStore.syncStateProjection()
	if !stateProjection.loaded {
		return false
	}

	var networkChanged bool
	limits := syncLimits(d.Sync.Config)

	// First pass: collect snapshots. They are validated with independent COW
	// savepoints and published as one final revision below.
	var snapshotApplies []syncSnapshotApply
	for _, action := range actions {
		switch a := action.(type) {
		case ApplySnapshotAction:
			if a.Snapshot == nil {
				continue
			}
			if a.Snapshot.Zone == stateProjection.managedZone {
				// Never accept a snapshot for our own managed zone from a peer;
				// we are the authority for it.
				d.logDebug("sync", "skipping_own_zone_snapshot", map[string]any{
					"peer_id": peerID,
					"zone":    a.Snapshot.Zone,
				})
				continue
			}
			applyLimits := limits
			if a.RelaxedLimits {
				applyLimits = limits
				applyLimits.MaxBytes = 8 << 20
			}
			snapshotApplies = append(snapshotApplies, syncSnapshotApply{action: a, limits: applyLimits})
		}
	}
	snapshotCommit := syncSnapshotCommit{}
	var snapshotOutcomes []syncSnapshotOutcome
	if len(snapshotApplies) > 0 {
		outcomes, commit, err := d.applySyncSnapshotBatch(peerID, snapshotApplies, now)
		if err != nil {
			d.logWarn("sync", "snapshot_batch_commit_failed", map[string]any{
				"peer_id": peerID,
				"error":   err,
			})
			for _, apply := range snapshotApplies {
				if apply.action.ReportResult && apply.action.Snapshot != nil {
					_ = d.postSyncEvent(&SnapshotAppliedEvent{
						PeerID: peerID,
						Zone:   apply.action.Snapshot.Zone,
						Err:    err,
					})
				}
			}
			// Do not execute transport/timer callbacks derived from a batch
			// that was never published.
			return false
		} else {
			snapshotOutcomes = outcomes
			snapshotCommit = commit
			networkChanged = commit.NetworkChanged
			for i, outcome := range outcomes {
				apply := snapshotApplies[i]
				if outcome.applyErr != nil {
					d.logWarn("sync", "zone_apply_failed", map[string]any{
						"peer_id": peerID,
						"zone":    apply.action.Snapshot.Zone,
						"reason":  gossip.RejectReason(outcome.applyErr),
						"error":   outcome.applyErr,
					})
					continue
				}
				if outcome.result == nil {
					continue
				}
				d.logSnapshotAdoption(peerID, outcome)
				if !commit.NetworkChanged || !outcome.networkChanged {
					d.logDebug("sync", "zone_apply_noop", map[string]any{
						"peer_id": peerID,
						"zone":    apply.action.Snapshot.Zone,
						"via":     snapshotApplyVia(apply.action),
					})
					continue
				}
				d.logInfo("sync", "zone_applied", map[string]any{
					"peer_id":     peerID,
					"zone":        apply.action.Snapshot.Zone,
					"records":     outcome.result.Records,
					"delegations": outcome.result.Delegation,
					"via":         snapshotApplyVia(apply.action),
				})
			}
		}
	}

	// Second pass: refresh the reader view after the single batch publication.
	// Persistence is coalesced with any SaveStateAction below so a batch writes
	// the state file at most once.
	if networkChanged {
		stateProjection = d.StateStore.syncStateProjection()
	}
	for i, apply := range snapshotApplies {
		if !apply.action.ReportResult || apply.action.Snapshot == nil {
			continue
		}
		event := &SnapshotAppliedEvent{
			PeerID: peerID,
			Zone:   apply.action.Snapshot.Zone,
		}
		if i >= len(snapshotOutcomes) {
			event.Err = errors.New("snapshot apply produced no outcome")
		} else {
			event.Err = snapshotOutcomes[i].applyErr
		}
		_ = d.postSyncEvent(event)
	}

	// Applied object-pull or chunk-fallback snapshots may leave a zone pending
	// until the FSM sees local state again. Reconcile before sending more I/O.
	if !session.Done() && stateProjection.loaded {
		reconcileActions := session.reconcilePendingWithDigests(stateProjection.digests)
		actions = append(actions, reconcileActions...)
	}

	// Third pass: send messages.
	budget := gossip.DefaultMaxMessage
	budget = d.syncDatagramBudget()
	for _, action := range actions {
		switch a := action.(type) {
		case SendPingAction:
			d.sendSyncSessionMessage(peerID, &gossip.Message{
				Type: gossip.MessagePing,
				Ping: &gossip.Ping{Summary: a.Summary},
			})
		case SendFetchCatalogPageAction:
			d.sendSyncSessionMessage(peerID, &gossip.Message{
				Type:             gossip.MessageFetchCatalogPage,
				FetchCatalogPage: &gossip.FetchCatalogPage{Cursor: a.Cursor},
			})
		case SendCatalogPageAction:
			if !stateProjection.loaded {
				continue
			}
			page, err := gossip.CatalogPageForDigests(stateProjection.digests, a.Cursor, budget, d.Sync.Config.PeerID)
			if err != nil {
				now := d.Sync.now()
				recordDatagramTooLarge(d.PeerObservability, peerID, "send", "catalog_page", "", "", 0, budget, now)
				recordCatalogReject(d.PeerObservability, peerID, a.Cursor, gossip.RejectReason(err), now)
				d.logWarn("sync", "catalog_page_failed", map[string]any{
					"peer_id": peerID,
					"cursor":  a.Cursor,
					"error":   err,
				})
				continue
			}
			recordCatalogPage(d.PeerObservability, peerID, page, d.Sync.now())
			d.sendSyncSessionMessage(peerID, &gossip.Message{
				Type:        gossip.MessageCatalogPage,
				CatalogPage: page,
			})
		case SendFetchZoneAction:
			if !a.ChunkFallback {
				d.logDebug("sync", "fetch_zone_ignored", map[string]any{
					"peer_id": peerID,
					"zone":    a.Zone,
					"reason":  "ordinary_fetch_zone_disabled",
				})
				continue
			}
			d.sendSyncSessionMessage(peerID, &gossip.Message{
				Type:      gossip.MessageFetchZone,
				FetchZone: &gossip.FetchZone{Zone: a.Zone, ChunkFallback: a.ChunkFallback},
			})
		}
	}

	// Fourth pass: start async object pulls.
	for _, action := range actions {
		if a, ok := action.(StartObjectPullAction); ok {
			d.submitObjectPull(ctx, a.PeerID, a.Zone, now)
		}
	}

	// Fifth pass: timer actions.
	for _, action := range actions {
		switch a := action.(type) {
		case StartTimerAction:
			d.timerManager.Start(a.PeerID, a.Kind, a.Deadline)
		case CancelTimerAction:
			d.timerManager.Cancel(a.PeerID, a.Kind)
		}
	}

	// Final pass: backoff and persistence intent. Snapshot application is the
	// authoritative source for whether this event changed Network; an action
	// that only records peer runtime state must not rewrite every zone bucket.
	persistenceRequested := snapshotCommit.StateCommitted
	persistenceScope := SyncPersistenceMeta
	persistenceReason := "snapshot_batch"
	for _, action := range actions {
		switch a := action.(type) {
		case RecordBackoffAction:
			if mutations == nil {
				d.recordSyncPeerState(a.PeerID, "peer_backoff", func(state *stateFile) {
					recordPeerBackoff(state, a.PeerID, a.Err, now)
				})
			} else {
				actionPeerID := a.PeerID
				actionErr := a.Err
				mutations.add("peer_backoff", func(state *stateFile) {
					recordPeerBackoff(state, actionPeerID, actionErr, now)
				})
			}
		case SaveStateAction:
			if mutations != nil {
				if session.Done() {
					mutations.addCompletion(session, now)
				}
				mutations.commit(d)
			}
			persistenceRequested = true
			actionScope := a.Persistence
			if actionScope == SyncPersistenceUnspecified {
				// An omitted intent stays fail-safe for future callers. Current
				// metadata-only FSM actions all opt in explicitly.
				actionScope = SyncPersistenceNetwork
			}
			if actionScope > persistenceScope {
				persistenceScope = actionScope
			}
			persistenceReason = a.Reason
		}
	}
	if networkChanged {
		persistenceRequested = true
		persistenceScope = SyncPersistenceNetwork
	}
	if persistenceRequested {
		var err error
		if persistenceScope == SyncPersistenceNetwork {
			err = d.saveCommittedState()
		} else {
			d.markMetadataCheckpointDirty()
		}
		if err != nil {
			d.logWarn("sync", "save_failed", map[string]any{
				"peer_id": peerID,
				"reason":  persistenceReason,
				"error":   err,
			})
		}
	}

	return networkChanged
}

func (d *DaemonService) submitObjectPull(ctx context.Context, peerID string, path zone.ZonePath, now time.Time) {
	if d == nil || d.objectPullPool == nil || d.Sync == nil {
		return
	}
	addr, stateAvailable := d.StateStore.peerTCPAddrProjection(d.Sync.Config, peerID)
	if !stateAvailable {
		err := fmt.Errorf("no committed state for peer %s", peerID)
		result := ObjectPullResult{PeerID: peerID, Zone: path, Err: err, Unreachable: true}
		d.observeObjectPullResult(result)
		d.enqueueObjectPullResult(result)
		return
	}
	if addr == "" {
		err := fmt.Errorf("no TCP address for peer %s", peerID)
		result := ObjectPullResult{PeerID: peerID, Zone: path, Err: err, Unreachable: true}
		d.observeObjectPullResult(result)
		d.enqueueObjectPullResult(result)
		return
	}
	d.observeObjectPullAttempt(peerID, path, now)
	if !d.objectPullPool.Submit(ctx, ObjectPullRequest{PeerID: peerID, Zone: path, Addr: addr}) {
		err := errors.New("object pull submit failed")
		result := ObjectPullResult{PeerID: peerID, Zone: path, Err: err, Unreachable: true}
		d.observeObjectPullResult(result)
		d.enqueueObjectPullResult(result)
	}
}

func (d *DaemonService) enqueueObjectPullResult(result ObjectPullResult) {
	select {
	case d.syncEvents <- objectPullResultToEvent(result):
	default:
		d.logWarn("sync", "object_pull_result_dropped", map[string]any{
			"peer_id": result.PeerID,
			"zone":    result.Zone,
		})
	}
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

func (d *DaemonService) sendSyncMessage(peerID string, msg *gossip.Message) error {
	return d.sendSyncMessageTo(peerID, nil, msg)
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

func (d *DaemonService) completeSyncSessionAfterPeerState(session *SyncSession, networkChanged bool) {
	if session == nil {
		return
	}
	peerID := session.PeerID
	d.timerManager.CancelAll(peerID)
	// Only mark the last-used address as failing for timeout-like errors; do
	// not penalize the address for internal/event handling failures.
	if session.lastError != nil && d.Sync.Transport != nil && strings.Contains(session.lastError.Error(), "timeout") {
		if lastAddr := d.Sync.Transport.LastSendAddr(peerID); lastAddr != nil {
			d.Sync.Transport.RecordAddrFailure(peerID, lastAddr)
		}
	}
	if session.State == SyncSessionCompleted && networkChanged {
		if d.Sync.Transport != nil {
			d.updateDiscoveredPeers()
		}
		d.notifyStateChanged()
		d.relaySyncToPeers(peerID)
		if err := d.saveCommittedState(); err != nil {
			d.logWarn("sync", "session_save_failed", map[string]any{"peer_id": peerID, "error": err})
		}
	}
	delete(d.syncSessions, peerID)
	if d.pendingSyncHints != nil && d.pendingSyncHints[peerID] {
		delete(d.pendingSyncHints, peerID)
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
	projection := d.StateStore.relayProjection(d.Sync.Config, now, d.syncDatagramBudget())
	if projection.err != nil {
		d.logWarn("sync", "relay_catalog_summary_failed", map[string]any{"error": projection.err})
		return
	}
	if projection.summary == nil {
		return
	}
	localDigests, peers, peerStates := projection.digests, projection.peers, projection.peerStates
	catalogRoot := hex.EncodeToString(projection.summary.CatalogRoot)
	for _, peerID := range peers {
		if peerID == sourcePeerID {
			continue
		}
		if relayed >= maxRelayFanoutPerUpdate {
			d.recordSyncPeerState(peerID, "relay_suppression", func(state *stateFile) {
				recordRelaySuppression(state, peerID, "relay_fanout_limited", now)
			})
			continue
		}
		allowed, reason := shouldRelayToPeer(peerStates[peerID], peerID, sourcePeerID, catalogRoot, now)
		if !allowed {
			d.recordSyncPeerState(peerID, "relay_suppression", func(state *stateFile) {
				recordRelaySuppression(state, peerID, reason, now)
			})
			continue
		}
		relayed++
		if existing, ok := d.syncSessions[peerID]; ok && !existing.Done() {
			continue
		}
		d.syncSessions[peerID] = NewSyncSession(peerID)
		queued := false
		select {
		case d.syncEvents <- &SyncTimerEvent{
			PeerID:       peerID,
			LocalDigests: localDigests,
			LocalSummary: projection.summary,
		}:
			queued = true
		default:
			d.logWarn("sync", "relay_event_full", map[string]any{"peer_id": peerID, "source_peer": sourcePeerID})
		}
		if !queued {
			delete(d.syncSessions, peerID)
			continue
		}
		d.recordSyncPeerState(peerID, "relay_success", func(state *stateFile) {
			recordRelaySuccess(state, peerID, sourcePeerID, catalogRoot, now)
		})
	}
}

func digestForSnapshot(snapshot *gossip.ZoneSnapshot) gossip.ZoneDigest {
	if snapshot == nil {
		return gossip.ZoneDigest{}
	}
	return gossip.ZoneDigest{
		Zone:     snapshot.Zone,
		RootHash: gossip.ZoneRoot(zoneStateFromSnapshot(snapshot)),
	}
}

func zoneStateFromSnapshot(snapshot *gossip.ZoneSnapshot) *zone.ZoneState {
	if snapshot == nil {
		return nil
	}
	zs := zone.NewZoneState(snapshot.Zone, snapshot.Authority)
	zs.Delegations = snapshot.Delegations
	zs.Revocations = snapshot.Revocations
	zs.Records = snapshot.Records
	zs.RecordHistory = snapshot.RecordHistory
	return zs
}

// recordPeerBackoff mutates state.SyncPeers. The caller must hold the write lock
// on state.
func recordPeerBackoff(state *stateFile, peerID string, err error, now time.Time) {
	if state == nil || peerID == "" {
		return
	}
	normalizeSyncPeers(state)
	peerState := state.SyncPeers[peerID]
	peerState.LastAttemptUnix = now.Unix()
	if err != nil {
		peerState.LastError = err.Error()
	}
	backoff := time.Duration(1<<minInt(peerState.FailureCount, 6)) * time.Second
	peerState.BackoffUntilUnix = now.Add(backoff).Unix()
	state.SyncPeers[peerID] = peerState
}
