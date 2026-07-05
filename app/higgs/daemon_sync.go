package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Catofes/higgs/pkg/core/gossip"
	"github.com/Catofes/higgs/pkg/core/zone"
)

// runtimeClock wraps a Runtime-style func() time.Time into the Clock interface.
type runtimeClock struct {
	now func() time.Time
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
	d.timerManager = NewTimerManager(clock, d.syncEvents)
}

func (d *DaemonService) handleSyncTimerEventLoop(_ context.Context, force bool) error {
	now := d.Sync.now()
	peers := outboundSyncPeersAt(d.Sync.State, d.Sync.Config, now)
	d.logDebug("sync", "event_loop_timer", map[string]any{
		"peer_count": len(peers),
		"force":      force,
	})
	for _, peerID := range peers {
		if !force && backoffRemaining(d.Sync.State.SyncPeers[peerID], now) > 0 {
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
		summary, err := gossip.CatalogSummaryFor(d.Sync.State.Network, d.syncDatagramBudget())
		if err != nil {
			d.logWarn("sync", "catalog_summary_failed", map[string]any{"peer_id": peerID, "error": err})
			continue
		}
		event := &SyncTimerEvent{
			PeerID:       peerID,
			LocalDigests: gossip.ZoneDigests(d.Sync.State.Network),
			LocalSummary: summary,
		}
		select {
		case d.syncEvents <- event:
		default:
			d.logWarn("sync", "event_loop_full", map[string]any{"peer_id": peerID})
		}
	}
	return nil
}

func (d *DaemonService) handlePacketEventSyncSession(packet *gossip.Packet, _ context.Context) error {
	if packet != nil && packet.Message != nil && d != nil && d.Sync != nil && d.Sync.State != nil {
		d.recordSyncPeerState(packet.Message.PeerID, "observed_path", func(state *stateFile) {
			recordVerifiedObservedPath(state, packet.Message.PeerID, packet.Addr, packet.Message.Type, d.Sync.now())
		})
		d.Sync.seedObservedPeerPath(packet.Message.PeerID)
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
			return d.respondPing(msg.PeerID, msg.Ping)
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
			// Chunk fallback requests use sendSnapshots, which knows how to split
			// oversized zone snapshots into UDP object chunks.
			// Keep them out of the active pull FSM as a read-only responder path.
			if msg.FetchZone.ChunkFallback {
				return d.respondFetchZoneChunks(msg.PeerID, msg.FetchZone.Zone)
			}
			return d.respondFetchZone(msg.PeerID, msg.FetchZone.Zone)
		case gossip.MessageFetchCatalogPage:
			if msg.FetchCatalogPage == nil {
				return nil
			}
			return d.respondFetchCatalogPage(msg.PeerID, msg.FetchCatalogPage.Cursor)
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
			// Object chunks still use the global UDP chunk assembly store.
			return d.Sync.handleObjectChunk(msg, syncLimits(d.Sync.Config))
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
			if err := d.respondPing(msg.PeerID, msg.Ping); err != nil {
				return err
			}
			if msg.Ping.Summary != nil {
				return d.handleAnnounceHint(msg.PeerID)
			}
			return nil
		case gossip.MessageFetchZone:
			if msg.FetchZone == nil {
				return nil
			}
			if msg.FetchZone.ChunkFallback {
				return d.respondFetchZoneChunks(msg.PeerID, msg.FetchZone.Zone)
			}
			return d.respondFetchZone(msg.PeerID, msg.FetchZone.Zone)
		case gossip.MessageFetchCatalogPage:
			if msg.FetchCatalogPage == nil {
				return nil
			}
			return d.respondFetchCatalogPage(msg.PeerID, msg.FetchCatalogPage.Cursor)
		case gossip.MessageAnnounce:
			return d.handleAnnounceHint(msg.PeerID)
		case gossip.MessageObjectChunk:
			return d.Sync.handleObjectChunk(msg, syncLimits(d.Sync.Config))
		default:
			return nil
		}
	default:
		return nil
	}
}

func (d *DaemonService) respondPing(peerID string, ping *gossip.Ping) error {
	if d == nil || d.Sync == nil || d.Sync.State == nil || d.Sync.State.Network == nil || d.Sync.Transport == nil || ping == nil {
		return nil
	}
	summary, err := gossip.CatalogSummaryFor(d.Sync.State.Network, d.syncDatagramBudget())
	if err != nil {
		return err
	}
	d.recordSyncPeerState(peerID, "catalog_summary", func(state *stateFile) {
		recordCatalogSummary(state, peerID, summary, d.Sync.now())
	})
	d.sendSyncMessage(peerID, &gossip.Message{
		Type: gossip.MessagePong,
		Pong: &gossip.Pong{Summary: summary},
	})
	if ping.Summary != nil && !bytes.Equal(ping.Summary.CatalogRoot, summary.CatalogRoot) {
		d.sendSyncMessage(peerID, &gossip.Message{
			Type:             gossip.MessageFetchCatalogPage,
			FetchCatalogPage: &gossip.FetchCatalogPage{},
		})
	}
	return nil
}

func (d *DaemonService) handleAnnounceHint(peerID string) error {
	if d == nil || d.Sync == nil || d.Sync.State == nil || d.Sync.State.Network == nil || peerID == "" {
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
	if d == nil || d.Sync == nil || d.Sync.State == nil || d.Sync.State.Network == nil || peerID == "" {
		return nil
	}
	now := d.Sync.now()
	summary, err := gossip.CatalogSummaryFor(d.Sync.State.Network, d.syncDatagramBudget())
	if err != nil {
		d.logWarn("sync", "catalog_summary_failed", map[string]any{
			"peer_id": peerID,
			"reason":  reason,
			"error":   err,
		})
		return nil
	}
	d.syncSessions[peerID] = NewSyncSession(peerID)
	if err := d.postSyncEvent(&SyncTimerEvent{
		PeerID:       peerID,
		LocalDigests: gossip.ZoneDigests(d.Sync.State.Network),
		LocalSummary: summary,
	}); err != nil {
		delete(d.syncSessions, peerID)
		return err
	}
	d.recordSyncPeerState(peerID, "sync_hint", func(state *stateFile) {
		recordSyncHint(state, peerID, reason, "", true, now)
	})
	d.recordSyncPeerState(peerID, "active_pull", func(state *stateFile) {
		recordSyncActivePull(state, peerID, "hint_queued", d.syncSessions[peerID], now)
	})
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
	if d == nil || d.Sync == nil || d.Sync.State == nil {
		return nil
	}
	d.recordSyncPeerState(peerID, "read_only_responder", func(state *stateFile) {
		recordReadOnlyResponder(state, peerID, "catalog_page", "", d.Sync.now())
	})
	budget := d.syncDatagramBudget()
	page, err := gossip.CatalogPageFor(d.Sync.State.Network, cursor, budget)
	if err != nil {
		d.recordSyncPeerState(peerID, "catalog_page_reject", func(state *stateFile) {
			recordDatagramTooLarge(state, peerID, "send", "catalog_page", "", "", 0, budget, d.Sync.now())
			recordCatalogReject(state, peerID, cursor, gossip.RejectReason(err), d.Sync.now())
		})
		d.logWarn("sync", "catalog_page_failed", map[string]any{
			"peer_id": peerID,
			"cursor":  cursor,
			"error":   err,
			"via":     "responder",
		})
		return nil
	}
	d.recordSyncPeerState(peerID, "catalog_page", func(state *stateFile) {
		recordCatalogPage(state, peerID, page, d.Sync.now())
	})
	d.sendSyncMessage(peerID, &gossip.Message{
		Type:        gossip.MessageCatalogPage,
		CatalogPage: page,
	})
	return nil
}

func (d *DaemonService) respondFetchZone(peerID string, path zone.ZonePath) error {
	if d == nil || d.Sync == nil || d.Sync.State == nil || d.Sync.State.Network == nil {
		return nil
	}
	d.recordSyncPeerState(peerID, "read_only_responder", func(state *stateFile) {
		recordReadOnlyResponder(state, peerID, "fetch_zone", path, d.Sync.now())
	})
	snap, err := gossip.Snapshot(d.Sync.State.Network, path)
	if err != nil {
		d.logDebug("sync", "fetch_zone_snapshot_missing", map[string]any{
			"peer_id": peerID,
			"zone":    path,
			"error":   err,
			"via":     "responder",
		})
		return nil
	}
	return d.respondAnnounceSnapshots(peerID, []*gossip.ZoneSnapshot{snap})
}

func (d *DaemonService) respondFetchZoneChunks(peerID string, path zone.ZonePath) error {
	if d == nil || d.Sync == nil || d.Sync.State == nil {
		return nil
	}
	d.recordSyncPeerState(peerID, "read_only_responder", func(state *stateFile) {
		recordReadOnlyResponder(state, peerID, "chunk_fallback", path, d.Sync.now())
	})
	return d.Sync.sendSnapshots(peerID, []zone.ZonePath{path}, true)
}

func (d *DaemonService) respondAnnounceSnapshots(peerID string, snapshots []*gossip.ZoneSnapshot) error {
	if d == nil || d.Sync == nil || d.Sync.State == nil || d.Sync.State.Network == nil || len(snapshots) == 0 {
		return nil
	}
	budget := d.syncDatagramBudget()
	zones := make([]zone.ZonePath, 0, len(snapshots))
	for _, snap := range snapshots {
		if snap != nil {
			zones = append(zones, snap.Zone)
		}
	}
	plan := planSnapshotDatagrams(d.Sync.State.Network, zones, budget, d.Sync.now())
	for _, oversized := range plan.Oversized {
		d.recordSyncPeerState(peerID, "datagram_too_large", func(state *stateFile) {
			recordDatagramTooLarge(state, peerID, "send", oversized.Object, oversized.Zone, oversized.Key, oversized.Size, budget, d.Sync.now())
		})
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
		d.sendSyncMessage(peerID, &gossip.Message{
			Type:     gossip.MessageAnnounce,
			Announce: announce,
		})
	}
	return nil
}

func (d *DaemonService) handleSyncEvent(ctx context.Context, event SyncEvent) {
	unlock := d.lockState()
	defer unlock()
	peerID := syncEventPeerID(event)
	if peerID == "" {
		d.logDebug("sync", "event_dropped", map[string]any{"reason": "no_peer_id"})
		return
	}
	session := d.syncSessions[peerID]
	if session == nil {
		d.logDebug("sync", "event_dropped", map[string]any{
			"peer_id": peerID,
			"reason":  "no_session",
		})
		return
	}
	// Enrich packet-derived events with current-state derivations right before
	// the FSM consumes them, so stale snapshots are not used after state changes
	// (e.g. a record_put that arrived while the event was queued).
	switch e := event.(type) {
	case *PongReceivedEvent:
		if e.Pong != nil {
			if e.Pong.Summary != nil {
				d.recordSyncPeerState(peerID, "catalog_summary", func(state *stateFile) {
					recordCatalogSummary(state, peerID, e.Pong.Summary, d.Sync.now())
				})
			}
		}
	case *CatalogSummaryReceivedEvent:
		d.recordSyncPeerState(peerID, "catalog_summary", func(state *stateFile) {
			recordCatalogSummary(state, peerID, e.Summary, d.Sync.now())
		})
	case *CatalogPageReceivedEvent:
		e.LocalEntries = gossip.ZoneDigests(d.Sync.State.Network)
		e.Page = filterRemoteCatalogPage(d.Sync.State, peerID, e.Page, d.Sync.now())
		d.recordSyncPeerState(peerID, "catalog_page", func(state *stateFile) {
			recordCatalogPage(state, peerID, e.Page, d.Sync.now())
		})
	}
	oldState := session.State
	actions, err := session.OnEvent(event, d.Sync.now())
	if err != nil {
		d.logWarn("sync", "session_event_error", map[string]any{
			"peer_id": peerID,
			"error":   err,
		})
		session.State = SyncSessionFailed
		session.lastError = err
	}
	d.recordSyncPeerState(peerID, "active_pull", func(state *stateFile) {
		recordSyncActivePull(state, peerID, syncEventName(event), session, d.Sync.now())
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
	changed := d.executeSyncActions(ctx, session, actions)
	if session.Done() {
		d.completeSyncSession(session, changed)
	}
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
	}
	return ""
}

func (d *DaemonService) recordSyncPeerState(peerID, label string, fn func(*stateFile)) {
	if d == nil || d.Sync == nil || fn == nil {
		return
	}
	liveLocked := d.hasStateLock()
	if d.Sync.State != nil && liveLocked {
		fn(d.Sync.State)
	}
	if d.StateStore == nil {
		if d.Sync.State != nil && !liveLocked {
			d.Sync.State.Lock()
			fn(d.Sync.State)
			d.Sync.State.Unlock()
		}
		return
	}
	if _, err := d.StateStore.Update(func(state *stateFile) error {
		fn(state)
		return nil
	}); err != nil {
		d.logWarn("sync", "sync_peer_state_commit_failed", map[string]any{
			"peer_id": peerID,
			"label":   label,
			"error":   err,
		})
	}
	if !liveLocked && d.liveStateReadableNow() {
		d.installCommittedSnapshotIfLiveUnlocked()
	}
}

func (d *DaemonService) liveStateReadableNow() bool {
	if d == nil || d.Sync == nil || d.Sync.State == nil {
		return true
	}
	unlock, ok := tryStateRLockWithin(d.Sync.State, stateReadLockTimeout)
	if !ok {
		return false
	}
	unlock()
	return true
}

func (d *DaemonService) executeSyncActions(ctx context.Context, session *SyncSession, actions []SyncAction) bool {
	if len(actions) == 0 {
		return false
	}
	peerID := session.PeerID
	now := d.Sync.now()
	configureValidation(d.Sync.State.Network)

	var changed bool
	limits := syncLimits(d.Sync.Config)

	// First pass: apply snapshots and records.
	for _, action := range actions {
		switch a := action.(type) {
		case ApplySnapshotAction:
			if a.Snapshot == nil {
				continue
			}
			if a.Snapshot.Zone == d.Sync.State.ManagedZone {
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
			result, err := gossip.ApplySnapshot(d.Sync.State.Network, a.Snapshot, now, applyLimits)
			if err != nil {
				d.recordSyncPeerState(peerID, "rejected_digest", func(state *stateFile) {
					recordRejectedDigest(state, peerID, digestForSnapshot(a.Snapshot), gossip.RejectReason(err), now)
				})
				d.logWarn("sync", "zone_apply_failed", map[string]any{
					"peer_id": peerID,
					"zone":    a.Snapshot.Zone,
					"reason":  gossip.RejectReason(err),
					"error":   err,
				})
				continue
			}
			d.recordSyncPeerState(peerID, "clear_rejected_digest", func(state *stateFile) {
				clearRejectedDigest(state, peerID, a.Snapshot.Zone)
			})
			changed = true
			d.logInfo("sync", "zone_applied", map[string]any{
				"peer_id":     peerID,
				"zone":        a.Snapshot.Zone,
				"records":     result.Records,
				"delegations": result.Delegation,
				"via":         "event_loop",
			})
			d.tryAdoptAutoJoinAfterSync(peerID, "event_loop", now, &changed)
		}
	}

	// Second pass: persist once if any apply succeeded.
	if changed {
		if err := d.Sync.saveState(); err != nil {
			d.logWarn("sync", "save_failed", map[string]any{"peer_id": peerID, "error": err})
		}
	}

	// Applied object-pull or chunk-fallback snapshots may leave a zone pending
	// until the FSM sees local state again. Reconcile before sending more I/O.
	if !session.Done() {
		reconcileActions := session.reconcilePendingWithState(d.Sync.State.Network)
		actions = append(actions, reconcileActions...)
	}

	// Third pass: send messages.
	budget := gossip.DefaultMaxMessage
	budget = d.syncDatagramBudget()
	for _, action := range actions {
		switch a := action.(type) {
		case SendPingAction:
			d.sendSyncMessage(peerID, &gossip.Message{
				Type: gossip.MessagePing,
				Ping: &gossip.Ping{Summary: a.Summary},
			})
		case SendFetchCatalogPageAction:
			d.sendSyncMessage(peerID, &gossip.Message{
				Type:             gossip.MessageFetchCatalogPage,
				FetchCatalogPage: &gossip.FetchCatalogPage{Cursor: a.Cursor},
			})
		case SendCatalogPageAction:
			page, err := gossip.CatalogPageFor(d.Sync.State.Network, a.Cursor, budget)
			if err != nil {
				d.recordSyncPeerState(peerID, "catalog_page_reject", func(state *stateFile) {
					recordDatagramTooLarge(state, peerID, "send", "catalog_page", "", "", 0, budget, d.Sync.now())
					recordCatalogReject(state, peerID, a.Cursor, gossip.RejectReason(err), d.Sync.now())
				})
				d.logWarn("sync", "catalog_page_failed", map[string]any{
					"peer_id": peerID,
					"cursor":  a.Cursor,
					"error":   err,
				})
				continue
			}
			d.recordSyncPeerState(peerID, "catalog_page", func(state *stateFile) {
				recordCatalogPage(state, peerID, page, d.Sync.now())
			})
			d.sendSyncMessage(peerID, &gossip.Message{
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
			d.sendSyncMessage(peerID, &gossip.Message{
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

	// Final pass: backoff and save-state actions.
	for _, action := range actions {
		switch a := action.(type) {
		case RecordBackoffAction:
			d.recordSyncPeerState(a.PeerID, "peer_backoff", func(state *stateFile) {
				recordPeerBackoff(state, a.PeerID, a.Err, now)
			})
		case SaveStateAction:
			if err := d.Sync.saveState(); err != nil {
				d.logWarn("sync", "save_failed", map[string]any{
					"peer_id": peerID,
					"reason":  a.Reason,
					"error":   err,
				})
			}
		}
	}

	return changed
}

func (d *DaemonService) submitObjectPull(ctx context.Context, peerID string, path zone.ZonePath, now time.Time) {
	if d == nil || d.objectPullPool == nil || d.Sync == nil || d.Sync.State == nil {
		return
	}
	state := d.Sync.State
	if snapshot, _, _ := d.snapshotState(); snapshot != nil {
		state = snapshot
	}
	addr := resolvePeerTCPAddr(state, d.Sync.Config, peerID)
	if addr == "" {
		err := fmt.Errorf("no TCP address for peer %s", peerID)
		result := ObjectPullResult{PeerID: peerID, Zone: path, Err: err, Unreachable: true}
		d.commitObjectPullResult(result)
		d.enqueueObjectPullResult(result)
		return
	}
	d.commitObjectPullAttempt(peerID, path, now)
	if !d.objectPullPool.Submit(ctx, ObjectPullRequest{PeerID: peerID, Zone: path, Addr: addr}) {
		err := errors.New("object pull submit failed")
		result := ObjectPullResult{PeerID: peerID, Zone: path, Err: err, Unreachable: true}
		d.commitObjectPullResult(result)
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

func (d *DaemonService) tryAdoptAutoJoinAfterSync(peerID, via string, now time.Time, changed *bool) {
	adopted, err := tryAdoptAutoJoinDelegation(d.Sync.State, now)
	recordAdoptionResult(d.Sync.State, adopted, err, now)
	if err != nil {
		d.logWarn("auto_join", "adopt_failed", map[string]any{
			"peer_id": peerID,
			"zone":    d.Sync.State.ManagedZone,
			"via":     via,
			"error":   err,
		})
		return
	}
	if !adopted {
		// Record bootstrap sync success for pending diagnostics.
		recordBootstrapSyncSuccess(d.Sync.State, peerID, d.Sync.Config, now)
		return
	}
	if changed != nil {
		*changed = true
	}
	d.logInfo("auto_join", "adopted", map[string]any{
		"peer_id": peerID,
		"zone":    d.Sync.State.ManagedZone,
		"via":     via,
	})
}

func (d *DaemonService) sendSyncMessage(peerID string, msg *gossip.Message) {
	if d.Sync == nil || d.Sync.Transport == nil {
		return
	}
	budget := d.syncDatagramBudget()
	if size := messageWireSize(msg); size > budget {
		object := string(msg.Type)
		d.recordSyncPeerState(peerID, "datagram_too_large", func(state *stateFile) {
			recordDatagramTooLarge(state, peerID, "send", object, "", "", size, budget, d.Sync.now())
		})
		d.logWarn("transport", "datagram_too_large", map[string]any{
			"peer_id": peerID,
			"type":    msg.Type,
			"bytes":   size,
			"limit":   budget,
			"action":  "drop",
		})
		return
	}
	if err := d.Sync.Transport.Send(peerID, msg); err != nil {
		d.logDebug("sync", "send_failed", map[string]any{
			"peer_id": peerID,
			"type":    msg.Type,
			"error":   err,
		})
	}
}

func (d *DaemonService) completeSyncSession(session *SyncSession, changed bool) {
	peerID := session.PeerID
	d.timerManager.CancelAll(peerID)
	d.recordSyncPeerState(peerID, "peer_sync", func(state *stateFile) {
		recordPeerSyncAt(state, peerID, session.lastError, d.Sync.now())
	})
	// Only mark the last-used address as failing for timeout-like errors; do
	// not penalize the address for internal/event handling failures.
	if session.lastError != nil && d.Sync.Transport != nil && strings.Contains(session.lastError.Error(), "timeout") {
		if lastAddr := d.Sync.Transport.LastSendAddr(peerID); lastAddr != nil {
			d.Sync.Transport.RecordAddrFailure(peerID, lastAddr)
		}
	}
	if session.State == SyncSessionCompleted && changed {
		if d.Sync.Transport != nil {
			d.Sync.updateDiscoveredPeers()
		}
		d.notifyStateChanged()
		d.relaySyncToPeers(peerID)
		if err := d.Sync.saveState(); err != nil {
			d.logWarn("sync", "session_save_failed", map[string]any{"peer_id": peerID, "error": err})
		}
	}
	delete(d.syncSessions, peerID)
	if d.pendingSyncHints != nil && d.pendingSyncHints[peerID] {
		delete(d.pendingSyncHints, peerID)
		_ = d.startHintedSyncSession(peerID, "announce_hint_followup")
	}
}

func (d *DaemonService) relaySyncToPeers(sourcePeerID string) {
	now := d.Sync.now()
	relayed := 0
	for _, peerID := range outboundSyncPeersAt(d.Sync.State, d.Sync.Config, now) {
		if peerID == sourcePeerID {
			continue
		}
		if relayed >= maxRelayFanoutPerUpdate {
			recordRelaySuppression(d.Sync.State, peerID, "relay_fanout_limited", now)
			continue
		}
		allowed, reason := shouldRelayToPeer(d.Sync.State.SyncPeers[peerID], peerID, sourcePeerID, now)
		if !allowed {
			recordRelaySuppression(d.Sync.State, peerID, reason, now)
			continue
		}
		relayed++
		if existing, ok := d.syncSessions[peerID]; ok && !existing.Done() {
			continue
		}
		d.syncSessions[peerID] = NewSyncSession(peerID)
		select {
		case d.syncEvents <- &SyncTimerEvent{PeerID: peerID, LocalDigests: gossip.ZoneDigests(d.Sync.State.Network)}:
		default:
			d.logWarn("sync", "relay_event_full", map[string]any{"peer_id": peerID, "source_peer": sourcePeerID})
		}
		recordRelaySuccess(d.Sync.State, peerID, sourcePeerID, now)
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
