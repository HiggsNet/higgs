package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corehost "github.com/HiggsNet/photon/pkg/core/host"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

// EnableEventLoopSync configures the event-loop gossip.SyncSession clock. The
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
		d.hostRuntime = corehost.NewRuntime(clock, corehost.DefaultEventBuffer)
		return
	}
	d.hostRuntime.ResetScheduler(clock)
}

func (d *DaemonService) handleSyncTimerEventLoop(_ context.Context, force bool) error {
	if d == nil || d.Sync == nil {
		return nil
	}
	now := d.Sync.now()
	projection := d.StateStore.syncTimerProjection(d.Sync.Config, now)
	peers := projection.peers
	if len(peers) == 0 {
		return nil
	}
	d.logDebug("sync", "event_loop_timer", map[string]any{
		"peer_count": len(peers),
		"force":      force,
	})
	for _, peerID := range peers {
		if !force && backoffRemaining(projection.peerStates[peerID], now) > 0 {
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
			LocalSummary: projection.summary,
		}
		if err := d.hostRuntime.PostGossip(event); err != nil {
			d.logWarn("sync", "event_loop_full", map[string]any{"peer_id": peerID})
		}
	}
	return nil
}

func (d *DaemonService) handlePacketEventSyncSession(packet *gossip.Packet, ctx context.Context) error {
	if packet != nil && packet.Message != nil && d != nil && d.Sync != nil {
		msg := packet.Message
		now := d.Sync.now()
		mutations := []func(*stateFile){
			func(state *stateFile) {
				recordVerifiedObservedPath(state, msg.PeerID, packet.Addr, msg.Type, now)
			},
		}
		label := "observed_path"
		if request, ok := gossip.ClassifyReadOnlyRequest(msg); ok &&
			(request.Kind != gossip.ReadOnlyChunkFallback || d.Sync.Transport != nil) {
			label += ",read_only_responder"
			mutations = append(mutations, func(state *stateFile) {
				recordReadOnlyResponder(state, msg.PeerID, string(request.Kind), request.Zone, now)
			})
		}
		d.recordPacketPeerStateBatch(msg.PeerID, label, mutations...)
		d.seedObservedPeerPath(msg.PeerID)
	}
	controller := &daemonGossipActionController{
		daemon: d,
		now:    d.Sync.now(),
		limits: syncLimits(d.Sync.Config),
	}
	return d.hostRuntime.ExecuteGossipInbound(ctx, d.hostRuntime.Gossip.PlanInbound(packet), controller)
}

func (d *DaemonService) handleAnnounceHint(peerID string) error {
	if d == nil || d.Sync == nil || peerID == "" {
		return nil
	}
	now := d.Sync.now()
	if d.hostRuntime.Gossip.HasActiveSession(peerID) {
		d.hostRuntime.Gossip.DeferHint(peerID)
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
	summary := d.StateStore.catalogSummaryProjection()
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
	d.recordSyncPeerStateBatch(peerID, "sync_hint,active_pull",
		func(state *stateFile) {
			recordSyncHint(state, peerID, reason, "", true, now)
		},
		func(state *stateFile) {
			recordSyncActivePull(state, peerID, "hint_queued", session, now)
		},
	)
	d.logDebug("sync", "hinted_sync_started", map[string]any{
		"peer_id": peerID,
		"reason":  reason,
	})
	return nil
}
func (d *DaemonService) respondFetchZone(peerID string, path zone.ZonePath) error {
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
	return d.respondAnnouncePlan(peerID, plan, budget)
}

func (d *DaemonService) respondFetchZoneChunks(peerID string, path zone.ZonePath) error {
	if d == nil || d.Sync == nil || d.Sync.Transport == nil {
		return nil
	}
	now := d.Sync.now()
	plan, snapshot, err := d.StateStore.fetchZoneChunkProjection(path, d.syncDatagramBudget(), now)
	if err != nil || snapshot == nil {
		return nil
	}
	diag, err := sendDetachedSnapshotWithDiagnostics(snapshot, plan, d.Sync.Transport, peerID, now, d.Sync.logger())
	recordDatagramSendDiagnostics(d.PeerObservability, peerID, diag, d.syncDatagramBudget(), now)
	return err
}

func (d *DaemonService) respondAnnouncePlan(peerID string, plan gossip.DatagramPlan, budget int) error {
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
		d.sendSyncMessage(peerID, &gossip.Message{
			Type:     gossip.MessageAnnounce,
			Announce: announce,
		})
	}
	return nil
}

func (d *DaemonService) handleSyncEvent(ctx context.Context, event gossip.SyncEvent) bool {
	peerID := gossip.SyncEventPeerID(event)
	if peerID == "" {
		d.logDebug("sync", "event_dropped", map[string]any{"reason": "no_peer_id"})
		return false
	}
	session := d.hostRuntime.Gossip.Session(peerID)
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
	case *gossip.PongReceivedEvent:
		if e.Pong != nil {
			if e.Pong.Summary != nil {
				recordCatalogSummary(d.PeerObservability, peerID, e.Pong.Summary, d.Sync.now())
			}
		}
	case *gossip.CatalogSummaryReceivedEvent:
		recordCatalogSummary(d.PeerObservability, peerID, e.Summary, d.Sync.now())
	case *gossip.CatalogPageReceivedEvent:
		e.LocalEntries, e.Page = d.StateStore.filteredCatalogProjection(peerID, e.Page, d.Sync.now())
		recordCatalogPage(d.PeerObservability, peerID, e.Page, d.Sync.now())
	}
	if _, ok := event.(*gossip.RoundTimeoutEvent); ok {
		udpChunkAssemblies.DropPeer(peerID)
	}
	engineResult := d.hostRuntime.Gossip.HandleEvent(event, d.Sync.now())
	if engineResult.Err != nil {
		d.logWarn("sync", "session_event_error", map[string]any{
			"peer_id": peerID,
			"error":   engineResult.Err,
		})
	}
	actions := engineResult.Actions
	eventName := gossip.SyncEventName(event)
	eventNow := d.Sync.now()
	activeSession := &gossip.SyncSession{State: session.State}
	mutations := newSyncPeerStateMutationBatch(peerID)
	mutations.add("active_pull", func(state *stateFile) {
		recordSyncActivePull(state, peerID, eventName, activeSession, eventNow)
	})
	if session.State != engineResult.OldState {
		d.logDebug("sync", "session_state_changed", map[string]any{
			"peer_id":   peerID,
			"event":     fmt.Sprintf("%T", event),
			"old_state": engineResult.OldState,
			"new_state": session.State,
			"pending":   session.PendingCount(),
			"inflight":  session.InflightCount(),
		})
	}
	changed := d.executeSyncActionsWithMutations(ctx, session, actions, mutations)
	if session.Done() {
		mutations.addCompletion(session, eventNow)
	}
	mutations.commit(d)
	if session.Done() {
		d.completeSyncSessionAfterPeerState(session, changed)
	}
	return changed
}

func filterRemoteCatalogPage(state *stateFile, peerID string, page *corestate.CatalogPage, now time.Time) *corestate.CatalogPage {
	if page == nil || state == nil || len(page.Entries) == 0 {
		return page
	}
	filtered := *page
	filtered.Entries = make([]corestate.ZoneDigest, 0, len(page.Entries))
	for _, entry := range page.Entries {
		if shouldSkipRemoteZone(state, peerID, entry.Zone, entry.RootHash, now) {
			continue
		}
		filtered.Entries = append(filtered.Entries, entry)
	}
	return &filtered
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
	}
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
	}
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

func (b *syncPeerStateMutationBatch) addCompletion(session *gossip.SyncSession, now time.Time) {
	if b == nil || session == nil || b.completionRecorded {
		return
	}
	peerID := session.PeerID
	lastError := session.LastError()
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
	action gossip.ApplySnapshotAction
	limits corestate.SyncLimits
}

type syncSnapshotOutcome struct {
	result      *corestate.ApplyResult
	applyErr    error
	adopted     bool
	adoptionErr error
	refreshed   bool
	refreshErr  error
	managedZone zone.ZonePath
}

// applySyncSnapshotBatch gives every action an independent target-zone COW
// savepoint, then publishes the final working root once. The callback body is
// pure with respect to external effects, so an unexpected stale revision can
// discard and recompute the complete batch safely.
func (d *DaemonService) applySyncSnapshotBatch(peerID string, applies []syncSnapshotApply, now time.Time) ([]syncSnapshotOutcome, bool, error) {
	if d == nil || d.Sync == nil || d.StateStore == nil {
		return nil, false, errors.New("daemon service is not initialized")
	}
	for range maxSyncPeerUpdateAttempts {
		state, revision := d.StateStore.snapshotApplyWorkspace()
		if state == nil || state.Network == nil {
			return nil, false, errors.New("daemon state network is nil")
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
			nextNetwork, result, err := corestate.ApplySnapshot(state.Network, snapshot, now, apply.limits)
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
			clearRejectedDigest(state, peerID, snapshot.Zone)
			outcome.result = result
			recordAdoptionResult(state, outcome.adopted, outcome.adoptionErr, now)
			if !outcome.adopted && outcome.adoptionErr == nil {
				recordBootstrapSyncSuccess(state, peerID, d.Sync.Config, now)
			}
			dirty = true
		}
		if !dirty {
			return outcomes, false, nil
		}
		if _, committed := d.StateStore.commitSnapshotApplyIfRevision(revision, state); committed {
			return outcomes, true, nil
		}
	}
	return nil, false, errDaemonStateRevisionStale
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

func (d *DaemonService) applySyncSnapshotAction(peerID string, action gossip.ApplySnapshotAction, limits corestate.SyncLimits, now time.Time) (*corestate.ApplyResult, bool, error) {
	if action.Snapshot == nil {
		return nil, false, nil
	}
	outcomes, committed, err := d.applySyncSnapshotBatch(peerID, []syncSnapshotApply{{action: action, limits: limits}}, now)
	if err != nil {
		return nil, false, err
	}
	if !committed || len(outcomes) == 0 {
		return nil, false, nil
	}
	outcome := outcomes[0]
	if outcome.applyErr != nil {
		return nil, false, outcome.applyErr
	}
	d.logSnapshotAdoption(peerID, outcome)
	return outcome.result, true, nil
}

type daemonGossipActionController struct {
	daemon    *DaemonService
	mutations *syncPeerStateMutationBatch
	now       time.Time
	limits    corestate.SyncLimits
}

func (controller *daemonGossipActionController) GossipStateView(context.Context) corehost.GossipStateView {
	projection := controller.daemon.StateStore.syncStateProjection()
	return corehost.GossipStateView{Loaded: projection.loaded, Digests: projection.digests}
}

func (controller *daemonGossipActionController) GossipDatagramBudget() int {
	return controller.daemon.syncDatagramBudget()
}

func (controller *daemonGossipActionController) ObserveGossipCatalogSummary(peerID string, summary *corestate.CatalogSummary) {
	recordCatalogSummary(controller.daemon.PeerObservability, peerID, summary, controller.now)
}

func (controller *daemonGossipActionController) ObserveGossipCatalogPage(peerID string, page *corestate.CatalogPage) {
	recordCatalogPage(controller.daemon.PeerObservability, peerID, page, controller.now)
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

func (controller *daemonGossipActionController) RecordGossipSummaryMatch(_ context.Context, peerID string) error {
	controller.daemon.recordSyncPeerStateBatch(peerID, "sync_hint,peer_sync",
		func(state *stateFile) {
			recordSyncHint(state, peerID, "ping_summary_match", "", true, controller.now)
		},
		func(state *stateFile) {
			recordPeerSyncAt(state, peerID, nil, controller.now)
		},
	)
	controller.daemon.logDebug("sync", "ping_summary_shortcut", map[string]any{
		"peer_id": peerID,
		"reason":  "catalog_root_match",
	})
	return nil
}

func (controller *daemonGossipActionController) HandleGossipAnnounceHint(_ context.Context, peerID string) error {
	return controller.daemon.handleAnnounceHint(peerID)
}

func (controller *daemonGossipActionController) RespondGossipFetchZone(_ context.Context, peerID string, request *gossip.FetchZone) error {
	if request == nil {
		return nil
	}
	if request.ChunkFallback {
		return controller.daemon.respondFetchZoneChunks(peerID, request.Zone)
	}
	return controller.daemon.respondFetchZone(peerID, request.Zone)
}

func (controller *daemonGossipActionController) HandleGossipObjectChunk(_ context.Context, message *gossip.Message) error {
	return controller.daemon.handleObjectChunk(message, controller.limits)
}

func (controller *daemonGossipActionController) HandleGossipObjectChunkNACK(_ context.Context, message *gossip.Message) error {
	return controller.daemon.Sync.handleObjectChunkNACK(message)
}

func (controller *daemonGossipActionController) ApplyGossipSnapshots(_ context.Context, peerID string, actions []gossip.ApplySnapshotAction) (corehost.GossipSnapshotApplyResult, error) {
	projection := controller.daemon.StateStore.syncStateProjection()
	var applies []syncSnapshotApply
	for _, action := range actions {
		if action.Snapshot == nil {
			continue
		}
		if action.Snapshot.Zone == projection.managedZone {
			controller.daemon.logDebug("sync", "skipping_own_zone_snapshot", map[string]any{
				"peer_id": peerID,
				"zone":    action.Snapshot.Zone,
			})
			continue
		}
		limits := controller.limits
		if action.RelaxedLimits {
			limits.MaxBytes = 8 << 20
		}
		applies = append(applies, syncSnapshotApply{action: action, limits: limits})
	}
	if len(applies) == 0 {
		return corehost.GossipSnapshotApplyResult{}, nil
	}
	outcomes, committed, err := controller.daemon.applySyncSnapshotBatch(peerID, applies, controller.now)
	if err != nil {
		return corehost.GossipSnapshotApplyResult{}, err
	}
	changed := false
	for i, outcome := range outcomes {
		apply := applies[i]
		if outcome.applyErr != nil {
			controller.daemon.logWarn("sync", "zone_apply_failed", map[string]any{
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
		changed = true
		controller.daemon.logSnapshotAdoption(peerID, outcome)
		controller.daemon.logInfo("sync", "zone_applied", map[string]any{
			"peer_id":     peerID,
			"zone":        apply.action.Snapshot.Zone,
			"records":     outcome.result.Records,
			"delegations": outcome.result.Delegation,
			"via":         "event_loop",
		})
	}
	return corehost.GossipSnapshotApplyResult{StateCommitted: committed, NetworkChanged: changed}, nil
}

func (controller *daemonGossipActionController) SendGossip(_ context.Context, outbound gossip.OutboundMessage) error {
	controller.daemon.sendSyncMessage(outbound.PeerID, outbound.Message)
	return nil
}

func (controller *daemonGossipActionController) StartGossipObjectPull(ctx context.Context, action gossip.StartObjectPullAction) error {
	controller.daemon.submitObjectPull(ctx, action.PeerID, action.Zone, controller.now)
	return nil
}

func (controller *daemonGossipActionController) RecordGossipBackoffs(_ context.Context, backoffs []gossip.RecordBackoffAction) error {
	for _, backoff := range backoffs {
		if controller.mutations == nil {
			controller.daemon.recordSyncPeerState(backoff.PeerID, "peer_backoff", func(state *stateFile) {
				recordPeerBackoff(state, backoff.PeerID, backoff.Err, controller.now)
			})
			continue
		}
		peerID := backoff.PeerID
		actionErr := backoff.Err
		controller.mutations.add("peer_backoff", func(state *stateFile) {
			recordPeerBackoff(state, peerID, actionErr, controller.now)
		})
	}
	return nil
}

func (controller *daemonGossipActionController) PersistGossip(_ context.Context, intent corehost.GossipPersistenceIntent, completion *corehost.GossipCompletionIntent) error {
	if controller.mutations != nil {
		if completion != nil && !controller.mutations.completionRecorded {
			peerID := completion.PeerID
			completionErr := completion.Err
			controller.mutations.add("peer_sync", func(state *stateFile) {
				recordPeerSyncAt(state, peerID, completionErr, controller.now)
			})
			controller.mutations.completionRecorded = true
		}
		controller.mutations.commit(controller.daemon)
	}
	if intent.Scope == gossip.SyncPersistenceNetwork {
		return controller.daemon.saveCommittedState()
	}
	controller.daemon.markMetadataCheckpointDirty()
	return nil
}

func (controller *daemonGossipActionController) ReportGossipIssue(issue corehost.GossipExecutionIssue) {
	event := "gossip_effect_failed"
	switch issue.Phase {
	case corehost.GossipPhaseApply:
		event = "snapshot_batch_commit_failed"
	case corehost.GossipPhaseInbound:
		event = "event_dropped"
	case corehost.GossipPhaseTimer:
		event = "timer_action_failed"
	case corehost.GossipPhasePersistence:
		event = "save_failed"
	}
	controller.daemon.logWarn("sync", event, map[string]any{
		"peer_id": issue.PeerID,
		"phase":   issue.Phase,
		"error":   issue.Err,
	})
}

func (d *DaemonService) executeSyncActionsWithMutations(ctx context.Context, session *gossip.SyncSession, actions []gossip.SyncAction, mutations *syncPeerStateMutationBatch) bool {
	if len(actions) == 0 || session == nil {
		return false
	}
	controller := &daemonGossipActionController{
		daemon:    d,
		mutations: mutations,
		now:       d.Sync.now(),
		limits:    syncLimits(d.Sync.Config),
	}
	result := d.hostRuntime.ExecuteGossipActions(ctx, session, actions, controller)
	return result.NetworkChanged
}

func (d *DaemonService) submitObjectPull(ctx context.Context, peerID string, path zone.ZonePath, now time.Time) {
	if d == nil || d.objectPullPool == nil || d.Sync == nil {
		return
	}
	addr, stateAvailable := d.StateStore.peerTCPAddrProjection(d.Sync.Config, peerID)
	if !stateAvailable {
		err := fmt.Errorf("no committed state for peer %s", peerID)
		result := ObjectPullResult{PeerID: peerID, Zone: path, Err: err, Unreachable: true}
		d.acceptObjectPullResult(result)
		return
	}
	if addr == "" {
		err := fmt.Errorf("no TCP address for peer %s", peerID)
		result := ObjectPullResult{PeerID: peerID, Zone: path, Err: err, Unreachable: true}
		d.acceptObjectPullResult(result)
		return
	}
	d.observeObjectPullAttempt(peerID, path, now)
	if !d.objectPullPool.Submit(ctx, ObjectPullRequest{PeerID: peerID, Zone: path, Addr: addr}) {
		err := errors.New("object pull submit failed")
		result := ObjectPullResult{PeerID: peerID, Zone: path, Err: err, Unreachable: true}
		d.acceptObjectPullResult(result)
	}
}

// acceptObjectPullResult is the sole ingress for completed platform pull work:
// Linux records transport diagnostics, then HostRuntime maps and orders the
// common completion with packet and timer events.
func (d *DaemonService) acceptObjectPullResult(result ObjectPullResult) {
	d.observeObjectPullResult(result)
	if err := d.hostRuntime.PostGossipObjectPullCompletion(corehost.GossipObjectPullCompletion{
		PeerID:   result.PeerID,
		Zone:     result.Zone,
		Snapshot: result.Snapshot,
		Err:      result.Err,
	}); err != nil {
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

func (d *DaemonService) sendSyncMessage(peerID string, msg *gossip.Message) {
	if d.Sync == nil || d.Sync.Transport == nil {
		return
	}
	budget := d.syncDatagramBudget()
	if size := gossip.MessageWireSize(msg); size > budget {
		object := string(msg.Type)
		recordDatagramTooLarge(d.PeerObservability, peerID, "send", object, "", "", size, budget, d.Sync.now())
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
		if err := d.saveCommittedState(); err != nil {
			d.logWarn("sync", "session_save_failed", map[string]any{"peer_id": peerID, "error": err})
		}
	}
	d.hostRuntime.Gossip.RemoveSession(peerID)
	if d.hostRuntime.Gossip.TakePendingHint(peerID) {
		_ = d.startHintedSyncSession(peerID, "announce_hint_followup")
	}
}

func (d *DaemonService) relaySyncToPeers(sourcePeerID string) {
	if d == nil || d.Sync == nil {
		return
	}
	now := d.Sync.now()
	relayed := 0
	projection := d.StateStore.relayProjection(d.Sync.Config, now)
	peers, peerStates := projection.peers, projection.peerStates
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
		allowed, reason := shouldRelayToPeer(peerStates[peerID], peerID, sourcePeerID, now)
		if !allowed {
			d.recordSyncPeerState(peerID, "relay_suppression", func(state *stateFile) {
				recordRelaySuppression(state, peerID, reason, now)
			})
			continue
		}
		relayed++
		if d.hostRuntime.Gossip.HasActiveSession(peerID) {
			continue
		}
		d.hostRuntime.Gossip.NewSession(peerID)
		if err := d.hostRuntime.PostGossip(&gossip.SyncTimerEvent{PeerID: peerID}); err != nil {
			d.logWarn("sync", "relay_event_full", map[string]any{"peer_id": peerID, "source_peer": sourcePeerID})
		}
		d.recordSyncPeerState(peerID, "relay_success", func(state *stateFile) {
			recordRelaySuccess(state, peerID, sourcePeerID, now)
		})
	}
}

func digestForSnapshot(snapshot *corestate.ZoneSnapshot) corestate.ZoneDigest {
	if snapshot == nil {
		return corestate.ZoneDigest{}
	}
	return corestate.ZoneDigest{
		Zone:     snapshot.Zone,
		RootHash: corestate.ZoneRoot(zoneStateFromSnapshot(snapshot)),
	}
}

func zoneStateFromSnapshot(snapshot *corestate.ZoneSnapshot) *zone.ZoneState {
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
