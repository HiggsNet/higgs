package main

import (
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

// EnableEventLoopSync switches the daemon to the event-driven SyncSession sync
// path. It is intended for tests and future configuration; the default remains
// the old synchronous path. If clock is nil, d.Sync.App.Clock is used when
// available, otherwise the real system clock.
func (d *DaemonService) EnableEventLoopSync(clock Clock) {
	d.eventLoopSync = true
	if clock == nil {
		if d.Sync != nil && d.Sync.App != nil && d.Sync.App.Clock != nil {
			clock = &runtimeClock{now: d.Sync.App.Clock}
		} else {
			clock = NewRealClock()
		}
	}
	d.timerManager = NewTimerManager(clock, d.syncEvents)
}

func (d *DaemonService) handleSyncTimerEventLoop(ctx context.Context, force bool) error {
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
		event := &SyncTimerEvent{
			PeerID:       peerID,
			LocalDigests: gossip.ZoneDigests(d.Sync.State.Network),
		}
		select {
		case d.syncEvents <- event:
		default:
			d.logWarn("sync", "event_loop_full", map[string]any{"peer_id": peerID})
		}
	}
	return nil
}

func (d *DaemonService) handlePacketEventSyncSession(packet *gossip.Packet, ctx context.Context) error {
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
				_ = d.postSyncEvent(&PongReceivedEvent{
					PeerID: msg.PeerID,
					Pong:   &gossip.Pong{Zones: msg.Ping.Zones},
				})
			}
			return d.Sync.handlePacket(packet)
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
			// Chunk fallback requests need the legacy sendSnapshots path, which
			// knows how to split oversized zone snapshots into UDP object chunks.
			// The event-loop path only emits a single announce and cannot chunk.
			if msg.FetchZone.ChunkFallback {
				return d.Sync.handlePacket(packet)
			}
			return d.postSyncEvent(&FetchZoneReceivedEvent{
				PeerID: msg.PeerID,
				Zone:   msg.FetchZone.Zone,
			})
		case gossip.MessageAnnounce:
			if msg.Announce == nil {
				return nil
			}
			return d.postSyncEvent(&AnnounceReceivedEvent{
				PeerID:   msg.PeerID,
				Announce: msg.Announce,
			})
		case gossip.MessageObjectChunk:
			// Object chunks still use the global UDP chunk assembly store.
			return d.Sync.handleObjectChunk(msg, syncLimits(d.Sync.Config))
		default:
			return d.Sync.handlePacket(packet)
		}
	case *UnsolicitedPacketEvent:
		return d.Sync.handlePacket(packet)
	default:
		return d.Sync.handlePacket(packet)
	}
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

func localSnapshotsForPong(ns *zone.NetworkState, zones []zone.ZonePath) []*gossip.ZoneSnapshot {
	if ns == nil || len(zones) == 0 {
		return nil
	}
	var out []*gossip.ZoneSnapshot
	for _, z := range zones {
		snap, err := gossip.Snapshot(ns, z)
		if err != nil {
			continue
		}
		out = append(out, snap)
	}
	return out
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
			e.MissingZones = fetchListForPeer(d.Sync.State, peerID, e.Pong.Zones, d.Sync.now())
			e.LocalSnapshots = localSnapshotsForPong(d.Sync.State.Network, e.Pong.FetchZones)
		}
	case *FetchZoneReceivedEvent:
		if s, err := gossip.Snapshot(d.Sync.State.Network, e.Zone); err == nil {
			e.Snapshot = s
		}
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
	if session.State != oldState {
		d.logInfo("sync", "session_state_changed", map[string]any{
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

func syncEventPeerID(event SyncEvent) string {
	switch e := event.(type) {
	case *SyncTimerEvent:
		return e.PeerID
	case *PongReceivedEvent:
		return e.PeerID
	case *FetchZoneReceivedEvent:
		return e.PeerID
	case *AnnounceReceivedEvent:
		return e.PeerID
	case *PacketQuietTimeoutEvent:
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
				recordRejectedDigest(d.Sync.State, peerID, digestForSnapshot(a.Snapshot), gossip.RejectReason(err), now)
				d.logWarn("sync", "zone_apply_failed", map[string]any{
					"peer_id": peerID,
					"zone":    a.Snapshot.Zone,
					"reason":  gossip.RejectReason(err),
					"error":   err,
				})
				continue
			}
			clearRejectedDigest(d.Sync.State, peerID, a.Snapshot.Zone)
			changed = true
			d.logInfo("sync", "zone_applied", map[string]any{
				"peer_id":     peerID,
				"zone":        a.Snapshot.Zone,
				"records":     result.Records,
				"delegations": result.Delegation,
				"via":         "event_loop",
			})
		case ApplyRecordSnapshotAction:
			if a.Record == nil || a.Record.Record == nil {
				continue
			}
			if a.Record.Zone == d.Sync.State.ManagedZone {
				d.logDebug("sync", "skipping_own_zone_record", map[string]any{
					"peer_id": peerID,
					"zone":    a.Record.Zone,
					"key":     a.Record.Record.Key,
				})
				continue
			}
			err := gossip.ApplyRecordSnapshot(d.Sync.State.Network, a.Record, now)
			if err != nil {
				recordRejectedRecord(d.Sync.State, peerID, a.Record, gossip.RejectReason(err), now)
				d.logWarn("sync", "record_apply_failed", map[string]any{
					"peer_id": peerID,
					"zone":    a.Record.Zone,
					"key":     a.Record.Record.Key,
					"reason":  gossip.RejectReason(err),
					"error":   err,
				})
				continue
			}
			normalizeSyncPeers(d.Sync.State)
			peerState := d.Sync.State.SyncPeers[peerID]
			if peerState.RejectedDigests != nil {
				delete(peerState.RejectedDigests, rejectedRecordKey(a.Record.Zone, a.Record.Record.Key))
				d.Sync.State.SyncPeers[peerID] = peerState
			}
			changed = true
		}
	}

	// Second pass: persist once if any apply succeeded.
	if changed {
		if err := d.Sync.saveState(); err != nil {
			d.logWarn("sync", "save_failed", map[string]any{"peer_id": peerID, "error": err})
		}
	}

	// UDP skeletons and split record datagrams may leave a zone pending even
	// though the local state now matches the peer's advertised digest. Reconcile
	// so the session can complete without waiting for an unnecessary object pull.
	if !session.Done() {
		reconcileActions := session.reconcilePendingWithState(d.Sync.State.Network)
		actions = append(actions, reconcileActions...)
	}

	// Third pass: send messages. For FETCH_ZONE requests whose full snapshot
	// cannot fit in a UDP datagram, also queue an async object pull so we are
	// not dependent on the peer's UDP announce/chunk fallback path.
	var eagerPulls []zone.ZonePath
	budget := gossip.DefaultMaxMessage
	if d.Sync.Transport != nil {
		if m := d.Sync.Transport.MaxMessageBytes(); m > 0 {
			budget = m
		}
	}
	for _, action := range actions {
		switch a := action.(type) {
		case SendPingAction:
			d.sendSyncMessage(peerID, &gossip.Message{
				Type: gossip.MessagePing,
				Ping: &gossip.Ping{Zones: a.Digests},
			})
		case SendPongAction:
			d.sendSyncMessage(peerID, &gossip.Message{
				Type: gossip.MessagePong,
				Pong: &gossip.Pong{Zones: a.Digests, FetchZones: a.FetchZones},
			})
		case SendFetchZoneAction:
			d.sendSyncMessage(peerID, &gossip.Message{
				Type:      gossip.MessageFetchZone,
				FetchZone: &gossip.FetchZone{Zone: a.Zone, ChunkFallback: a.ChunkFallback},
			})
			if a.Zone != d.Sync.State.ManagedZone && !session.objectPullInflight[a.Zone] && zoneSnapshotExceedsBudget(d.Sync.State.Network, a.Zone, budget) {
				eagerPulls = append(eagerPulls, a.Zone)
				session.objectPullInflight[a.Zone] = true
			}
		case SendAnnounceAction:
			announce := &gossip.Announce{}
			if len(a.Snapshots) > 0 {
				announce.Snapshots = make([]gossip.ZoneSnapshot, 0, len(a.Snapshots))
				for _, snap := range a.Snapshots {
					if snap != nil {
						announce.Snapshots = append(announce.Snapshots, *snap)
					}
				}
			}
			if len(a.Records) > 0 {
				announce.Records = make([]gossip.RecordSnapshot, 0, len(a.Records))
				for _, rec := range a.Records {
					if rec != nil {
						announce.Records = append(announce.Records, *rec)
					}
				}
			}
			d.logInfo("sync", "sending_announce", map[string]any{
				"peer_id":          peerID,
				"zones":            len(announce.Snapshots),
				"records":          len(announce.Records),
				"snapshot_records": snapshotRecordsCount(announce.Snapshots),
			})
			d.sendSyncMessage(peerID, &gossip.Message{
				Type:     gossip.MessageAnnounce,
				Announce: announce,
			})
		}
	}

	// Fourth pass: start async object pulls.
	for _, path := range eagerPulls {
		d.objectPullPool.Submit(ctx, ObjectPullRequest{PeerID: peerID, Zone: path})
	}
	for _, action := range actions {
		if a, ok := action.(StartObjectPullAction); ok {
			d.objectPullPool.Submit(ctx, ObjectPullRequest{PeerID: a.PeerID, Zone: a.Zone})
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
			recordPeerBackoff(d.Sync.State, a.PeerID, a.Err, now)
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

func (d *DaemonService) sendSyncMessage(peerID string, msg *gossip.Message) {
	if d.Sync == nil || d.Sync.Transport == nil {
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
	recordPeerSyncAt(d.Sync.State, peerID, session.lastError, d.Sync.now())
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

func snapshotRecordsCount(snapshots []gossip.ZoneSnapshot) int {
	n := 0
	for i := range snapshots {
		n += len(snapshots[i].Records)
	}
	return n
}

func zoneSnapshotExceedsBudget(ns *zone.NetworkState, path zone.ZonePath, budget int) bool {
	if ns == nil || budget <= 0 {
		return false
	}
	snapshot, err := gossip.Snapshot(ns, path)
	if err != nil {
		return false
	}
	data, err := gossip.EncodeZoneSnapshotObject(snapshot)
	if err != nil {
		return false
	}
	return len(data) > budget
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
