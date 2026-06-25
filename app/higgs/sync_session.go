package main

import (
	"bytes"
	"errors"
	"fmt"
	"time"

	"github.com/Catofes/higgs/pkg/core/gossip"
	"github.com/Catofes/higgs/pkg/core/zone"
)

// SyncSessionState is the state of a per-peer sync FSM.
type SyncSessionState string

const (
	SyncSessionIdle             SyncSessionState = "idle"
	SyncSessionPingSent         SyncSessionState = "ping_sent"
	SyncSessionAwaitingAnnounce SyncSessionState = "awaiting_announce"
	SyncSessionFetchingLocal    SyncSessionState = "fetching_local"
	SyncSessionObjectPulling    SyncSessionState = "object_pulling"
	SyncSessionChunkFallback    SyncSessionState = "chunk_fallback"
	SyncSessionCompleted        SyncSessionState = "completed"
	SyncSessionFailed           SyncSessionState = "failed"
)

// RTT-aware timeout defaults. These match docs/phase6-event-driven-design.md.
const (
	MinPacketQuietTimeout = 250 * time.Millisecond
	MinRoundTimeout       = 5 * time.Second
	ObjectPullBudget      = 5 * time.Second
	InitialRTT            = 1 * time.Second

	kQuietMultiplier = 3
	kRoundMultiplier = 5
)

// SyncEvent is an event delivered to a SyncSession by the daemon event loop.
type SyncEvent interface {
	isSyncEvent()
}

type SyncTimerEvent struct {
	PeerID       string
	LocalDigests []gossip.ZoneDigest
}

func (*SyncTimerEvent) isSyncEvent() {}

type PongReceivedEvent struct {
	PeerID         string
	Pong           *gossip.Pong
	MissingZones   []zone.ZonePath        // populated by the event loop before OnEvent
	LocalSnapshots []*gossip.ZoneSnapshot // populated by the event loop before OnEvent
}

func (*PongReceivedEvent) isSyncEvent() {}

type FetchZoneReceivedEvent struct {
	PeerID   string
	Zone     zone.ZonePath
	Snapshot *gossip.ZoneSnapshot // populated by the event loop before OnEvent
}

func (*FetchZoneReceivedEvent) isSyncEvent() {}

type AnnounceReceivedEvent struct {
	PeerID   string
	Announce *gossip.Announce
}

func (*AnnounceReceivedEvent) isSyncEvent() {}

type PacketQuietTimeoutEvent struct {
	PeerID string
}

func (*PacketQuietTimeoutEvent) isSyncEvent() {}

type RoundTimeoutEvent struct {
	PeerID string
}

func (*RoundTimeoutEvent) isSyncEvent() {}

type ObjectPullResultEvent struct {
	PeerID   string
	Zone     zone.ZonePath
	Snapshot *gossip.ZoneSnapshot
	Err      error
}

func (*ObjectPullResultEvent) isSyncEvent() {}

type ObjectChunkEvent struct {
	PeerID   string
	Zone     zone.ZonePath
	Snapshot *gossip.ZoneSnapshot
	Err      error
}

func (*ObjectChunkEvent) isSyncEvent() {}

// SyncAction is an action returned by SyncSession.OnEvent for the event loop to execute.
type SyncAction interface {
	isSyncAction()
}

type SendPingAction struct {
	PeerID  string
	Digests []gossip.ZoneDigest
}

func (SendPingAction) isSyncAction() {}

type SendPongAction struct {
	PeerID     string
	Digests    []gossip.ZoneDigest
	FetchZones []zone.ZonePath
}

func (SendPongAction) isSyncAction() {}

type SendFetchZoneAction struct {
	PeerID        string
	Zone          zone.ZonePath
	ChunkFallback bool
}

func (SendFetchZoneAction) isSyncAction() {}

type SendAnnounceAction struct {
	PeerID    string
	Snapshots []*gossip.ZoneSnapshot
	Records   []*gossip.RecordSnapshot
}

func (SendAnnounceAction) isSyncAction() {}

type StartObjectPullAction struct {
	PeerID string
	Zone   zone.ZonePath
}

func (StartObjectPullAction) isSyncAction() {}

type ApplySnapshotAction struct {
	PeerID        string
	Snapshot      *gossip.ZoneSnapshot
	RelaxedLimits bool // set for object-pull / chunk-fallback snapshots
}

func (ApplySnapshotAction) isSyncAction() {}

type ApplyRecordSnapshotAction struct {
	PeerID string
	Record *gossip.RecordSnapshot
}

func (ApplyRecordSnapshotAction) isSyncAction() {}

type SaveStateAction struct {
	Reason string
}

func (SaveStateAction) isSyncAction() {}

type RecordBackoffAction struct {
	PeerID string
	Err    error
}

func (RecordBackoffAction) isSyncAction() {}

type StartTimerAction struct {
	PeerID   string
	Kind     string
	Deadline time.Time
}

func (StartTimerAction) isSyncAction() {}

type CancelTimerAction struct {
	PeerID string
	Kind   string
}

func (CancelTimerAction) isSyncAction() {}

// SyncSession is a per-peer sync state machine. It does not perform I/O;
// all side effects are returned as SyncAction values.
type SyncSession struct {
	PeerID string
	State  SyncSessionState

	// pendingZones are zones we believe the peer has and we need.
	pendingZones map[zone.ZonePath]bool
	// localFetchZones are zones the peer has explicitly requested from us.
	localFetchZones map[zone.ZonePath]bool
	// objectPullInflight tracks zones with an outstanding async TCP pull.
	objectPullInflight map[zone.ZonePath]bool
	// chunkFallbackZones tracks zones we are trying to receive via UDP chunk.
	chunkFallbackZones map[zone.ZonePath]bool
	// skeletonPending marks zones for which we received a UDP skeleton. Such
	// zones stay pending until we either receive records via UDP or finish an
	// object pull / chunk fallback. This prevents the local state from
	// accidentally matching a stale expected digest and declaring the zone done
	// while records are still missing.
	skeletonPending map[zone.ZonePath]bool
	// recordsReceived marks zones for which at least one record snapshot has
	// been applied since the skeleton was received. Once records have arrived,
	// normal root-hash reconciliation can complete the zone.
	recordsReceived map[zone.ZonePath]bool
	// expectedDigests maps pending zones to the remote root hash advertised in
	// the PONG. Used to detect stale or incomplete UDP announces.
	expectedDigests map[zone.ZonePath]gossip.ZoneDigest

	// RTT estimation.
	estimatedRTT time.Duration
	rttVariance  time.Duration
	pingSentAt   time.Time

	// quietCount counts PacketQuietTimeout firings in the active round.
	quietCount int

	lastError error
}

// NewSyncSession creates a new sync session for peerID.
func NewSyncSession(peerID string) *SyncSession {
	return &SyncSession{
		PeerID:             peerID,
		State:              SyncSessionIdle,
		pendingZones:       make(map[zone.ZonePath]bool),
		localFetchZones:    make(map[zone.ZonePath]bool),
		objectPullInflight: make(map[zone.ZonePath]bool),
		chunkFallbackZones: make(map[zone.ZonePath]bool),
		skeletonPending:    make(map[zone.ZonePath]bool),
		recordsReceived:    make(map[zone.ZonePath]bool),
		estimatedRTT:       InitialRTT,
	}
}

// OnEvent advances the state machine and returns actions for the event loop.
func (s *SyncSession) OnEvent(event SyncEvent, now time.Time) ([]SyncAction, error) {
	switch e := event.(type) {
	case *SyncTimerEvent:
		return s.onSyncTimer(e, now)
	case *PongReceivedEvent:
		return s.onPongReceived(e, now)
	case *FetchZoneReceivedEvent:
		return s.onFetchZoneReceived(e)
	case *AnnounceReceivedEvent:
		return s.onAnnounceReceived(e)
	case *PacketQuietTimeoutEvent:
		return s.onPacketQuietTimeout(e, now)
	case *RoundTimeoutEvent:
		return s.onRoundTimeout(e)
	case *ObjectPullResultEvent:
		return s.onObjectPullResult(e)
	case *ObjectChunkEvent:
		return s.onObjectChunk(e)
	default:
		return nil, fmt.Errorf("unknown sync event type %T", event)
	}
}

func (s *SyncSession) onSyncTimer(e *SyncTimerEvent, now time.Time) ([]SyncAction, error) {
	if s.State != SyncSessionIdle {
		return nil, nil
	}
	s.State = SyncSessionPingSent
	s.pingSentAt = now
	s.quietCount = 0
	s.pendingZones = make(map[zone.ZonePath]bool)
	s.localFetchZones = make(map[zone.ZonePath]bool)
	s.objectPullInflight = make(map[zone.ZonePath]bool)
	s.chunkFallbackZones = make(map[zone.ZonePath]bool)
	s.skeletonPending = make(map[zone.ZonePath]bool)
	s.recordsReceived = make(map[zone.ZonePath]bool)
	s.expectedDigests = make(map[zone.ZonePath]gossip.ZoneDigest)

	return []SyncAction{
		SendPingAction{PeerID: e.PeerID, Digests: e.LocalDigests},
		StartTimerAction{PeerID: e.PeerID, Kind: "round", Deadline: now.Add(s.roundTimeout())},
		StartTimerAction{PeerID: e.PeerID, Kind: "packet_quiet", Deadline: now.Add(s.packetQuietTimeout())},
	}, nil
}

func (s *SyncSession) onPongReceived(e *PongReceivedEvent, now time.Time) ([]SyncAction, error) {
	if s.State != SyncSessionPingSent {
		return nil, nil
	}
	if !s.pingSentAt.IsZero() && now.After(s.pingSentAt) {
		s.updateRTT(now.Sub(s.pingSentAt))
	}

	var actions []SyncAction

	// Peer asked us for zones: respond with announces.
	if len(e.LocalSnapshots) > 0 {
		for _, snap := range e.LocalSnapshots {
			s.localFetchZones[snap.Zone] = true
		}
		actions = append(actions, SendAnnounceAction{PeerID: e.PeerID, Snapshots: e.LocalSnapshots})
	}

	// We need zones from peer.
	if len(e.MissingZones) > 0 {
		s.State = SyncSessionAwaitingAnnounce
		s.quietCount = 0
		for _, z := range e.MissingZones {
			s.pendingZones[z] = true
			actions = append(actions, SendFetchZoneAction{PeerID: e.PeerID, Zone: z})
		}
		if e.Pong != nil {
			for _, d := range e.Pong.Zones {
				s.expectedDigests[d.Zone] = d
			}
		}
		actions = append(actions, StartTimerAction{PeerID: e.PeerID, Kind: "packet_quiet", Deadline: now.Add(s.packetQuietTimeout())})
		return actions, nil
	}

	if len(actions) == 0 {
		s.State = SyncSessionCompleted
		actions = append(actions, SaveStateAction{Reason: "sync completed after pong, no differences"})
	} else {
		s.State = SyncSessionFetchingLocal
	}
	return actions, nil
}

func (s *SyncSession) onFetchZoneReceived(e *FetchZoneReceivedEvent) ([]SyncAction, error) {
	if e.Snapshot == nil {
		return nil, nil
	}
	s.localFetchZones[e.Zone] = true
	if s.State == SyncSessionIdle || s.State == SyncSessionPingSent || s.State == SyncSessionAwaitingAnnounce {
		if s.State != SyncSessionAwaitingAnnounce {
			s.State = SyncSessionFetchingLocal
		}
		return []SyncAction{
			SendAnnounceAction{PeerID: e.PeerID, Snapshots: []*gossip.ZoneSnapshot{e.Snapshot}},
		}, nil
	}
	return []SyncAction{
		SendAnnounceAction{PeerID: e.PeerID, Snapshots: []*gossip.ZoneSnapshot{e.Snapshot}},
	}, nil
}

func (s *SyncSession) onAnnounceReceived(e *AnnounceReceivedEvent) ([]SyncAction, error) {
	// Accept announces while we are actively waiting for or pulling data from the
	// peer, and also while we are sending local zones to the peer (the peer may
	// send its own announces concurrently). Idle/completed/failed sessions should
	// ignore stale/relay traffic.
	if s.State != SyncSessionPingSent &&
		s.State != SyncSessionAwaitingAnnounce &&
		s.State != SyncSessionObjectPulling &&
		s.State != SyncSessionChunkFallback &&
		s.State != SyncSessionFetchingLocal {
		return nil, nil
	}
	var actions []SyncAction
	for i := range e.Announce.Snapshots {
		snap := &e.Announce.Snapshots[i]
		expected, ok := s.expectedDigests[snap.Zone]
		isSkeleton := len(snap.Records) == 0 && len(snap.RecordHistory) == 0
		if ok && !bytes.Equal(expected.RootHash, gossip.ZoneRoot(zoneStateFromSnapshot(snap))) {
			if !isSkeleton {
				// Stale or incomplete announce. Keep the zone pending so object
				// pull / chunk fallback can finish the sync.
				continue
			}
		}
		actions = append(actions, ApplySnapshotAction{PeerID: e.PeerID, Snapshot: snap, RelaxedLimits: false})
		if isSkeleton {
			// UDP skeletons intentionally omit records. Keep the zone pending
			// until records arrive or an object pull / chunk fallback completes.
			// Records received for a previous version of this zone are no longer
			// authoritative once a new skeleton arrives.
			s.skeletonPending[snap.Zone] = true
			delete(s.recordsReceived, snap.Zone)
			continue
		}
		delete(s.pendingZones, snap.Zone)
		delete(s.skeletonPending, snap.Zone)
		delete(s.recordsReceived, snap.Zone)
		delete(s.objectPullInflight, snap.Zone)
		delete(s.chunkFallbackZones, snap.Zone)
		delete(s.expectedDigests, snap.Zone)
	}
	for i := range e.Announce.Records {
		rec := &e.Announce.Records[i]
		actions = append(actions, ApplyRecordSnapshotAction{PeerID: e.PeerID, Record: rec})
		s.recordsReceived[rec.Zone] = true
	}
	if s.pendingEmpty() {
		s.State = SyncSessionCompleted
		actions = append(actions, SaveStateAction{Reason: fmt.Sprintf("sync completed after announce from %s", e.PeerID)})
	} else {
		s.State = SyncSessionAwaitingAnnounce
	}
	return actions, nil
}

// reconcilePendingWithState removes pending zones whose local root hash now
// matches the digest advertised by the peer. This is needed because UDP
// skeletons and split record datagrams populate a zone incrementally rather
// than in a single announce.
func (s *SyncSession) reconcilePendingWithState(ns *zone.NetworkState) []SyncAction {
	if ns == nil {
		return nil
	}
	for z := range s.pendingZones {
		if s.skeletonPending[z] {
			// We only have a UDP skeleton for this zone. Don't reconcile it away
			// until records arrive via UDP or an object pull / chunk fallback
			// completes. This prevents stale record datagrams or a coincidental
			// local root-hash match from hiding a real requirement.
			continue
		}
		expected, ok := s.expectedDigests[z]
		if !ok {
			continue
		}
		zs := ns.Zones[z]
		if zs == nil {
			continue
		}
		if bytes.Equal(expected.RootHash, gossip.ZoneRoot(zs)) {
			delete(s.pendingZones, z)
			delete(s.skeletonPending, z)
			delete(s.recordsReceived, z)
			delete(s.expectedDigests, z)
			delete(s.objectPullInflight, z)
			delete(s.chunkFallbackZones, z)
		}
	}
	if s.pendingEmpty() && (s.State == SyncSessionAwaitingAnnounce ||
		s.State == SyncSessionObjectPulling ||
		s.State == SyncSessionChunkFallback) {
		s.State = SyncSessionCompleted
		return []SyncAction{SaveStateAction{Reason: "sync completed after pending zones reconciled with local state"}}
	}
	return nil
}

func (s *SyncSession) onPacketQuietTimeout(e *PacketQuietTimeoutEvent, now time.Time) ([]SyncAction, error) {
	s.quietCount++
	switch s.State {
	case SyncSessionAwaitingAnnounce:
		if s.quietCount == 1 && !s.pendingEmpty() {
			s.State = SyncSessionObjectPulling
			var actions []SyncAction
			for z := range s.pendingZones {
				if s.objectPullInflight[z] {
					continue
				}
				s.objectPullInflight[z] = true
				actions = append(actions, StartObjectPullAction{PeerID: e.PeerID, Zone: z})
			}
			return actions, nil
		}
		if s.quietCount >= 2 {
			if s.pendingEmpty() {
				s.State = SyncSessionCompleted
				return []SyncAction{SaveStateAction{Reason: fmt.Sprintf("sync completed after quiet timeout from %s", e.PeerID)}}, nil
			}
			s.State = SyncSessionFailed
			s.lastError = errors.New("sync timed out with pending zones after UDP quiet period")
			return []SyncAction{
				RecordBackoffAction{PeerID: e.PeerID, Err: s.lastError},
				SaveStateAction{Reason: fmt.Sprintf("sync failed for %s: %v", e.PeerID, s.lastError)},
			}, nil
		}
	case SyncSessionObjectPulling, SyncSessionChunkFallback:
		if s.quietCount >= 2 {
			if s.pendingEmpty() {
				s.State = SyncSessionCompleted
				return []SyncAction{SaveStateAction{Reason: fmt.Sprintf("sync completed after post-pull quiet timeout from %s", e.PeerID)}}, nil
			}
			s.State = SyncSessionFailed
			s.lastError = errors.New("sync timed out with pending zones after object pull/chunk fallback")
			return []SyncAction{
				RecordBackoffAction{PeerID: e.PeerID, Err: s.lastError},
				SaveStateAction{Reason: fmt.Sprintf("sync failed for %s: %v", e.PeerID, s.lastError)},
			}, nil
		}
	case SyncSessionFetchingLocal:
		// We already sent the zones the peer requested and have no missing
		// zones of our own. If the UDP path has been quiet, the peer has had
		// enough time to ask for more; complete the round so a new session
		// can be started to pull updates from the peer.
		s.State = SyncSessionCompleted
		return []SyncAction{SaveStateAction{Reason: fmt.Sprintf("sync completed after quiet timeout from %s", e.PeerID)}}, nil
	}
	return nil, nil
}

func (s *SyncSession) onRoundTimeout(e *RoundTimeoutEvent) ([]SyncAction, error) {
	if s.State == SyncSessionCompleted || s.State == SyncSessionFailed || s.State == SyncSessionIdle {
		return nil, nil
	}
	s.State = SyncSessionFailed
	s.lastError = errors.New("round timeout")
	return []SyncAction{
		RecordBackoffAction{PeerID: e.PeerID, Err: s.lastError},
		SaveStateAction{Reason: fmt.Sprintf("sync failed for %s: round timeout", e.PeerID)},
		CancelTimerAction{PeerID: e.PeerID, Kind: "packet_quiet"},
	}, nil
}

func (s *SyncSession) onObjectPullResult(e *ObjectPullResultEvent) ([]SyncAction, error) {
	// Only process results for zones that are still in flight. A zone may be
	// removed from objectPullInflight early if an announce arrived first, or if
	// a concurrent result for the same zone was already processed.
	if !s.objectPullInflight[e.Zone] {
		return nil, nil
	}
	delete(s.objectPullInflight, e.Zone)

	var actions []SyncAction

	if e.Err != nil {
		s.chunkFallbackZones[e.Zone] = true
		actions = append(actions, SendFetchZoneAction{PeerID: e.PeerID, Zone: e.Zone, ChunkFallback: true})
	} else if e.Snapshot != nil {
		s.pendingZones[e.Snapshot.Zone] = false
		delete(s.pendingZones, e.Snapshot.Zone)
		delete(s.skeletonPending, e.Snapshot.Zone)
		delete(s.recordsReceived, e.Snapshot.Zone)
		actions = append(actions, ApplySnapshotAction{PeerID: e.PeerID, Snapshot: e.Snapshot, RelaxedLimits: true})
	}

	// Don't change state until all concurrent object pulls have reported back.
	if len(s.objectPullInflight) > 0 {
		return actions, nil
	}

	// If any zone failed over to UDP chunk fallback, stay in that state so
	// onObjectChunk can process the response. Otherwise complete if nothing is
	// left to fetch, or wait for UDP announces for the remaining zones.
	if len(s.chunkFallbackZones) > 0 {
		s.State = SyncSessionChunkFallback
	} else if s.pendingEmpty() {
		s.State = SyncSessionCompleted
		actions = append(actions, SaveStateAction{Reason: fmt.Sprintf("sync completed after object pull from %s", e.PeerID)})
	} else {
		s.State = SyncSessionAwaitingAnnounce
	}
	return actions, nil
}

func (s *SyncSession) onObjectChunk(e *ObjectChunkEvent) ([]SyncAction, error) {
	if s.State != SyncSessionChunkFallback {
		return nil, nil
	}
	if e.Err != nil {
		s.State = SyncSessionFailed
		s.lastError = e.Err
		return []SyncAction{
			RecordBackoffAction{PeerID: e.PeerID, Err: e.Err},
			SaveStateAction{Reason: fmt.Sprintf("sync failed for %s: chunk fallback error: %v", e.PeerID, e.Err)},
		}, nil
	}
	if e.Snapshot != nil {
		delete(s.chunkFallbackZones, e.Snapshot.Zone)
		delete(s.pendingZones, e.Snapshot.Zone)
		delete(s.skeletonPending, e.Snapshot.Zone)
		delete(s.recordsReceived, e.Snapshot.Zone)
		if s.pendingEmpty() {
			s.State = SyncSessionCompleted
			return []SyncAction{
				ApplySnapshotAction{PeerID: e.PeerID, Snapshot: e.Snapshot, RelaxedLimits: true},
				SaveStateAction{Reason: fmt.Sprintf("sync completed after chunk fallback from %s", e.PeerID)},
			}, nil
		}
		s.State = SyncSessionAwaitingAnnounce
		return []SyncAction{ApplySnapshotAction{PeerID: e.PeerID, Snapshot: e.Snapshot, RelaxedLimits: true}}, nil
	}
	return nil, nil
}

// Done returns true when the session has reached a terminal state.
func (s *SyncSession) Done() bool {
	return s.State == SyncSessionCompleted || s.State == SyncSessionFailed
}

// EstimatedRTT returns the current estimated RTT for this peer.
func (s *SyncSession) EstimatedRTT() time.Duration {
	if s.estimatedRTT <= 0 {
		return InitialRTT
	}
	return s.estimatedRTT
}

func (s *SyncSession) packetQuietTimeout() time.Duration {
	d := time.Duration(kQuietMultiplier) * s.EstimatedRTT()
	if d < MinPacketQuietTimeout {
		d = MinPacketQuietTimeout
	}
	return d
}

func (s *SyncSession) roundTimeout() time.Duration {
	d := time.Duration(kRoundMultiplier)*s.EstimatedRTT() + ObjectPullBudget
	if d < MinRoundTimeout {
		d = MinRoundTimeout
	}
	return d
}

func (s *SyncSession) updateRTT(sample time.Duration) {
	if sample <= 0 {
		return
	}
	if s.estimatedRTT <= 0 {
		s.estimatedRTT = sample
		s.rttVariance = sample / 2
		return
	}
	s.estimatedRTT = (7*s.estimatedRTT + sample) / 8
	diff := sample - s.estimatedRTT
	if diff < 0 {
		diff = -diff
	}
	s.rttVariance = (3*s.rttVariance + diff) / 4
}

func (s *SyncSession) pendingEmpty() bool {
	for _, v := range s.pendingZones {
		if v {
			return false
		}
	}
	return true
}
