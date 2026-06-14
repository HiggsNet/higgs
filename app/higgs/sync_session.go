package main

import (
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
	MissingZones   []zone.ZonePath    // zones local needs from peer
	LocalSnapshots []*gossip.ZoneSnapshot // snapshots for zones peer requested from us
}

func (*PongReceivedEvent) isSyncEvent() {}

type FetchZoneReceivedEvent struct {
	PeerID   string
	Zone     zone.ZonePath
	Snapshot *gossip.ZoneSnapshot // nil if local does not have / will not serve this zone
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
	PeerID   string
	Snapshot *gossip.ZoneSnapshot
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
		for _, z := range e.MissingZones {
			s.pendingZones[z] = true
			actions = append(actions, SendFetchZoneAction{PeerID: e.PeerID, Zone: z})
		}
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
	if s.State != SyncSessionAwaitingAnnounce &&
		s.State != SyncSessionObjectPulling &&
		s.State != SyncSessionChunkFallback {
		return nil, nil
	}
	var actions []SyncAction
	for i := range e.Announce.Snapshots {
		snap := &e.Announce.Snapshots[i]
		actions = append(actions, ApplySnapshotAction{PeerID: e.PeerID, Snapshot: snap})
		delete(s.pendingZones, snap.Zone)
		delete(s.objectPullInflight, snap.Zone)
		delete(s.chunkFallbackZones, snap.Zone)
	}
	for i := range e.Announce.Records {
		rec := &e.Announce.Records[i]
		actions = append(actions, ApplyRecordSnapshotAction{PeerID: e.PeerID, Record: rec})
	}
	if s.pendingEmpty() {
		s.State = SyncSessionCompleted
		actions = append(actions, SaveStateAction{Reason: fmt.Sprintf("sync completed after announce from %s", e.PeerID)})
	} else {
		s.State = SyncSessionAwaitingAnnounce
	}
	return actions, nil
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
	if s.State != SyncSessionObjectPulling {
		return nil, nil
	}
	delete(s.objectPullInflight, e.Zone)
	if e.Err != nil {
		s.State = SyncSessionChunkFallback
		s.chunkFallbackZones[e.Zone] = true
		return []SyncAction{
			SendFetchZoneAction{PeerID: e.PeerID, Zone: e.Zone, ChunkFallback: true},
		}, nil
	}
	if e.Snapshot != nil {
		s.pendingZones[e.Snapshot.Zone] = false
		delete(s.pendingZones, e.Snapshot.Zone)
		if s.pendingEmpty() {
			s.State = SyncSessionCompleted
			return []SyncAction{
				ApplySnapshotAction{PeerID: e.PeerID, Snapshot: e.Snapshot},
				SaveStateAction{Reason: fmt.Sprintf("sync completed after object pull from %s", e.PeerID)},
			}, nil
		}
		s.State = SyncSessionAwaitingAnnounce
		return []SyncAction{ApplySnapshotAction{PeerID: e.PeerID, Snapshot: e.Snapshot}}, nil
	}
	return nil, nil
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
		if s.pendingEmpty() {
			s.State = SyncSessionCompleted
			return []SyncAction{
				ApplySnapshotAction{PeerID: e.PeerID, Snapshot: e.Snapshot},
				SaveStateAction{Reason: fmt.Sprintf("sync completed after chunk fallback from %s", e.PeerID)},
			}, nil
		}
		s.State = SyncSessionAwaitingAnnounce
		return []SyncAction{ApplySnapshotAction{PeerID: e.PeerID, Snapshot: e.Snapshot}}, nil
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
