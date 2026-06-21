package main

import (
	"errors"
	"testing"
	"time"

	"github.com/Catofes/higgs/pkg/core/gossip"
	"github.com/Catofes/higgs/pkg/core/zone"
)

func TestSyncSessionIdleToPingSent(t *testing.T) {
	s := NewSyncSession("peer-a")
	now := time.Unix(1000, 0)
	digests := []gossip.ZoneDigest{{Zone: "catofes.", RootHash: []byte("h1")}}

	actions, err := s.OnEvent(&SyncTimerEvent{PeerID: "peer-a", LocalDigests: digests}, now)
	if err != nil {
		t.Fatalf("OnEvent error: %v", err)
	}
	if s.State != SyncSessionPingSent {
		t.Fatalf("expected state ping_sent, got %s", s.State)
	}

	assertActionTypes(t, actions, []string{"SendPingAction", "StartTimerAction", "StartTimerAction"})

	ping := actions[0].(SendPingAction)
	if len(ping.Digests) != 1 || ping.Digests[0].Zone != "catofes." {
		t.Fatalf("unexpected ping digests: %+v", ping.Digests)
	}

	round := actions[1].(StartTimerAction)
	quiet := actions[2].(StartTimerAction)
	if round.Kind != "round" || quiet.Kind != "packet_quiet" {
		t.Fatalf("expected round and packet_quiet timers, got %s and %s", round.Kind, quiet.Kind)
	}
	if !round.Deadline.After(quiet.Deadline) {
		t.Fatalf("round deadline %v should be after quiet deadline %v", round.Deadline, quiet.Deadline)
	}
}

func TestSyncSessionPongNoDifferences(t *testing.T) {
	s := NewSyncSession("peer-a")
	now := time.Unix(1000, 0)
	digests := []gossip.ZoneDigest{{Zone: "catofes.", RootHash: []byte("h1")}}

	_, _ = s.OnEvent(&SyncTimerEvent{PeerID: "peer-a", LocalDigests: digests}, now)
	now = now.Add(100 * time.Millisecond)

	actions, err := s.OnEvent(&PongReceivedEvent{
		PeerID:         "peer-a",
		Pong:           &gossip.Pong{Zones: digests},
		MissingZones:   nil,
		LocalSnapshots: nil,
	}, now)
	if err != nil {
		t.Fatalf("OnEvent error: %v", err)
	}
	if s.State != SyncSessionCompleted {
		t.Fatalf("expected state completed, got %s", s.State)
	}
	assertActionTypes(t, actions, []string{"SaveStateAction"})
}

func TestSyncSessionPongWithMissingZones(t *testing.T) {
	s := NewSyncSession("peer-a")
	now := time.Unix(1000, 0)
	local := []gossip.ZoneDigest{{Zone: "catofes.", RootHash: []byte("h1")}}
	remote := []gossip.ZoneDigest{
		{Zone: "catofes.", RootHash: []byte("h1")},
		{Zone: "node-a.catofes.", RootHash: []byte("h2")},
	}

	_, _ = s.OnEvent(&SyncTimerEvent{PeerID: "peer-a", LocalDigests: local}, now)
	now = now.Add(50 * time.Millisecond)

	actions, err := s.OnEvent(&PongReceivedEvent{
		PeerID:         "peer-a",
		Pong:           &gossip.Pong{Zones: remote},
		MissingZones:   []zone.ZonePath{"node-a.catofes."},
		LocalSnapshots: nil,
	}, now)
	if err != nil {
		t.Fatalf("OnEvent error: %v", err)
	}
	if s.State != SyncSessionAwaitingAnnounce {
		t.Fatalf("expected state awaiting_announce, got %s", s.State)
	}
	assertActionTypes(t, actions, []string{"SendFetchZoneAction", "StartTimerAction"})
	if actions[0].(SendFetchZoneAction).Zone != "node-a.catofes." {
		t.Fatalf("unexpected fetch zone: %v", actions[0])
	}
	// Initial RTT is 1s; a 50ms sample should pull the estimate down toward the sample.
	if s.EstimatedRTT() >= InitialRTT {
		t.Fatalf("expected RTT estimate to decrease from initial %v, got %v", InitialRTT, s.EstimatedRTT())
	}
	if s.EstimatedRTT() <= 50*time.Millisecond {
		t.Fatalf("expected RTT estimate to remain above sample 50ms after one EWMA step, got %v", s.EstimatedRTT())
	}
}

func TestSyncSessionPongPeerRequestsLocalZones(t *testing.T) {
	s := NewSyncSession("peer-a")
	now := time.Unix(1000, 0)
	local := []gossip.ZoneDigest{{Zone: "catofes.", RootHash: []byte("h1")}}

	_, _ = s.OnEvent(&SyncTimerEvent{PeerID: "peer-a", LocalDigests: local}, now)
	now = now.Add(10 * time.Millisecond)

	snap := &gossip.ZoneSnapshot{Zone: "catofes."}
	actions, err := s.OnEvent(&PongReceivedEvent{
		PeerID:         "peer-a",
		Pong:           &gossip.Pong{Zones: local, FetchZones: []zone.ZonePath{"catofes."}},
		MissingZones:   nil,
		LocalSnapshots: []*gossip.ZoneSnapshot{snap},
	}, now)
	if err != nil {
		t.Fatalf("OnEvent error: %v", err)
	}
	if s.State != SyncSessionFetchingLocal {
		t.Fatalf("expected state fetching_local, got %s", s.State)
	}
	assertActionTypes(t, actions, []string{"SendAnnounceAction"})
	ann := actions[0].(SendAnnounceAction)
	if len(ann.Snapshots) != 1 || ann.Snapshots[0].Zone != "catofes." {
		t.Fatalf("unexpected announce snapshots: %+v", ann.Snapshots)
	}
}

func TestSyncSessionFetchZoneReceived(t *testing.T) {
	s := NewSyncSession("peer-a")
	now := time.Unix(1000, 0)

	snap := &gossip.ZoneSnapshot{Zone: "catofes."}
	actions, err := s.OnEvent(&FetchZoneReceivedEvent{PeerID: "peer-a", Zone: "catofes.", Snapshot: snap}, now)
	if err != nil {
		t.Fatalf("OnEvent error: %v", err)
	}
	if s.State != SyncSessionFetchingLocal {
		t.Fatalf("expected state fetching_local, got %s", s.State)
	}
	assertActionTypes(t, actions, []string{"SendAnnounceAction"})
}

func TestSyncSessionAnnounceAppliesAndCompletes(t *testing.T) {
	s := NewSyncSession("peer-a")
	now := time.Unix(1000, 0)

	_, _ = s.OnEvent(&SyncTimerEvent{PeerID: "peer-a", LocalDigests: nil}, now)
	_, _ = s.OnEvent(&PongReceivedEvent{
		PeerID:       "peer-a",
		Pong:         &gossip.Pong{},
		MissingZones: []zone.ZonePath{"node-a.catofes."},
	}, now)

	actions, err := s.OnEvent(&AnnounceReceivedEvent{
		PeerID: "peer-a",
		Announce: &gossip.Announce{
			Snapshots: []gossip.ZoneSnapshot{{Zone: "node-a.catofes."}},
		},
	}, now)
	if err != nil {
		t.Fatalf("OnEvent error: %v", err)
	}
	if s.State != SyncSessionCompleted {
		t.Fatalf("expected state completed, got %s", s.State)
	}
	assertActionTypes(t, actions, []string{"ApplySnapshotAction", "SaveStateAction"})
}

func TestSyncSessionQuietTimeoutStartsObjectPull(t *testing.T) {
	s := NewSyncSession("peer-a")
	now := time.Unix(1000, 0)

	_, _ = s.OnEvent(&SyncTimerEvent{PeerID: "peer-a", LocalDigests: nil}, now)
	_, _ = s.OnEvent(&PongReceivedEvent{
		PeerID:       "peer-a",
		Pong:         &gossip.Pong{},
		MissingZones: []zone.ZonePath{"node-a.catofes.", "node-b.catofes."},
	}, now)

	actions, err := s.OnEvent(&PacketQuietTimeoutEvent{PeerID: "peer-a"}, now)
	if err != nil {
		t.Fatalf("OnEvent error: %v", err)
	}
	if s.State != SyncSessionObjectPulling {
		t.Fatalf("expected state object_pulling, got %s", s.State)
	}
	assertActionTypes(t, actions, []string{"StartObjectPullAction", "StartObjectPullAction"})
}

func TestSyncSessionConcurrentObjectPullsComplete(t *testing.T) {
	s := NewSyncSession("peer-a")
	now := time.Unix(1000, 0)

	_, _ = s.OnEvent(&SyncTimerEvent{PeerID: "peer-a", LocalDigests: nil}, now)
	_, _ = s.OnEvent(&PongReceivedEvent{
		PeerID:       "peer-a",
		Pong:         &gossip.Pong{},
		MissingZones: []zone.ZonePath{"catofes.", "node-a.catofes."},
	}, now)
	_, _ = s.OnEvent(&PacketQuietTimeoutEvent{PeerID: "peer-a"}, now)

	if s.State != SyncSessionObjectPulling {
		t.Fatalf("expected state object_pulling, got %s", s.State)
	}

	// First result returns while the second pull is still in flight. The
	// session must stay in object_pulling so the second result is not dropped.
	actions1, err := s.OnEvent(&ObjectPullResultEvent{
		PeerID:   "peer-a",
		Zone:     "catofes.",
		Snapshot: &gossip.ZoneSnapshot{Zone: "catofes."},
	}, now)
	if err != nil {
		t.Fatalf("OnEvent error: %v", err)
	}
	if s.State != SyncSessionObjectPulling {
		t.Fatalf("expected state object_pulling after first concurrent result, got %s", s.State)
	}
	assertActionTypes(t, actions1, []string{"ApplySnapshotAction"})

	// Second result returns; both snapshots should be applied and session completes.
	actions2, err := s.OnEvent(&ObjectPullResultEvent{
		PeerID:   "peer-a",
		Zone:     "node-a.catofes.",
		Snapshot: &gossip.ZoneSnapshot{Zone: "node-a.catofes."},
	}, now)
	if err != nil {
		t.Fatalf("OnEvent error: %v", err)
	}
	if s.State != SyncSessionCompleted {
		t.Fatalf("expected state completed, got %s", s.State)
	}
	assertActionTypes(t, actions2, []string{"ApplySnapshotAction", "SaveStateAction"})
}

func TestSyncSessionConcurrentObjectPullsOneError(t *testing.T) {
	s := NewSyncSession("peer-a")
	now := time.Unix(1000, 0)

	_, _ = s.OnEvent(&SyncTimerEvent{PeerID: "peer-a", LocalDigests: nil}, now)
	_, _ = s.OnEvent(&PongReceivedEvent{
		PeerID:       "peer-a",
		Pong:         &gossip.Pong{},
		MissingZones: []zone.ZonePath{"catofes.", "node-a.catofes."},
	}, now)
	_, _ = s.OnEvent(&PacketQuietTimeoutEvent{PeerID: "peer-a"}, now)

	// First pull fails. We request chunk fallback but stay in object_pulling
	// because another pull is still in flight.
	actions1, err := s.OnEvent(&ObjectPullResultEvent{
		PeerID: "peer-a",
		Zone:   "catofes.",
		Err:    errors.New("tcp unreachable"),
	}, now)
	if err != nil {
		t.Fatalf("OnEvent error: %v", err)
	}
	if s.State != SyncSessionObjectPulling {
		t.Fatalf("expected state object_pulling after first error with in-flight pull, got %s", s.State)
	}
	assertActionTypes(t, actions1, []string{"SendFetchZoneAction"})

	// Second pull succeeds. Because a zone needs chunk fallback, we transition
	// to chunk_fallback instead of completed.
	actions2, err := s.OnEvent(&ObjectPullResultEvent{
		PeerID:   "peer-a",
		Zone:     "node-a.catofes.",
		Snapshot: &gossip.ZoneSnapshot{Zone: "node-a.catofes."},
	}, now)
	if err != nil {
		t.Fatalf("OnEvent error: %v", err)
	}
	if s.State != SyncSessionChunkFallback {
		t.Fatalf("expected state chunk_fallback, got %s", s.State)
	}
	assertActionTypes(t, actions2, []string{"ApplySnapshotAction"})
}

func TestSyncSessionObjectPullSuccess(t *testing.T) {
	s := NewSyncSession("peer-a")
	now := time.Unix(1000, 0)

	_, _ = s.OnEvent(&SyncTimerEvent{PeerID: "peer-a", LocalDigests: nil}, now)
	_, _ = s.OnEvent(&PongReceivedEvent{
		PeerID:       "peer-a",
		Pong:         &gossip.Pong{},
		MissingZones: []zone.ZonePath{"node-a.catofes."},
	}, now)
	_, _ = s.OnEvent(&PacketQuietTimeoutEvent{PeerID: "peer-a"}, now)

	actions, err := s.OnEvent(&ObjectPullResultEvent{
		PeerID:   "peer-a",
		Zone:     "node-a.catofes.",
		Snapshot: &gossip.ZoneSnapshot{Zone: "node-a.catofes."},
	}, now)
	if err != nil {
		t.Fatalf("OnEvent error: %v", err)
	}
	if s.State != SyncSessionCompleted {
		t.Fatalf("expected state completed, got %s", s.State)
	}
	assertActionTypes(t, actions, []string{"ApplySnapshotAction", "SaveStateAction"})
}

func TestSyncSessionObjectPullErrorFallsBackToChunk(t *testing.T) {
	s := NewSyncSession("peer-a")
	now := time.Unix(1000, 0)

	_, _ = s.OnEvent(&SyncTimerEvent{PeerID: "peer-a", LocalDigests: nil}, now)
	_, _ = s.OnEvent(&PongReceivedEvent{
		PeerID:       "peer-a",
		Pong:         &gossip.Pong{},
		MissingZones: []zone.ZonePath{"node-a.catofes."},
	}, now)
	_, _ = s.OnEvent(&PacketQuietTimeoutEvent{PeerID: "peer-a"}, now)

	actions, err := s.OnEvent(&ObjectPullResultEvent{
		PeerID: "peer-a",
		Zone:   "node-a.catofes.",
		Err:    errors.New("tcp unreachable"),
	}, now)
	if err != nil {
		t.Fatalf("OnEvent error: %v", err)
	}
	if s.State != SyncSessionChunkFallback {
		t.Fatalf("expected state chunk_fallback, got %s", s.State)
	}
	assertActionTypes(t, actions, []string{"SendFetchZoneAction"})
	fz := actions[0].(SendFetchZoneAction)
	if !fz.ChunkFallback || fz.Zone != "node-a.catofes." {
		t.Fatalf("unexpected fetch zone action: %+v", fz)
	}
}

func TestSyncSessionChunkComplete(t *testing.T) {
	s := NewSyncSession("peer-a")
	now := time.Unix(1000, 0)

	_, _ = s.OnEvent(&SyncTimerEvent{PeerID: "peer-a", LocalDigests: nil}, now)
	_, _ = s.OnEvent(&PongReceivedEvent{
		PeerID:       "peer-a",
		Pong:         &gossip.Pong{},
		MissingZones: []zone.ZonePath{"node-a.catofes."},
	}, now)
	_, _ = s.OnEvent(&PacketQuietTimeoutEvent{PeerID: "peer-a"}, now)
	_, _ = s.OnEvent(&ObjectPullResultEvent{PeerID: "peer-a", Zone: "node-a.catofes.", Err: errors.New("tcp unreachable")}, now)

	actions, err := s.OnEvent(&ObjectChunkEvent{
		PeerID:   "peer-a",
		Zone:     "node-a.catofes.",
		Snapshot: &gossip.ZoneSnapshot{Zone: "node-a.catofes."},
	}, now)
	if err != nil {
		t.Fatalf("OnEvent error: %v", err)
	}
	if s.State != SyncSessionCompleted {
		t.Fatalf("expected state completed, got %s", s.State)
	}
	assertActionTypes(t, actions, []string{"ApplySnapshotAction", "SaveStateAction"})
}

func TestChunkFallbackFetchDoesNotStartEagerObjectPull(t *testing.T) {
	s := NewSyncSession("peer-a")
	s.objectPullInflight = make(map[zone.ZonePath]bool)

	action := SendFetchZoneAction{
		PeerID:        "peer-a",
		Zone:          "node-a.catofes.",
		ChunkFallback: true,
	}

	if shouldStartEagerObjectPull(action, s, "local.catofes.", nil, 1200) {
		t.Fatalf("chunk fallback fetch should not start another eager object pull")
	}
}

func TestSyncSessionFetchingLocalCompletesOnQuietTimeout(t *testing.T) {
	s := NewSyncSession("peer-a")
	now := time.Unix(1000, 0)
	local := []gossip.ZoneDigest{{Zone: "catofes.", RootHash: []byte("h1")}}
	snap := &gossip.ZoneSnapshot{Zone: "catofes."}

	_, _ = s.OnEvent(&SyncTimerEvent{PeerID: "peer-a", LocalDigests: local}, now)
	now = now.Add(10 * time.Millisecond)

	_, _ = s.OnEvent(&PongReceivedEvent{
		PeerID:         "peer-a",
		Pong:           &gossip.Pong{Zones: local, FetchZones: []zone.ZonePath{"catofes."}},
		MissingZones:   nil,
		LocalSnapshots: []*gossip.ZoneSnapshot{snap},
	}, now)
	if s.State != SyncSessionFetchingLocal {
		t.Fatalf("expected state fetching_local, got %s", s.State)
	}

	actions, err := s.OnEvent(&PacketQuietTimeoutEvent{PeerID: "peer-a"}, now)
	if err != nil {
		t.Fatalf("OnEvent error: %v", err)
	}
	if s.State != SyncSessionCompleted {
		t.Fatalf("expected state completed, got %s", s.State)
	}
	assertActionTypes(t, actions, []string{"SaveStateAction"})
}

func TestSyncSessionRoundTimeout(t *testing.T) {
	s := NewSyncSession("peer-a")
	now := time.Unix(1000, 0)

	_, _ = s.OnEvent(&SyncTimerEvent{PeerID: "peer-a", LocalDigests: nil}, now)
	actions, err := s.OnEvent(&RoundTimeoutEvent{PeerID: "peer-a"}, now)
	if err != nil {
		t.Fatalf("OnEvent error: %v", err)
	}
	if s.State != SyncSessionFailed {
		t.Fatalf("expected state failed, got %s", s.State)
	}
	assertActionTypes(t, actions, []string{"RecordBackoffAction", "SaveStateAction", "CancelTimerAction"})
}

func TestSyncSessionRTTAwareTimeouts(t *testing.T) {
	s := NewSyncSession("peer-a")
	now := time.Unix(1000, 0)

	_, _ = s.OnEvent(&SyncTimerEvent{PeerID: "peer-a", LocalDigests: nil}, now)
	// Simulate a 600ms RTT.
	_, _ = s.OnEvent(&PongReceivedEvent{PeerID: "peer-a", Pong: &gossip.Pong{}}, now.Add(600*time.Millisecond))

	quiet := s.packetQuietTimeout()
	expectedMin := time.Duration(kQuietMultiplier) * 600 * time.Millisecond
	if quiet < expectedMin {
		t.Fatalf("quiet timeout %v should be >= %v", quiet, expectedMin)
	}
	if quiet < MinPacketQuietTimeout {
		t.Fatalf("quiet timeout %v should respect min %v", quiet, MinPacketQuietTimeout)
	}

	round := s.roundTimeout()
	expectedRoundMin := time.Duration(kRoundMultiplier)*600*time.Millisecond + ObjectPullBudget
	if round < expectedRoundMin {
		t.Fatalf("round timeout %v should be >= %v", round, expectedRoundMin)
	}
	if round < MinRoundTimeout {
		t.Fatalf("round timeout %v should respect min %v", round, MinRoundTimeout)
	}
}

func TestSyncSessionDone(t *testing.T) {
	s := NewSyncSession("peer-a")
	if s.Done() {
		t.Fatal("new session should not be done")
	}
	_, _ = s.OnEvent(&SyncTimerEvent{PeerID: "peer-a"}, time.Unix(1000, 0))
	_, _ = s.OnEvent(&RoundTimeoutEvent{PeerID: "peer-a"}, time.Unix(1000, 0))
	if !s.Done() {
		t.Fatal("failed session should be done")
	}
}

func assertActionTypes(t *testing.T, actions []SyncAction, want []string) {
	t.Helper()
	if len(actions) != len(want) {
		t.Fatalf("expected %d actions (%v), got %d (%v)", len(want), want, len(actions), actionTypes(actions))
	}
	for i, a := range actions {
		got := actionType(a)
		if got != want[i] {
			t.Fatalf("action %d: expected %s, got %s", i, want[i], got)
		}
	}
}

func TestSyncSessionAnnounceAcceptsSkeletonAndStaysPending(t *testing.T) {
	s := NewSyncSession("peer-a")
	now := time.Unix(1000, 0)

	_, _ = s.OnEvent(&SyncTimerEvent{PeerID: "peer-a", LocalDigests: nil}, now)
	_, _ = s.OnEvent(&PongReceivedEvent{
		PeerID:       "peer-a",
		Pong:         &gossip.Pong{},
		MissingZones: []zone.ZonePath{"node-a.catofes."},
	}, now)

	authority := &zone.ZoneAuthority{
		Zone:      "node-a.catofes.",
		Epoch:     1,
		Keys:      []zone.AuthorizedKey{{Key: make([]byte, 32)}},
		Threshold: 1,
	}

	// Advertised digest includes records, so a skeleton (authority only) will not
	// match it.
	fullZS := zone.NewZoneState("node-a.catofes.", authority)
	fullZS.Records["identity"] = &zone.Record{Key: "identity", Value: []byte("node-a")}
	s.expectedDigests["node-a.catofes."] = gossip.ZoneDigest{
		Zone:     "node-a.catofes.",
		RootHash: gossip.ZoneRoot(fullZS),
	}

	skeleton := &gossip.ZoneSnapshot{
		Zone:      "node-a.catofes.",
		Authority: authority,
	}

	actions, err := s.OnEvent(&AnnounceReceivedEvent{
		PeerID: "peer-a",
		Announce: &gossip.Announce{
			Snapshots: []gossip.ZoneSnapshot{*skeleton},
		},
	}, now)
	if err != nil {
		t.Fatalf("OnEvent error: %v", err)
	}
	if s.State != SyncSessionAwaitingAnnounce {
		t.Fatalf("expected state awaiting_announce, got %s", s.State)
	}
	if _, ok := s.pendingZones["node-a.catofes."]; !ok {
		t.Fatalf("expected node-a.catofes. to remain pending after skeleton")
	}
	if _, ok := s.expectedDigests["node-a.catofes."]; !ok {
		t.Fatalf("expected node-a.catofes. expected digest to remain after skeleton")
	}
	assertActionTypes(t, actions, []string{"ApplySnapshotAction"})
}

func actionType(a SyncAction) string {
	switch a.(type) {
	case SendPingAction:
		return "SendPingAction"
	case SendPongAction:
		return "SendPongAction"
	case SendFetchZoneAction:
		return "SendFetchZoneAction"
	case SendAnnounceAction:
		return "SendAnnounceAction"
	case StartObjectPullAction:
		return "StartObjectPullAction"
	case ApplySnapshotAction:
		return "ApplySnapshotAction"
	case ApplyRecordSnapshotAction:
		return "ApplyRecordSnapshotAction"
	case SaveStateAction:
		return "SaveStateAction"
	case RecordBackoffAction:
		return "RecordBackoffAction"
	case StartTimerAction:
		return "StartTimerAction"
	case CancelTimerAction:
		return "CancelTimerAction"
	default:
		return "unknown"
	}
}

func actionTypes(actions []SyncAction) []string {
	out := make([]string, len(actions))
	for i, a := range actions {
		out[i] = actionType(a)
	}
	return out
}
