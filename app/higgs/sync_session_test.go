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
	if s.State != SyncSessionSummarySent {
		t.Fatalf("expected state summary_sent, got %s", s.State)
	}

	assertActionTypes(t, actions, []string{"SendPingAction", "StartTimerAction"})

	ping := actions[0].(SendPingAction)
	if len(ping.Digests) != 1 || ping.Digests[0].Zone != "catofes." {
		t.Fatalf("unexpected ping digests: %+v", ping.Digests)
	}

	round := actions[1].(StartTimerAction)
	if round.Kind != "round" {
		t.Fatalf("expected round timer, got %s", round.Kind)
	}
	if !round.Deadline.After(now) {
		t.Fatalf("round deadline %v should be after now %v", round.Deadline, now)
	}
}

func TestSyncSessionPongNoDifferences(t *testing.T) {
	s := NewSyncSession("peer-a")
	now := time.Unix(1000, 0)
	digests := []gossip.ZoneDigest{{Zone: "catofes.", RootHash: []byte("h1")}}

	_, _ = s.OnEvent(&SyncTimerEvent{PeerID: "peer-a", LocalDigests: digests}, now)
	now = now.Add(100 * time.Millisecond)

	actions, err := s.OnEvent(&PongReceivedEvent{
		PeerID:       "peer-a",
		Pong:         &gossip.Pong{},
		MissingZones: nil,
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

	_, _ = s.OnEvent(&SyncTimerEvent{PeerID: "peer-a", LocalDigests: local}, now)
	now = now.Add(50 * time.Millisecond)

	actions, err := s.OnEvent(&PongReceivedEvent{
		PeerID:       "peer-a",
		Pong:         &gossip.Pong{},
		MissingZones: []zone.ZonePath{"node-a.catofes."},
	}, now)
	if err != nil {
		t.Fatalf("OnEvent error: %v", err)
	}
	if s.State != SyncSessionObjectPulling {
		t.Fatalf("expected state object_pulling, got %s", s.State)
	}
	assertActionTypes(t, actions, []string{"StartObjectPullAction"})
	// Initial RTT is 1s; a 50ms sample should pull the estimate down toward the sample.
	if s.EstimatedRTT() >= InitialRTT {
		t.Fatalf("expected RTT estimate to decrease from initial %v, got %v", InitialRTT, s.EstimatedRTT())
	}
	if s.EstimatedRTT() <= 50*time.Millisecond {
		t.Fatalf("expected RTT estimate to remain above sample 50ms after one EWMA step, got %v", s.EstimatedRTT())
	}
}

func TestSyncSessionCatalogSummaryFetchesPages(t *testing.T) {
	s := NewSyncSession("peer-a")
	now := time.Unix(1000, 0)
	localRoot := gossip.CatalogRoot([]gossip.ZoneDigest{{Zone: "catofes.", RootHash: []byte("local")}})
	remoteRoot := gossip.CatalogRoot([]gossip.ZoneDigest{{Zone: "node-a.catofes.", RootHash: []byte("remote")}})

	_, _ = s.OnEvent(&SyncTimerEvent{
		PeerID:       "peer-a",
		LocalSummary: &gossip.CatalogSummary{CatalogRoot: localRoot, ZoneCount: 1},
	}, now)
	actions, err := s.OnEvent(&PongReceivedEvent{
		PeerID: "peer-a",
		Pong:   &gossip.Pong{Summary: &gossip.CatalogSummary{CatalogRoot: remoteRoot, ZoneCount: 1}},
	}, now.Add(10*time.Millisecond))
	if err != nil {
		t.Fatalf("OnEvent error: %v", err)
	}
	if s.State != SyncSessionCatalogDiffing {
		t.Fatalf("expected state catalog_diffing, got %s", s.State)
	}
	assertActionTypes(t, actions, []string{"SendFetchCatalogPageAction", "StartTimerAction"})
}

func TestSyncSessionResponderPacketsDoNotEnterActivePullFSM(t *testing.T) {
	s := NewSyncSession("peer-a")
	now := time.Unix(1000, 0)
	localRoot := gossip.CatalogRoot([]gossip.ZoneDigest{{Zone: "catofes.", RootHash: []byte("local")}})
	remoteRoot := gossip.CatalogRoot([]gossip.ZoneDigest{{Zone: "node-a.catofes.", RootHash: []byte("remote")}})

	_, _ = s.OnEvent(&SyncTimerEvent{
		PeerID:       "peer-a",
		LocalSummary: &gossip.CatalogSummary{CatalogRoot: localRoot, ZoneCount: 1},
	}, now)
	if s.State != SyncSessionSummarySent {
		t.Fatalf("expected state summary_sent, got %s", s.State)
	}

	actions, err := s.OnEvent(&PacketEvent{}, now.Add(5*time.Millisecond))
	if err == nil {
		t.Fatal("PacketEvent unexpectedly entered SyncSession")
	}
	if s.State != SyncSessionSummarySent {
		t.Fatalf("responder packet changed active pull state to %s", s.State)
	}
	if len(actions) != 0 {
		t.Fatalf("responder packet returned actions: %+v", actions)
	}

	actions, err = s.OnEvent(&PongReceivedEvent{
		PeerID: "peer-a",
		Pong:   &gossip.Pong{Summary: &gossip.CatalogSummary{CatalogRoot: remoteRoot, ZoneCount: 1}},
	}, now.Add(10*time.Millisecond))
	if err != nil {
		t.Fatalf("OnEvent(pong): %v", err)
	}
	if s.State != SyncSessionCatalogDiffing {
		t.Fatalf("expected pong to continue active pull into catalog_diffing, got %s", s.State)
	}
	assertActionTypes(t, actions, []string{"SendFetchCatalogPageAction", "StartTimerAction"})
}

func TestSyncSessionCatalogPageStartsObjectPull(t *testing.T) {
	s := NewSyncSession("peer-a")
	now := time.Unix(1000, 0)
	local := []gossip.ZoneDigest{{Zone: "catofes.", RootHash: []byte("local")}}
	remote := []gossip.ZoneDigest{{Zone: "catofes.", RootHash: []byte("remote")}}
	root := gossip.CatalogRoot(remote)

	_, _ = s.OnEvent(&SyncTimerEvent{
		PeerID:       "peer-a",
		LocalSummary: &gossip.CatalogSummary{CatalogRoot: gossip.CatalogRoot(local), ZoneCount: 1},
	}, now)
	_, _ = s.OnEvent(&PongReceivedEvent{
		PeerID: "peer-a",
		Pong:   &gossip.Pong{Summary: &gossip.CatalogSummary{CatalogRoot: root, ZoneCount: 1}},
	}, now.Add(10*time.Millisecond))

	actions, err := s.OnEvent(&CatalogPageReceivedEvent{
		PeerID:       "peer-a",
		Page:         &gossip.CatalogPage{CatalogRoot: root, Entries: remote},
		LocalEntries: local,
	}, now.Add(20*time.Millisecond))
	if err != nil {
		t.Fatalf("OnEvent error: %v", err)
	}
	if s.State != SyncSessionObjectPulling {
		t.Fatalf("expected state object_pulling, got %s", s.State)
	}
	assertActionTypes(t, actions, []string{"StartObjectPullAction"})
	if !s.pendingZones["catofes."] || !s.objectPullInflight["catofes."] {
		t.Fatalf("catalog diff did not mark zone pending/inflight")
	}
}

func TestSyncSessionCatalogPageRejectsRootMismatch(t *testing.T) {
	s := NewSyncSession("peer-a")
	now := time.Unix(1000, 0)
	local := []gossip.ZoneDigest{{Zone: "catofes.", RootHash: []byte("local")}}
	remote := []gossip.ZoneDigest{{Zone: "catofes.", RootHash: []byte("remote")}}
	root := gossip.CatalogRoot(remote)

	_, _ = s.OnEvent(&SyncTimerEvent{
		PeerID:       "peer-a",
		LocalSummary: &gossip.CatalogSummary{CatalogRoot: gossip.CatalogRoot(local), ZoneCount: 1},
	}, now)
	_, _ = s.OnEvent(&PongReceivedEvent{
		PeerID: "peer-a",
		Pong:   &gossip.Pong{Summary: &gossip.CatalogSummary{CatalogRoot: root, ZoneCount: 1}},
	}, now.Add(10*time.Millisecond))

	actions, err := s.OnEvent(&CatalogPageReceivedEvent{
		PeerID:       "peer-a",
		Page:         &gossip.CatalogPage{CatalogRoot: []byte("wrong-root"), Entries: remote},
		LocalEntries: local,
	}, now.Add(20*time.Millisecond))
	if err != nil {
		t.Fatalf("OnEvent error: %v", err)
	}
	if s.State != SyncSessionFailed {
		t.Fatalf("expected state failed, got %s", s.State)
	}
	assertActionTypes(t, actions, []string{"RecordBackoffAction", "SaveStateAction"})
}

func TestSyncSessionCatalogPageBeforeTimerDoesNotPanic(t *testing.T) {
	s := NewSyncSession("peer-a")
	now := time.Unix(1000, 0)
	local := []gossip.ZoneDigest{{Zone: "catofes.", RootHash: []byte("local")}}
	remote := []gossip.ZoneDigest{{Zone: "catofes.", RootHash: []byte("remote")}}
	root := gossip.CatalogRoot(remote)

	// A catalog page may arrive for a freshly created session before the
	// SyncTimerEvent has been processed (e.g. the timer event was dropped
	// because the event channel was full). The session must not panic.
	actions, err := s.OnEvent(&CatalogPageReceivedEvent{
		PeerID:       "peer-a",
		Page:         &gossip.CatalogPage{CatalogRoot: root, Entries: remote},
		LocalEntries: local,
	}, now)
	if err != nil {
		t.Fatalf("OnEvent error: %v", err)
	}
	if s.State != SyncSessionObjectPulling {
		t.Fatalf("expected state object_pulling, got %s", s.State)
	}
	assertActionTypes(t, actions, []string{"StartObjectPullAction"})
}

func TestSyncSessionPongMissingZonesStartsObjectPull(t *testing.T) {
	s := NewSyncSession("peer-a")
	now := time.Unix(1000, 0)

	_, _ = s.OnEvent(&SyncTimerEvent{PeerID: "peer-a", LocalDigests: nil}, now)
	actions, err := s.OnEvent(&PongReceivedEvent{
		PeerID:       "peer-a",
		Pong:         &gossip.Pong{},
		MissingZones: []zone.ZonePath{"node-a.catofes.", "node-b.catofes."},
	}, now)
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

	catalogPage := s.catalogPageTimeout()
	expectedMin := time.Duration(kCatalogPageTimeoutMultiplier) * 600 * time.Millisecond
	if catalogPage < expectedMin {
		t.Fatalf("catalog page timeout %v should be >= %v", catalogPage, expectedMin)
	}
	if catalogPage < MinCatalogPageTimeout {
		t.Fatalf("catalog page timeout %v should respect min %v", catalogPage, MinCatalogPageTimeout)
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

func actionType(a SyncAction) string {
	switch a.(type) {
	case SendPingAction:
		return "SendPingAction"
	case SendFetchZoneAction:
		return "SendFetchZoneAction"
	case SendFetchCatalogPageAction:
		return "SendFetchCatalogPageAction"
	case SendCatalogPageAction:
		return "SendCatalogPageAction"
	case StartObjectPullAction:
		return "StartObjectPullAction"
	case ApplySnapshotAction:
		return "ApplySnapshotAction"
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
