package main

import (
	"bytes"
	"context"
	"github.com/HiggsNet/photon/pkg/core/gossip"
	"path/filepath"
	"testing"
	"time"
)

func TestDaemonEventLoopSyncSession(t *testing.T) {
	stateA, configA, stateB, configB := buildTestABDaemonStates(t)
	now := time.Now()

	recordA, err := buildSignedRecordAt(stateA, "node-a.catofes.", "event-loop-test", []byte("from-a"), "policy.string", now)
	if err != nil {
		t.Fatalf("build record for A: %v", err)
	}
	if err := stateA.Network.Put(recordA); err != nil {
		t.Fatalf("put record on A: %v", err)
	}
	recordB, err := buildSignedRecordAt(stateB, "node-b.catofes.", "event-loop-test", []byte("from-b"), "policy.string", now)
	if err != nil {
		t.Fatalf("build record for B: %v", err)
	}
	if err := stateB.Network.Put(recordB); err != nil {
		t.Fatalf("put record on B: %v", err)
	}

	transportA, err := gossip.Listen(gossip.Config{PeerID: configA.PeerID, ListenAddr: configA.ListenAddr})
	if err != nil {
		t.Fatalf("Listen(A): %v", err)
	}
	defer transportA.Close()
	transportB, err := gossip.Listen(gossip.Config{PeerID: configB.PeerID, ListenAddr: configB.ListenAddr})
	if err != nil {
		t.Fatalf("Listen(B): %v", err)
	}
	defer transportB.Close()
	transportA.AddPeer(configB.PeerID, transportB.LocalAddr())
	transportB.AddPeer(configA.PeerID, transportA.LocalAddr())
	configA.ListenAddr = transportA.LocalAddr().String()
	configB.ListenAddr = transportB.LocalAddr().String()
	configA.Bootstrap = []syncConfigPeer{{ID: configB.PeerID, Addr: transportB.LocalAddr().String()}}
	configB.Bootstrap = []syncConfigPeer{{ID: configA.PeerID, Addr: transportA.LocalAddr().String()}}

	rtA := &Runtime{
		Config:    defaultAppConfig(),
		StatePath: filepath.Join(t.TempDir(), "node-a.db"),
		Clock:     func() time.Time { return now },
	}
	rtB := &Runtime{
		Config:    defaultAppConfig(),
		StatePath: filepath.Join(t.TempDir(), "node-b.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rtA.SaveState(stateA); err != nil {
		t.Fatalf("SaveState(A): %v", err)
	}
	if err := rtB.SaveState(stateB); err != nil {
		t.Fatalf("SaveState(B): %v", err)
	}

	serviceA := newDaemonService(rtA, stateA, configA, time.Second)
	serviceA.Sync.Transport = transportA
	serviceB := newDaemonService(rtB, stateB, configB, time.Second)
	serviceB.Sync.Transport = transportB

	fc := newFakeClock(now)
	serviceA.EnableEventLoopSync(fc)
	serviceB.EnableEventLoopSync(fc)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	listenerA, err := startObjectPullServer(serviceA)
	if err != nil {
		t.Fatalf("startObjectPullServer(A): %v", err)
	}
	if listenerA != nil {
		defer listenerA.Close()
	}
	listenerB, err := startObjectPullServer(serviceB)
	if err != nil {
		t.Fatalf("startObjectPullServer(B): %v", err)
	}
	if listenerB != nil {
		defer listenerB.Close()
	}
	serviceA.objectPullPool.Start(ctx)
	defer serviceA.objectPullPool.Stop()
	serviceB.objectPullPool.Start(ctx)
	defer serviceB.objectPullPool.Stop()

	// Start sessions in both directions through the event-loop timer handler.
	if err := serviceA.handleSyncTimerEvent(ctx, true); err != nil {
		t.Fatalf("handleSyncTimerEvent(A): %v", err)
	}
	if err := serviceB.handleSyncTimerEvent(ctx, true); err != nil {
		t.Fatalf("handleSyncTimerEvent(B): %v", err)
	}

	// Pump events, then advance the fake clock to fire any pending timers.
	// Repeat until all sessions have completed.
	for {
		pumpEventLoopSync(ctx, []*DaemonService{serviceA, serviceB}, []*gossip.Transport{transportA, transportB})
		aActive := false
		if s := serviceA.hostRuntime.Gossip.Session(configB.PeerID); s != nil && !s.Done() {
			aActive = true
		}
		bActive := false
		if s := serviceB.hostRuntime.Gossip.Session(configA.PeerID); s != nil && !s.Done() {
			bActive = true
		}
		if !aActive && !bActive {
			break
		}
		fc.Advance(5 * time.Second)
	}

	if serviceA.hostRuntime.Gossip.Session(configB.PeerID) != nil {
		t.Fatalf("session for B still active on A")
	}
	if serviceB.hostRuntime.Gossip.Session(configA.PeerID) != nil {
		t.Fatalf("session for A still active on B")
	}

	latestA, err := rtA.LoadState()
	if err != nil {
		t.Fatalf("LoadState(A): %v", err)
	}
	latestB, err := rtB.LoadState()
	if err != nil {
		t.Fatalf("LoadState(B): %v", err)
	}
	if latestA.Network.Zones["node-b.catofes."] == nil || latestA.Network.Zones["node-b.catofes."].Records["event-loop-test"] == nil {
		t.Fatalf("record from B did not appear on A")
	}
	if latestB.Network.Zones["node-a.catofes."] == nil || latestB.Network.Zones["node-a.catofes."].Records["event-loop-test"] == nil {
		t.Fatalf("record from A did not appear on B")
	}
}

func TestDaemonEventLoopResponderDoesNotStealActiveSession(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(1000, 0)
	rt := &Runtime{
		Config:    defaultAppConfig(),
		StatePath: filepath.Join(t.TempDir(), "state.db"),
		Clock:     func() time.Time { return now },
	}
	service := newDaemonService(rt, state, config, time.Second)
	service.EnableEventLoopSync(newFakeClock(now))

	peerID := "peer-a"
	session := gossip.NewSyncSession(peerID)
	_, _ = session.OnEvent(&gossip.SyncTimerEvent{
		PeerID:       peerID,
		LocalSummary: &gossip.CatalogSummary{CatalogRoot: gossip.CatalogRoot(nil), ZoneCount: 0},
	}, now)
	if session.State != gossip.SyncSessionSummarySent {
		t.Fatalf("expected setup state summary_sent, got %s", session.State)
	}
	service.hostRuntime.Gossip.SetSession(peerID, session)

	before := service.StateStore.Meta().Revision
	err := service.processPacketEvent(&gossip.Packet{Message: &gossip.Message{
		Type:             gossip.MessageFetchCatalogPage,
		PeerID:           peerID,
		FetchCatalogPage: &gossip.FetchCatalogPage{},
	}}, context.Background())
	if err != nil {
		t.Fatalf("process fetch catalog page: %v", err)
	}
	if session.State != gossip.SyncSessionSummarySent {
		t.Fatalf("fetch catalog page changed active session state to %s", session.State)
	}
	if got := service.hostRuntime.PendingEventCount(); got != 0 {
		t.Fatalf("fetch catalog page queued %d sync events, want none", got)
	}
	if after := service.StateStore.Meta().Revision; after != before+1 {
		t.Fatalf("fetch catalog page state revision = %d, want one packet commit after %d", after, before)
	}

	before = service.StateStore.Meta().Revision
	err = service.processPacketEvent(&gossip.Packet{Message: &gossip.Message{
		Type:      gossip.MessageFetchZone,
		PeerID:    peerID,
		FetchZone: &gossip.FetchZone{Zone: "catofes."},
	}}, context.Background())
	if err != nil {
		t.Fatalf("process fetch zone: %v", err)
	}
	if session.State != gossip.SyncSessionSummarySent {
		t.Fatalf("fetch zone changed active session state to %s", session.State)
	}
	if got := service.hostRuntime.PendingEventCount(); got != 0 {
		t.Fatalf("fetch zone queued %d sync events, want none", got)
	}
	if after := service.StateStore.Meta().Revision; after != before+1 {
		t.Fatalf("fetch zone state revision = %d, want one packet commit after %d", after, before)
	}
}

func TestDaemonEventLoopAnnounceIsHint(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(1000, 0)
	rt := &Runtime{
		Config:    defaultAppConfig(),
		StatePath: filepath.Join(t.TempDir(), "state.db"),
		Clock:     func() time.Time { return now },
	}
	service := newDaemonService(rt, state, config, time.Second)
	service.EnableEventLoopSync(newFakeClock(now))

	beforeRoot := append([]byte(nil), gossip.ZoneRoot(state.Network.Zones["node-b.catofes."])...)
	err := service.processPacketEvent(&gossip.Packet{Message: &gossip.Message{
		Type:     gossip.MessageAnnounce,
		PeerID:   "peer-a",
		Announce: &gossip.Announce{Zones: []gossip.ZoneDigest{{Zone: "node-b.catofes.", RootHash: []byte("remote-root")}}},
	}}, context.Background())
	if err != nil {
		t.Fatalf("process announce: %v", err)
	}
	if afterRoot := gossip.ZoneRoot(state.Network.Zones["node-b.catofes."]); !bytes.Equal(afterRoot, beforeRoot) {
		t.Fatal("announce changed zone state directly; want hint-only ingress")
	}
	session := service.hostRuntime.Gossip.Session("peer-a")
	if session == nil || session.State != gossip.SyncSessionIdle {
		t.Fatalf("announce hint session = %+v, want idle session queued for active pull", session)
	}
	if got := service.hostRuntime.PendingEventCount(); got != 1 {
		t.Fatalf("announce hint queued %d events, want one sync timer", got)
	}
	ev, ok := service.hostRuntime.GossipEventFor(<-service.hostRuntime.Events())
	if !ok {
		t.Fatal("announce hint did not produce a gossip event")
	}
	timer, ok := ev.(*gossip.SyncTimerEvent)
	if !ok {
		t.Fatalf("announce hint event = %T, want gossip.SyncTimerEvent", ev)
	}
	if timer.PeerID != "peer-a" || timer.LocalSummary == nil {
		t.Fatalf("announce hint timer = %+v, want peer-a with local summary", timer)
	}
}

func TestDaemonUnsolicitedPingSummaryMatchSkipsSession(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(1000, 0)
	rt := &Runtime{
		Config:    defaultAppConfig(),
		StatePath: filepath.Join(t.TempDir(), "state.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	service := newDaemonService(rt, state, config, time.Second)
	service.EnableEventLoopSync(newFakeClock(now))

	peerID := "peer-a"
	localSummary, err := gossip.CatalogSummaryFor(state.Network, service.syncDatagramBudget())
	if err != nil {
		t.Fatalf("CatalogSummaryFor: %v", err)
	}

	err = service.processPacketEvent(&gossip.Packet{Message: &gossip.Message{
		Type:   gossip.MessagePing,
		PeerID: peerID,
		Ping:   &gossip.Ping{Summary: localSummary},
	}}, context.Background())
	if err != nil {
		t.Fatalf("process ping: %v", err)
	}

	if session := service.hostRuntime.Gossip.Session(peerID); session != nil {
		t.Fatalf("expected no session for matching summary, got %+v", session)
	}
	if got := service.hostRuntime.PendingEventCount(); got != 0 {
		t.Fatalf("expected no sync events, got %d", got)
	}

	snapshot, _ := service.StateStore.Snapshot()
	peerState := snapshot.SyncPeers[peerID]
	if peerState.LastSyncUnix != now.Unix() {
		t.Fatalf("LastSyncUnix = %d, want %d", peerState.LastSyncUnix, now.Unix())
	}
	if peerState.LastHintReason != "ping_summary_match" {
		t.Fatalf("LastHintReason = %q, want ping_summary_match", peerState.LastHintReason)
	}
	if peerState.BackoffUntilUnix != 0 {
		t.Fatalf("BackoffUntilUnix = %d, want 0", peerState.BackoffUntilUnix)
	}
}

func TestDaemonPingSummaryShortcutCommitsPeerChangesOnce(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(1000, 0)
	service := newDaemonService(&Runtime{
		Config: defaultAppConfig(),
		Clock:  func() time.Time { return now },
	}, state, config, time.Second)

	summary, err := gossip.CatalogSummaryFor(state.Network, service.syncDatagramBudget())
	if err != nil {
		t.Fatalf("CatalogSummaryFor: %v", err)
	}
	localSummary, err := service.StateStore.catalogSummaryProjection(service.syncDatagramBudget())
	if err != nil {
		t.Fatalf("catalogSummaryProjection: %v", err)
	}
	before := service.StateStore.Meta().Revision
	if err := service.maybeShortcutSyncFromPingSummaryWithLocal("peer-a", summary, localSummary); err != nil {
		t.Fatalf("maybeShortcutSyncFromPingSummaryWithLocal: %v", err)
	}
	after := service.StateStore.Meta().Revision
	if after != before+1 {
		t.Fatalf("state revision = %d, want one commit after %d", after, before)
	}
}

func TestDaemonHintedSessionCommitsPeerChangesOnce(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(1000, 0)
	service := newDaemonService(&Runtime{
		Config: defaultAppConfig(),
		Clock:  func() time.Time { return now },
	}, state, config, time.Second)

	before := service.StateStore.Meta().Revision
	if err := service.startHintedSyncSession("peer-a", "test_hint"); err != nil {
		t.Fatalf("startHintedSyncSession: %v", err)
	}
	after := service.StateStore.Meta().Revision
	if after != before+1 {
		t.Fatalf("state revision = %d, want one commit after %d", after, before)
	}
	snapshot, _ := service.StateStore.Snapshot()
	peerState := snapshot.SyncPeers["peer-a"]
	if peerState.LastHintReason != "test_hint" || peerState.ActivePullLastEvent != "hint_queued" {
		t.Fatalf("peer state = %+v, want hint and active-pull changes", peerState)
	}
}

func TestDaemonSyncEventBatchesActiveBackoffAndCompletion(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(1000, 0)
	rt := &Runtime{
		Config:    defaultAppConfig(),
		StatePath: filepath.Join(t.TempDir(), "state.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	service := newDaemonService(rt, state, config, time.Second)
	service.EnableEventLoopSync(newFakeClock(now))

	peerID := "peer-a"
	session := gossip.NewSyncSession(peerID)
	if _, err := session.OnEvent(&gossip.SyncTimerEvent{
		PeerID:       peerID,
		LocalSummary: &gossip.CatalogSummary{CatalogRoot: []byte("local"), ZoneCount: 1},
	}, now); err != nil {
		t.Fatalf("start sync session: %v", err)
	}
	service.hostRuntime.Gossip.SetSession(peerID, session)

	before := service.StateStore.Meta().Revision
	service.handleSyncEvent(context.Background(), &gossip.RoundTimeoutEvent{PeerID: peerID})
	after := service.StateStore.Meta().Revision
	if after != before+1 {
		t.Fatalf("state revision = %d, want one event commit after %d", after, before)
	}
	snapshot, _ := service.StateStore.Snapshot()
	peerState := snapshot.SyncPeers[peerID]
	if peerState.ActivePullLastEvent != "round_timeout" || peerState.FailureCount != 1 || peerState.LastError != "round timeout" {
		t.Fatalf("peer state = %+v, want active-pull, backoff, and completion changes", peerState)
	}
}

func TestDaemonUnsolicitedPingSummaryMismatchStartsSession(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(1000, 0)
	rt := &Runtime{
		Config:    defaultAppConfig(),
		StatePath: filepath.Join(t.TempDir(), "state.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	service := newDaemonService(rt, state, config, time.Second)
	service.EnableEventLoopSync(newFakeClock(now))

	peerID := "peer-a"
	err := service.processPacketEvent(&gossip.Packet{Message: &gossip.Message{
		Type:   gossip.MessagePing,
		PeerID: peerID,
		Ping:   &gossip.Ping{Summary: &gossip.CatalogSummary{CatalogRoot: []byte("mismatch"), ZoneCount: 99}},
	}}, context.Background())
	if err != nil {
		t.Fatalf("process ping: %v", err)
	}

	if session := service.hostRuntime.Gossip.Session(peerID); session == nil || session.State != gossip.SyncSessionIdle {
		t.Fatalf("expected idle session for mismatched summary, got %+v", session)
	}
	if got := service.hostRuntime.PendingEventCount(); got != 1 {
		t.Fatalf("expected one sync timer event, got %d", got)
	}
}

func TestDaemonEventLoopAnnounceDoesNotStealActiveSession(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(1000, 0)
	rt := &Runtime{
		Config:    defaultAppConfig(),
		StatePath: filepath.Join(t.TempDir(), "state.db"),
		Clock:     func() time.Time { return now },
	}
	service := newDaemonService(rt, state, config, time.Second)
	service.EnableEventLoopSync(newFakeClock(now))

	peerID := "peer-a"
	session := gossip.NewSyncSession(peerID)
	_, _ = session.OnEvent(&gossip.SyncTimerEvent{
		PeerID:       peerID,
		LocalSummary: &gossip.CatalogSummary{CatalogRoot: gossip.CatalogRoot(nil), ZoneCount: 0},
	}, now)
	if session.State != gossip.SyncSessionSummarySent {
		t.Fatalf("expected setup state summary_sent, got %s", session.State)
	}
	service.hostRuntime.Gossip.SetSession(peerID, session)

	err := service.processPacketEvent(&gossip.Packet{Message: &gossip.Message{
		Type:     gossip.MessageAnnounce,
		PeerID:   peerID,
		Announce: &gossip.Announce{},
	}}, context.Background())
	if err != nil {
		t.Fatalf("process announce: %v", err)
	}
	if session.State != gossip.SyncSessionSummarySent {
		t.Fatalf("announce changed active session state to %s", session.State)
	}
	if got := service.hostRuntime.PendingEventCount(); got != 0 {
		t.Fatalf("active announce queued %d sync events, want none", got)
	}
	if !service.hostRuntime.Gossip.PendingHint(peerID) {
		t.Fatal("active announce did not record a follow-up hint")
	}
	session.State = gossip.SyncSessionCompleted
	service.completeSyncSession(session, false)
	if service.hostRuntime.Gossip.PendingHint(peerID) {
		t.Fatal("follow-up hint was not consumed after session completion")
	}
	if got := service.hostRuntime.PendingEventCount(); got != 1 {
		t.Fatalf("follow-up hint queued %d sync events, want one", got)
	}
	ev, ok := service.hostRuntime.GossipEventFor(<-service.hostRuntime.Events())
	if !ok {
		t.Fatal("follow-up hint did not produce a gossip event")
	}
	timer, ok := ev.(*gossip.SyncTimerEvent)
	if !ok {
		t.Fatalf("follow-up hint event = %T, want gossip.SyncTimerEvent", ev)
	}
	if timer.PeerID != peerID || timer.LocalSummary == nil {
		t.Fatalf("follow-up hint timer = %+v, want peer with local summary", timer)
	}
}
