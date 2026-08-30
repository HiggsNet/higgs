package main

import (
	"bytes"
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corehost "github.com/HiggsNet/photon/pkg/core/host"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
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

	transportA, err := listenTestGossipTransport(configA.ListenAddr, gossip.Config{PeerID: configA.PeerID})
	if err != nil {
		t.Fatalf("Listen(A): %v", err)
	}
	defer transportA.Close()
	transportB, err := listenTestGossipTransport(configB.ListenAddr, gossip.Config{PeerID: configB.PeerID})
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

	serviceA := newTestDaemonService(rtA, stateA, configA, time.Second)
	setTestGossipTransport(t, serviceA, transportA)
	serviceB := newTestDaemonService(rtB, stateB, configB, time.Second)
	setTestGossipTransport(t, serviceB, transportB)

	fc := newFakeClock(now)
	serviceA.EnableEventLoopSync(fc)
	serviceB.EnableEventLoopSync(fc)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := startObjectPullServer(ctx, serviceA); err != nil {
		t.Fatalf("startObjectPullServer(A): %v", err)
	}
	if err := startObjectPullServer(ctx, serviceB); err != nil {
		t.Fatalf("startObjectPullServer(B): %v", err)
	}
	if err := serviceA.hostRuntime.StartGossipObjectPullWorkers(ctx, serviceA.objectPullExecutor, 0, 0); err != nil {
		t.Fatal(err)
	}
	defer serviceA.hostRuntime.Stop()
	if err := serviceB.hostRuntime.StartGossipObjectPullWorkers(ctx, serviceB.objectPullExecutor, 0, 0); err != nil {
		t.Fatal(err)
	}
	defer serviceB.hostRuntime.Stop()

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

	latestA := serviceA.currentState()
	latestB := serviceB.currentState()
	if latestA.Network.Zones["node-b.catofes."] == nil || latestA.Network.Zones["node-b.catofes."].Records["event-loop-test"] == nil {
		t.Fatalf("record from B did not appear on A")
	}
	if latestB.Network.Zones["node-a.catofes."] == nil || latestB.Network.Zones["node-a.catofes."].Records["event-loop-test"] == nil {
		t.Fatalf("record from A did not appear on B")
	}
}

func TestDaemonSyncTimerStartsWhenInternalEventQueueIsFull(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(1000, 0)
	peerID := "bootstrap.catofes."
	config.Bootstrap = []syncConfigPeer{{ID: peerID, Addr: "127.0.0.1:33434"}}
	state.SyncPeers = map[string]syncPeerState{
		peerID: {
			BackoffUntilUnix: now.Add(-time.Minute).Unix(),
		},
	}
	rt := &Runtime{Config: defaultAppConfig(), Clock: func() time.Time { return now }}
	service := newTestDaemonService(rt, state, config, time.Minute)
	for {
		if err := service.hostRuntime.PostGossip(&gossip.SyncTimerEvent{PeerID: "queued.catofes."}); err != nil {
			break
		}
	}

	if err := service.handleSyncTimerEvent(context.Background(), false); err != nil {
		t.Fatalf("handleSyncTimerEvent: %v", err)
	}
	session := service.hostRuntime.Gossip.Session(peerID)
	if session == nil || session.State != gossip.SyncSessionSummarySent {
		t.Fatalf("bootstrap session = %#v, want directly started summary_sent session", session)
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
	service := newTestDaemonService(rt, state, config, time.Second)
	service.EnableEventLoopSync(newFakeClock(now))

	peerID := "peer-a"
	session := gossip.NewSyncSession(peerID)
	_, _ = session.OnEvent(&gossip.SyncTimerEvent{
		PeerID:       peerID,
		LocalSummary: &corestate.CatalogSummary{CatalogRoot: corestate.CatalogRoot(nil), ZoneCount: 0},
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
	if after := service.StateStore.Meta().Revision; after != before {
		t.Fatalf("fetch catalog page verified revision = %d, want %d", after, before)
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
	if after := service.StateStore.Meta().Revision; after != before {
		t.Fatalf("fetch zone verified revision = %d, want %d", after, before)
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
	service := newTestDaemonService(rt, state, config, time.Second)
	service.EnableEventLoopSync(newFakeClock(now))

	beforeRoot := append([]byte(nil), corestate.ZoneRoot(state.Network.Zones["node-b.catofes."])...)
	err := service.processPacketEvent(&gossip.Packet{Message: &gossip.Message{
		Type:     gossip.MessageAnnounce,
		PeerID:   "peer-a",
		Announce: &gossip.Announce{Zones: []corestate.ZoneDigest{{Zone: "node-b.catofes.", RootHash: []byte("remote-root")}}},
	}}, context.Background())
	if err != nil {
		t.Fatalf("process announce: %v", err)
	}
	if afterRoot := corestate.ZoneRoot(state.Network.Zones["node-b.catofes."]); !bytes.Equal(afterRoot, beforeRoot) {
		t.Fatal("announce changed zone state directly; want hint-only ingress")
	}
	session := service.hostRuntime.Gossip.Session("peer-a")
	if session == nil || session.State != gossip.SyncSessionIdle {
		t.Fatalf("announce hint session = %+v, want idle session queued for active pull", session)
	}
	if got := service.hostRuntime.PendingEventCount(); got != 1 {
		t.Fatalf("announce hint queued %d events, want one sync timer", got)
	}
	ev, ok := service.hostRuntime.GossipSessionEventFor(<-service.hostRuntime.Events())
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
	now := time.Unix(123, 0)
	rt := &Runtime{
		Config:    defaultAppConfig(),
		StatePath: filepath.Join(t.TempDir(), "state.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	service := newTestDaemonService(rt, state, config, time.Second)
	service.EnableEventLoopSync(newFakeClock(now))

	peerID := "node-b.catofes."
	localSummary := corestate.CatalogSummaryFor(state.Network)

	err := service.processPacketEvent(&gossip.Packet{
		Addr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 33434},
		Message: &gossip.Message{
			Type:   gossip.MessagePing,
			PeerID: peerID,
			Ping:   &gossip.Ping{Summary: localSummary},
		},
	}, context.Background())
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
	observed, ok := service.hostRuntime.Observability.Snapshot(peerID, now)
	if !ok || observed.LastHintReason != "ping_summary_match" {
		t.Fatalf("observed hint = %+v, want ping_summary_match", observed)
	}
	if peerState.BackoffUntilUnix != 0 {
		t.Fatalf("BackoffUntilUnix = %d, want 0", peerState.BackoffUntilUnix)
	}
	if peerState.ObservedAddr != "127.0.0.1:33434" {
		t.Fatalf("ObservedAddr = %q, want verified packet source", peerState.ObservedAddr)
	}
}

func TestDaemonPingSummaryShortcutCommitsPeerChangesOnce(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(1000, 0)
	service := newTestDaemonService(&Runtime{
		Config: defaultAppConfig(),
		Clock:  func() time.Time { return now },
	}, state, config, time.Second)
	bindTestHostGossipTransport(t, service, "peer-a")

	summary := corestate.CatalogSummaryFor(state.Network)
	message := &gossip.Message{
		Type:   gossip.MessagePing,
		PeerID: "peer-a",
		Ping:   &gossip.Ping{Summary: summary},
	}
	before := service.StateStore.Meta().Revision
	if _, err := service.hostRuntime.HandleGossipHostEvent(context.Background(), corehost.GossipPacketReceived{Packet: &gossip.Packet{Message: message}}, now, nil); err != nil {
		t.Fatalf("HandleGossipHostEvent: %v", err)
	}
	after := service.StateStore.Meta().Revision
	if after != before {
		t.Fatalf("verified revision = %d, want checkpoint update to keep %d", after, before)
	}
}

func TestDaemonHintedSessionWritesOnlyObservability(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(1000, 0)
	service := newTestDaemonService(&Runtime{
		Config: defaultAppConfig(),
		Clock:  func() time.Time { return now },
	}, state, config, time.Second)

	before := service.StateStore.Meta().Revision
	if err := service.hostRuntime.StartGossipSession("peer-a", "test_hint"); err != nil {
		t.Fatalf("StartGossipSession: %v", err)
	}
	after := service.StateStore.Meta().Revision
	if after != before {
		t.Fatalf("state revision = %d, want unchanged %d", after, before)
	}
	observed, ok := service.hostRuntime.Observability.Snapshot("peer-a", now)
	if !ok || observed.LastHintReason != "test_hint" || observed.ActivePullLastEvent != "hint_queued" {
		t.Fatalf("peer observability = %+v, want hint and active-pull changes", observed)
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
	service := newTestDaemonService(rt, state, config, time.Second)
	service.EnableEventLoopSync(newFakeClock(now))

	peerID := "peer-a"
	session := gossip.NewSyncSession(peerID)
	if _, err := session.OnEvent(&gossip.SyncTimerEvent{
		PeerID:       peerID,
		LocalSummary: &corestate.CatalogSummary{CatalogRoot: []byte("local"), ZoneCount: 1},
	}, now); err != nil {
		t.Fatalf("start sync session: %v", err)
	}
	service.hostRuntime.Gossip.SetSession(peerID, session)

	before := service.StateStore.Meta().Revision
	service.handleSyncEvent(context.Background(), &gossip.RoundTimeoutEvent{PeerID: peerID})
	after := service.StateStore.Meta().Revision
	if after != before {
		t.Fatalf("verified revision = %d, want checkpoint update to keep %d", after, before)
	}
	snapshot, _ := service.StateStore.Snapshot()
	peerState := snapshot.SyncPeers[peerID]
	observed, ok := service.hostRuntime.Observability.Snapshot(peerID, now)
	if !ok || observed.ActivePullLastEvent != "round_timeout" || peerState.FailureCount != 1 || peerState.LastError != "round timeout" {
		t.Fatalf("peer state/observability = %+v/%+v, want active-pull, backoff, and completion changes", peerState, observed)
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
	service := newTestDaemonService(rt, state, config, time.Second)
	service.EnableEventLoopSync(newFakeClock(now))

	peerID := "peer-a"
	err := service.processPacketEvent(&gossip.Packet{Message: &gossip.Message{
		Type:   gossip.MessagePing,
		PeerID: peerID,
		Ping:   &gossip.Ping{Summary: &corestate.CatalogSummary{CatalogRoot: []byte("mismatch"), ZoneCount: 99}},
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
	service := newTestDaemonService(rt, state, config, time.Second)
	service.EnableEventLoopSync(newFakeClock(now))

	peerID := "peer-a"
	session := gossip.NewSyncSession(peerID)
	_, _ = session.OnEvent(&gossip.SyncTimerEvent{
		PeerID:       peerID,
		LocalSummary: &corestate.CatalogSummary{CatalogRoot: corestate.CatalogRoot(nil), ZoneCount: 0},
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
	service.handleSyncEvent(context.Background(), &gossip.SyncTimerEvent{PeerID: peerID})
	if service.hostRuntime.Gossip.PendingHint(peerID) {
		t.Fatal("follow-up hint was not consumed after session completion")
	}
	if got := service.hostRuntime.PendingEventCount(); got != 1 {
		t.Fatalf("follow-up hint queued %d sync events, want one", got)
	}
	ev, ok := service.hostRuntime.GossipSessionEventFor(<-service.hostRuntime.Events())
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
