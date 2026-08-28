package host

import (
	"context"
	"errors"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

type memoryGossipController struct {
	trace       []string
	views       []GossipStateView
	applyResult GossipSnapshotApplyResult
	applyErr    error
	issues      []GossipExecutionIssue
	persisted   GossipPersistenceIntent
	completion  *GossipCompletionIntent
}

// These adapters intentionally add no behavior: their only purpose is to
// prove that platform composition selects capabilities, not an executor.
type memoryLinuxGossipController struct{ memoryGossipController }
type memoryWindowsGossipController struct{ memoryGossipController }

type successfulObjectPullClient struct{}

func (successfulObjectPullClient) Exchange(_ context.Context, _ string, request *gossip.ObjectPullRequest) (*gossip.ObjectPullResponse, error) {
	return &gossip.ObjectPullResponse{OK: true, Snapshot: &corestate.ZoneSnapshot{Zone: request.Zone}}, nil
}

func memoryObjectPullExecutor(pulls chan gossip.StartObjectPullAction) *GossipObjectPullExecutor {
	return NewGossipObjectPullExecutor(GossipObjectPullExecutorConfig{
		Client: successfulObjectPullClient{},
		Discovery: func() GossipDiscoveryInput {
			return GossipDiscoveryInput{
				Network:   zone.NewNetworkState(),
				Bootstrap: map[string]*net.UDPAddr{"peer-a": {IP: net.ParseIP("127.0.0.1"), Port: 1}},
			}
		},
		ObserveAttempt: func(peerID string, path zone.ZonePath, _ time.Time) {
			if pulls != nil {
				pulls <- gossip.StartObjectPullAction{PeerID: peerID, Zone: path}
			}
		},
	})
}

func (controller *memoryGossipController) GossipStateView(context.Context) GossipStateView {
	controller.trace = append(controller.trace, "read")
	if len(controller.views) == 0 {
		return GossipStateView{}
	}
	view := controller.views[0]
	if len(controller.views) > 1 {
		controller.views = controller.views[1:]
	}
	return view
}

func (controller *memoryGossipController) ApplyGossipSnapshots(context.Context, string, []gossip.ApplySnapshotAction) (GossipSnapshotApplyResult, error) {
	controller.trace = append(controller.trace, "apply")
	return controller.applyResult, controller.applyErr
}

func (controller *memoryGossipController) SendGossip(_ context.Context, outbound gossip.OutboundMessage) error {
	controller.trace = append(controller.trace, "send:"+string(outbound.Message.Type))
	return nil
}

func (controller *memoryGossipController) ObserveGossipCatalogSummary(string, *corestate.CatalogSummary) {
}

func (controller *memoryGossipController) ObserveGossipCatalogPage(string, *corestate.CatalogPage) {}

func (controller *memoryGossipController) FilterGossipCatalogPage(_ context.Context, _ string, page *corestate.CatalogPage, _ time.Time) ([]corestate.ZoneDigest, *corestate.CatalogPage) {
	return nil, page
}

func (controller *memoryGossipController) ObserveGossipChunkRepair(string) {}

func (controller *memoryGossipController) RecordGossipBackoffs(_ context.Context, backoffs []gossip.RecordBackoffAction) error {
	controller.trace = append(controller.trace, "backoff")
	return nil
}

func (controller *memoryGossipController) PersistGossip(_ context.Context, intent GossipPersistenceIntent, completion *GossipCompletionIntent) error {
	controller.trace = append(controller.trace, "persist")
	controller.persisted = intent
	controller.completion = completion
	return nil
}

func (controller *memoryGossipController) ReportGossipIssue(issue GossipExecutionIssue) {
	controller.issues = append(controller.issues, issue)
}

func TestRuntimeExecuteGossipActionsUsesCommonOrdering(t *testing.T) {
	clock := newFakeClock(time.Unix(100, 0))
	runtime := NewRuntime(clock, 4)
	defer runtime.Stop()
	pulls := make(chan gossip.StartObjectPullAction, 1)
	if err := runtime.StartGossipObjectPullWorkers(t.Context(), memoryObjectPullExecutor(pulls), 1, 1); err != nil {
		t.Fatal(err)
	}
	controller := &memoryGossipController{
		views: []GossipStateView{
			{Loaded: true},
			{Loaded: true, Digests: []corestate.ZoneDigest{{Zone: "node-a.catofes.", RootHash: []byte("root")}}},
		},
		applyResult: GossipSnapshotApplyResult{StateCommitted: true, NetworkChanged: true},
	}
	session := &gossip.SyncSession{PeerID: "peer-a", State: gossip.SyncSessionCompleted}
	deadline := clock.Now().Add(time.Second)
	actions := []gossip.SyncAction{
		gossip.StartObjectPullAction{PeerID: "peer-a", Zone: "node-a.catofes."},
		gossip.SendPingAction{PeerID: "peer-a"},
		gossip.ApplySnapshotAction{PeerID: "peer-a", Snapshot: &corestate.ZoneSnapshot{Zone: "node-a.catofes."}},
		gossip.StartTimerAction{PeerID: "peer-a", Kind: gossip.TimerKindRound, Deadline: deadline},
		gossip.RecordBackoffAction{PeerID: "peer-a", Err: errors.New("retry")},
		gossip.SaveStateAction{Reason: "complete", Persistence: gossip.SyncPersistenceMeta},
	}

	result := runtime.ExecuteGossipActions(context.Background(), session, actions, controller)
	if result.Aborted || !result.NetworkChanged {
		t.Fatalf("result = %#v", result)
	}
	wantTrace := []string{"read", "apply", "read", "send:ping", "backoff", "persist"}
	if !slices.Equal(controller.trace, wantTrace) {
		t.Fatalf("trace = %#v, want %#v", controller.trace, wantTrace)
	}
	if !controller.persisted.Requested || controller.persisted.Scope != gossip.SyncPersistenceNetwork || controller.persisted.Reason != "complete" {
		t.Fatalf("persistence = %#v", controller.persisted)
	}
	if controller.completion == nil || controller.completion.PeerID != "peer-a" || controller.completion.Err != nil {
		t.Fatalf("completion = %#v", controller.completion)
	}
	if pull := <-pulls; pull.PeerID != "peer-a" || pull.Zone != "node-a.catofes." {
		t.Fatalf("pull = %#v", pull)
	}
	if event, ok := runtime.GossipEventFor(<-runtime.Events()); !ok {
		t.Fatal("object-pull completion was not queued")
	} else if _, ok := event.(*gossip.ObjectPullResultEvent); !ok {
		t.Fatalf("event = %T, want *gossip.ObjectPullResultEvent", event)
	}
	clock.Advance(time.Second)
	if fired := receiveTimer(t, runtime.Events()); fired.ID.Owner != "peer-a" || fired.ID.Key != gossip.TimerKindRound {
		t.Fatalf("timer = %#v", fired)
	}
}

func TestRuntimeExecuteGossipActionsApplyFailureStopsLaterPhases(t *testing.T) {
	runtime := NewRuntime(newFakeClock(time.Unix(100, 0)), 1)
	defer runtime.Stop()
	applyErr := errors.New("commit failed")
	controller := &memoryGossipController{
		views:    []GossipStateView{{Loaded: true}},
		applyErr: applyErr,
	}
	session := &gossip.SyncSession{PeerID: "peer-a", State: gossip.SyncSessionObjectPulling}
	result := runtime.ExecuteGossipActions(context.Background(), session, []gossip.SyncAction{
		gossip.ApplySnapshotAction{PeerID: "peer-a", Snapshot: &corestate.ZoneSnapshot{Zone: "node-a.catofes."}},
		gossip.SendPingAction{PeerID: "peer-a"},
		gossip.SaveStateAction{Reason: "must not persist"},
	}, controller)
	if !result.Aborted || result.NetworkChanged {
		t.Fatalf("result = %#v", result)
	}
	if want := []string{"read", "apply"}; !slices.Equal(controller.trace, want) {
		t.Fatalf("trace = %#v, want %#v", controller.trace, want)
	}
	if len(controller.issues) != 1 || controller.issues[0].Phase != GossipPhaseApply || !errors.Is(controller.issues[0].Err, applyErr) {
		t.Fatalf("issues = %#v", controller.issues)
	}
}

func TestRuntimeExecuteGossipActionsMemoryAdaptersAreEquivalent(t *testing.T) {
	actions := []gossip.SyncAction{
		gossip.SendFetchCatalogPageAction{PeerID: "peer-a", Cursor: "2"},
		gossip.StartObjectPullAction{PeerID: "peer-a", Zone: "node-a.catofes."},
		gossip.SaveStateAction{Reason: "metadata", Persistence: gossip.SyncPersistenceMeta},
	}
	type outcome struct {
		trace     []string
		persisted GossipPersistenceIntent
		failure   []string
		issue     GossipExecutionIssue
	}
	adapters := []struct {
		name string
		new  func() (GossipActionController, *memoryGossipController)
	}{
		{
			name: "linux",
			new: func() (GossipActionController, *memoryGossipController) {
				controller := &memoryLinuxGossipController{memoryGossipController: memoryGossipController{views: []GossipStateView{{Loaded: true}}}}
				return controller, &controller.memoryGossipController
			},
		},
		{
			name: "windows",
			new: func() (GossipActionController, *memoryGossipController) {
				controller := &memoryWindowsGossipController{memoryGossipController: memoryGossipController{views: []GossipStateView{{Loaded: true}}}}
				return controller, &controller.memoryGossipController
			},
		},
	}
	var outcomes []outcome
	commitErr := errors.New("commit failed")
	for _, adapter := range adapters {
		runtime := NewRuntime(newFakeClock(time.Unix(100, 0)), 1)
		if err := runtime.StartGossipObjectPullWorkers(t.Context(), memoryObjectPullExecutor(nil), 1, 1); err != nil {
			t.Fatal(err)
		}
		controller, memory := adapter.new()
		runtime.ExecuteGossipActions(context.Background(), &gossip.SyncSession{PeerID: "peer-a"}, actions, controller)
		runtime.Stop()

		failureRuntime := NewRuntime(newFakeClock(time.Unix(100, 0)), 1)
		failureController, failureMemory := adapter.new()
		failureMemory.applyErr = commitErr
		failureRuntime.ExecuteGossipActions(context.Background(), &gossip.SyncSession{PeerID: "peer-a"}, []gossip.SyncAction{
			gossip.ApplySnapshotAction{PeerID: "peer-a", Snapshot: &corestate.ZoneSnapshot{Zone: "node-a.catofes."}},
			gossip.SendPingAction{PeerID: "peer-a"},
			gossip.SaveStateAction{Reason: "must not persist"},
		}, failureController)
		failureRuntime.Stop()
		if len(failureMemory.issues) != 1 {
			t.Fatalf("%s issues = %#v, want one", adapter.name, failureMemory.issues)
		}
		outcomes = append(outcomes, outcome{
			trace:     append([]string(nil), memory.trace...),
			persisted: memory.persisted,
			failure:   append([]string(nil), failureMemory.trace...),
			issue:     failureMemory.issues[0],
		})
	}
	left, right := outcomes[0], outcomes[1]
	if !slices.Equal(left.trace, right.trace) ||
		left.persisted != right.persisted ||
		!slices.Equal(left.failure, right.failure) ||
		left.issue.Phase != right.issue.Phase ||
		left.issue.PeerID != right.issue.PeerID ||
		!errors.Is(left.issue.Err, right.issue.Err) {
		t.Fatalf("adapter outcomes differ: %#v", outcomes)
	}
	if want := []string{"read", "send:fetch_catalog_page", "persist"}; !slices.Equal(outcomes[0].trace, want) {
		t.Fatalf("trace = %#v, want %#v", outcomes[0].trace, want)
	}
	if !outcomes[0].persisted.Requested || outcomes[0].persisted.Scope != gossip.SyncPersistenceMeta || outcomes[0].persisted.Reason != "metadata" {
		t.Fatalf("persistence = %#v", outcomes[0].persisted)
	}
	if want := []string{"read", "apply"}; !slices.Equal(outcomes[0].failure, want) || outcomes[0].issue.Phase != GossipPhaseApply {
		t.Fatalf("failure outcome = %#v", outcomes[0])
	}
}
