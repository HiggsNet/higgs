package host

import (
	"context"
	"errors"
	"testing"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
)

type blockingObjectPullWorker struct{ entered chan struct{} }

func (worker *blockingObjectPullWorker) PullGossipObject(ctx context.Context, action gossip.StartObjectPullAction) GossipObjectPullCompletion {
	select {
	case worker.entered <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return GossipObjectPullCompletion{PeerID: action.PeerID, Zone: action.Zone, Err: ctx.Err()}
}

func TestPostGossipObjectPullCompletionMapsAndQueuesFSMEvent(t *testing.T) {
	runtime := NewRuntime(nil, 1)
	defer runtime.Stop()

	pullErr := errors.New("pull failed")
	snapshot := &corestate.ZoneSnapshot{Zone: "node-a.catofes."}
	err := runtime.PostGossipObjectPullCompletion(GossipObjectPullCompletion{
		PeerID:   "peer-a",
		Zone:     snapshot.Zone,
		Snapshot: snapshot,
		Err:      pullErr,
	})
	if err != nil {
		t.Fatalf("PostGossipObjectPullCompletion: %v", err)
	}

	event, ok := runtime.GossipEventFor(<-runtime.Events())
	if !ok {
		t.Fatal("completion did not produce a gossip event")
	}
	result, ok := event.(*gossip.ObjectPullResultEvent)
	if !ok {
		t.Fatalf("event = %T, want *gossip.ObjectPullResultEvent", event)
	}
	if result.PeerID != "peer-a" || result.Zone != snapshot.Zone || result.Snapshot != snapshot || !errors.Is(result.Err, pullErr) {
		t.Fatalf("result = %+v, want mapped completion", result)
	}
}

func TestPostGossipObjectPullCompletionPreservesBackpressure(t *testing.T) {
	runtime := NewRuntime(nil, 1)
	defer runtime.Stop()
	if err := runtime.PostGossip(&gossip.SyncTimerEvent{PeerID: "occupy"}); err != nil {
		t.Fatalf("fill queue: %v", err)
	}
	if err := runtime.PostGossipObjectPullCompletion(GossipObjectPullCompletion{PeerID: "peer-a"}); !errors.Is(err, ErrEventQueueFull) {
		t.Fatalf("completion error = %v, want %v", err, ErrEventQueueFull)
	}
}

func TestGossipObjectPullWorkersProvideBoundedBackpressureAndStop(t *testing.T) {
	runtime := NewRuntime(nil, 4)
	worker := &blockingObjectPullWorker{entered: make(chan struct{}, 1)}
	if err := runtime.StartGossipObjectPullWorkers(t.Context(), worker, 1, 1); err != nil {
		t.Fatal(err)
	}
	first := gossip.StartObjectPullAction{PeerID: "peer-a", Zone: "a.catofes."}
	if err := runtime.SubmitGossipObjectPull(first); err != nil {
		t.Fatal(err)
	}
	<-worker.entered
	if err := runtime.SubmitGossipObjectPull(gossip.StartObjectPullAction{PeerID: "peer-b", Zone: "b.catofes."}); err != nil {
		t.Fatal(err)
	}
	if err := runtime.SubmitGossipObjectPull(gossip.StartObjectPullAction{PeerID: "peer-c", Zone: "c.catofes."}); !errors.Is(err, ErrGossipObjectPullQueueFull) {
		t.Fatalf("third submit error = %v, want %v", err, ErrGossipObjectPullQueueFull)
	}
	if got := runtime.PendingGossipObjectPullCount(); got != 2 {
		t.Fatalf("pending = %d, want 2", got)
	}
	runtime.Stop()
	if got := runtime.PendingGossipObjectPullCount(); got != 0 {
		t.Fatalf("pending after stop = %d, want 0", got)
	}
	if err := runtime.SubmitGossipObjectPull(first); !errors.Is(err, ErrRuntimeStopped) {
		t.Fatalf("submit after stop = %v, want %v", err, ErrRuntimeStopped)
	}
}
