package host

import (
	"errors"
	"testing"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
)

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
