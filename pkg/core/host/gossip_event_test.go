package host

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
)

type observingGossipEventController struct {
	memoryGossipController
	summaries int
	pages     int
}

func (controller *observingGossipEventController) ObserveGossipCatalogSummary(string, *corestate.CatalogSummary) {
	controller.summaries++
}

func (controller *observingGossipEventController) ObserveGossipCatalogPage(string, *corestate.CatalogPage) {
	controller.pages++
}

func TestRuntimeHandleGossipEventOwnsEngineToActionBridge(t *testing.T) {
	clock := newFakeClock(time.Unix(100, 0))
	controller := &memoryGossipController{}
	runtime := NewRuntime(clock, 2, &memoryGossipStateStore{views: []corestate.View{loadedGossipState()}, trace: &controller.trace}, GossipRuntimeConfig{PeerID: "local.catofes.", Limits: corestate.DefaultSyncLimits()})
	defer runtime.Stop()
	runtime.Gossip.NewSession("peer-a")

	result, err := runtime.HandleGossipEvent(context.Background(), &gossip.SyncTimerEvent{PeerID: "peer-a"}, clock.Now(), controller)
	if err != nil {
		t.Fatal(err)
	}
	if result.OldState != gossip.SyncSessionIdle || result.NewState != gossip.SyncSessionSummarySent || result.Done || result.ProtocolErr != nil {
		t.Fatalf("result = %#v", result)
	}
	if want := []string{"read", "send:ping"}; !reflect.DeepEqual(controller.trace, want) {
		t.Fatalf("trace = %#v, want %#v", controller.trace, want)
	}
}

func TestRuntimeHandleGossipEventRejectsMissingPeerOrSession(t *testing.T) {
	runtime := NewRuntime(nil, 1, nil, GossipRuntimeConfig{})
	defer runtime.Stop()
	controller := &memoryGossipController{}
	if _, err := runtime.HandleGossipEvent(context.Background(), &gossip.PacketEvent{}, time.Now(), controller); !errors.Is(err, ErrGossipEventPeerRequired) {
		t.Fatalf("missing peer error = %v", err)
	}
	if _, err := runtime.HandleGossipEvent(context.Background(), &gossip.SyncTimerEvent{PeerID: "missing"}, time.Now(), controller); !errors.Is(err, ErrGossipSessionNotFound) {
		t.Fatalf("missing session error = %v", err)
	}
}

func TestRuntimeRoundTimeoutDropsOnlyItsPeerChunkAssemblies(t *testing.T) {
	runtime := NewRuntime(nil, 2, &memoryGossipStateStore{views: []corestate.View{loadedGossipState("local.catofes.")}}, GossipRuntimeConfig{PeerID: "local.catofes.", Limits: corestate.DefaultSyncLimits()})
	defer runtime.Stop()
	runtime.Gossip.NewSession("peer-a")
	id := []byte("0123456789abcdef")
	first := &gossip.ObjectChunk{TransferID: id, Object: gossip.ObjectPullZone, Zone: "catofes.", ObjectHash: make([]byte, 32), Index: 0, Total: 2, Data: []byte("first")}
	if _, complete, err := runtime.AddGossipObjectChunk("peer-a", first, time.Now()); err != nil || complete {
		t.Fatalf("first chunk: complete=%t err=%v", complete, err)
	}
	controller := &memoryGossipController{}
	if _, err := runtime.HandleGossipEvent(context.Background(), &gossip.RoundTimeoutEvent{PeerID: "peer-a"}, time.Now(), controller); err != nil {
		t.Fatal(err)
	}
	second := &gossip.ObjectChunk{TransferID: id, Object: gossip.ObjectPullZone, Zone: "catofes.", ObjectHash: make([]byte, 32), Index: 1, Total: 2, Data: []byte("second")}
	if _, complete, err := runtime.AddGossipObjectChunk("peer-a", second, time.Now()); err != nil || complete {
		t.Fatalf("chunk after timeout: complete=%t err=%v", complete, err)
	}
}

func TestRuntimeHandleGossipEventOwnsCatalogEnrichment(t *testing.T) {
	runtime := NewRuntime(nil, 2, &memoryGossipStateStore{views: []corestate.View{loadedManagedGossipState("local.catofes.")}}, GossipRuntimeConfig{PeerID: "local.catofes.", Limits: corestate.DefaultSyncLimits()})
	defer runtime.Stop()
	session := runtime.Gossip.NewSession("peer-a")
	session.State = gossip.SyncSessionCatalogDiffing
	controller := &observingGossipEventController{}
	event := &gossip.CatalogPageReceivedEvent{PeerID: "peer-a", Page: &corestate.CatalogPage{Entries: []corestate.ZoneDigest{
		{Zone: "local.catofes.", RootHash: []byte("local")},
		{Zone: "remote.catofes.", RootHash: []byte("remote")},
	}}}
	if _, err := runtime.HandleGossipEvent(context.Background(), event, time.Now(), controller); err != nil {
		t.Fatal(err)
	}
	if controller.pages != 1 || len(event.Page.Entries) != 1 || event.Page.Entries[0].Zone != "remote.catofes." {
		t.Fatalf("pages=%d event=%#v", controller.pages, event)
	}
}

func TestRuntimeSchedulerDeliversChunkRepairThroughCommonEventBridge(t *testing.T) {
	clock := newFakeClock(time.Unix(100, 0))
	runtime := NewRuntime(clock, 2, &memoryGossipStateStore{views: []corestate.View{loadedGossipState()}}, GossipRuntimeConfig{PeerID: "local.catofes.", Limits: corestate.DefaultSyncLimits()})
	defer runtime.Stop()
	runtime.Gossip.NewSession("peer-a")
	id := []byte("0123456789abcdef")
	chunk := &gossip.ObjectChunk{TransferID: id, Object: gossip.ObjectPullZone, Zone: "catofes.", ObjectHash: make([]byte, 32), Index: 0, Total: 2, Data: []byte("partial")}
	if _, complete, err := runtime.AddGossipObjectChunk("peer-a", chunk, clock.Now()); err != nil || complete {
		t.Fatalf("add chunk: complete=%t err=%v", complete, err)
	}
	if err := runtime.ScheduleGossipChunkRepair("peer-a", chunk); err != nil {
		t.Fatal(err)
	}
	clock.Advance(gossip.ChunkRepairQuiet)
	hostEvent := <-runtime.Events()
	event, ok := runtime.GossipEventFor(hostEvent)
	if !ok {
		t.Fatalf("host event %#v was not a gossip event", hostEvent)
	}
	controller := &memoryGossipController{}
	if _, err := runtime.HandleGossipEvent(context.Background(), event, clock.Now(), controller); err != nil {
		t.Fatal(err)
	}
	if want := []string{"send:object_chunk_nack"}; !reflect.DeepEqual(controller.trace, want) {
		t.Fatalf("trace = %#v, want %#v", controller.trace, want)
	}
}
