package host

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
)

type memoryInboundController struct {
	budget        int
	outbound      []gossip.OutboundMessage
	summaries     []*corestate.CatalogSummary
	pages         []*corestate.CatalogPage
	rejects       []error
	hints         []string
	matches       []string
	fetches       []*gossip.FetchZone
	chunks        int
	nacks         int
	issues        []GossipExecutionIssue
	controllerErr error
}

func (controller *memoryInboundController) GossipDatagramBudget() int { return controller.budget }

func (controller *memoryInboundController) SendGossip(_ context.Context, outbound gossip.OutboundMessage) error {
	controller.outbound = append(controller.outbound, outbound)
	return controller.controllerErr
}

func (controller *memoryInboundController) ObserveGossipCatalogSummary(_ string, summary *corestate.CatalogSummary) {
	controller.summaries = append(controller.summaries, summary)
}

func (controller *memoryInboundController) ObserveGossipCatalogPage(_ string, page *corestate.CatalogPage) {
	controller.pages = append(controller.pages, page)
}

func (controller *memoryInboundController) ObserveGossipCatalogReject(_ string, _ string, err error) {
	controller.rejects = append(controller.rejects, err)
}

func (controller *memoryInboundController) RecordGossipSummaryMatch(_ context.Context, peerID string) error {
	controller.matches = append(controller.matches, peerID)
	return controller.controllerErr
}

func (controller *memoryInboundController) HandleGossipAnnounceHint(_ context.Context, peerID string) error {
	controller.hints = append(controller.hints, peerID)
	return controller.controllerErr
}

func (controller *memoryInboundController) RespondGossipFetchZone(_ context.Context, _ string, fetch *gossip.FetchZone) error {
	controller.fetches = append(controller.fetches, fetch)
	return controller.controllerErr
}

func (controller *memoryInboundController) HandleGossipObjectChunk(context.Context, *gossip.Message) error {
	controller.chunks++
	return controller.controllerErr
}

func (controller *memoryInboundController) HandleGossipObjectChunkNACK(context.Context, *gossip.Message) error {
	controller.nacks++
	return controller.controllerErr
}

func (controller *memoryInboundController) ReportGossipIssue(issue GossipExecutionIssue) {
	controller.issues = append(controller.issues, issue)
}

func TestRuntimeExecuteGossipInboundPlansPingResponsesAndHint(t *testing.T) {
	runtime := NewRuntime(newFakeClock(time.Unix(100, 0)), 2, &memoryGossipStateStore{views: []corestate.View{loadedGossipState("local.catofes.")}}, GossipRuntimeConfig{PeerID: "local.catofes.", Limits: corestate.DefaultSyncLimits()})
	defer runtime.Stop()
	controller := &memoryInboundController{}
	packet := &gossip.Packet{Message: &gossip.Message{
		Type:   gossip.MessagePing,
		PeerID: "peer-a",
		Ping:   &gossip.Ping{Summary: &corestate.CatalogSummary{CatalogRoot: []byte("remote"), ZoneCount: 1}},
	}}
	actions := runtime.Gossip.PlanInbound(packet)
	if err := runtime.ExecuteGossipInbound(context.Background(), actions, controller); err != nil {
		t.Fatalf("ExecuteGossipInbound: %v", err)
	}
	if len(controller.outbound) != 2 || controller.outbound[0].Message.Type != gossip.MessagePong || controller.outbound[1].Message.Type != gossip.MessageFetchCatalogPage {
		t.Fatalf("outbound = %#v, want PONG then FETCH_CATALOG_PAGE", controller.outbound)
	}
	if len(controller.summaries) != 1 || len(controller.hints) != 1 || controller.hints[0] != "peer-a" || len(controller.matches) != 0 {
		t.Fatalf("summary/hint/match = %d/%#v/%#v", len(controller.summaries), controller.hints, controller.matches)
	}
}

func TestRuntimeExecuteGossipInboundBuildsBoundedCatalogPage(t *testing.T) {
	runtime := NewRuntime(newFakeClock(time.Unix(100, 0)), 1, &memoryGossipStateStore{views: []corestate.View{loadedGossipState("a.catofes.", "b.catofes.")}}, GossipRuntimeConfig{PeerID: "local.catofes.", Limits: corestate.DefaultSyncLimits()})
	defer runtime.Stop()
	controller := &memoryInboundController{
		budget: gossip.DefaultDatagramBudget,
	}
	packet := &gossip.Packet{Message: &gossip.Message{
		Type:             gossip.MessageFetchCatalogPage,
		PeerID:           "peer-a",
		FetchCatalogPage: &gossip.FetchCatalogPage{},
	}}
	if err := runtime.ExecuteGossipInbound(context.Background(), runtime.Gossip.PlanInbound(packet), controller); err != nil {
		t.Fatalf("ExecuteGossipInbound: %v", err)
	}
	if len(controller.pages) != 1 || len(controller.outbound) != 1 || controller.outbound[0].Message.CatalogPage != controller.pages[0] {
		t.Fatalf("pages/outbound = %#v/%#v", controller.pages, controller.outbound)
	}
	if size := gossip.MessageWireSize(controller.outbound[0].Message); size > controller.budget {
		t.Fatalf("catalog page size = %d, limit %d", size, controller.budget)
	}
}

func TestRuntimeExecuteGossipInboundRespondsToActivePingWhenQueueFull(t *testing.T) {
	runtime := NewRuntime(newFakeClock(time.Unix(100, 0)), 1, &memoryGossipStateStore{views: []corestate.View{loadedGossipState()}}, GossipRuntimeConfig{PeerID: "local.catofes.", Limits: corestate.DefaultSyncLimits()})
	defer runtime.Stop()
	runtime.Gossip.NewSession("peer-a")
	if err := runtime.PostGossip(&gossip.SyncTimerEvent{PeerID: "occupy"}); err != nil {
		t.Fatalf("fill queue: %v", err)
	}
	controller := &memoryInboundController{}
	packet := &gossip.Packet{Message: &gossip.Message{
		Type:   gossip.MessagePing,
		PeerID: "peer-a",
		Ping:   &gossip.Ping{Summary: &corestate.CatalogSummary{CatalogRoot: []byte("remote")}},
	}}
	if err := runtime.ExecuteGossipInbound(context.Background(), runtime.Gossip.PlanInbound(packet), controller); err != nil {
		t.Fatalf("ExecuteGossipInbound: %v", err)
	}
	if len(controller.outbound) == 0 || controller.outbound[0].Message.Type != gossip.MessagePong {
		t.Fatalf("outbound = %#v, want responder PONG", controller.outbound)
	}
	if len(controller.issues) != 1 || !errors.Is(controller.issues[0].Err, ErrEventQueueFull) {
		t.Fatalf("issues = %#v, want queue-full report", controller.issues)
	}
}
