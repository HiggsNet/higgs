package host

import (
	"context"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
)

const GossipPhaseInbound = "inbound"

// GossipInboundController extends the common state/send capabilities with the
// remaining host effects required by verified inbound packets. Ping and
// catalog response protocol logic stays in this package and pkg/core/gossip.
type GossipInboundController interface {
	GossipStateView(context.Context) GossipStateView
	GossipDatagramBudget() int
	SendGossip(context.Context, gossip.OutboundMessage) error
	ObserveGossipCatalogSummary(string, *corestate.CatalogSummary)
	ObserveGossipCatalogPage(string, *corestate.CatalogPage)
	ObserveGossipCatalogReject(string, string, error)
	RecordGossipSummaryMatch(context.Context, string) error
	HandleGossipAnnounceHint(context.Context, string) error
	RespondGossipFetchZone(context.Context, string, *gossip.FetchZone) error
	HandleGossipObjectChunk(context.Context, *gossip.Message) error
	HandleGossipObjectChunkNACK(context.Context, *gossip.Message) error
	ReportGossipIssue(GossipExecutionIssue)
}

// ExecuteGossipInbound executes the ordered decisions produced by
// gossip.PlanInboundPacket. Platforms no longer switch on InboundActionKind.
func (runtime *Runtime) ExecuteGossipInbound(ctx context.Context, actions []gossip.InboundAction, controller GossipInboundController) error {
	if runtime == nil {
		return ErrRuntimeStopped
	}
	if controller == nil {
		return ErrGossipControllerRequired
	}
	if ctx == nil {
		ctx = context.Background()
	}
	for _, action := range actions {
		message := action.Message
		if message == nil {
			continue
		}
		switch action.Kind {
		case gossip.InboundPostSessionEvent:
			err := runtime.PostGossip(action.Event)
			if err == nil {
				continue
			}
			controller.ReportGossipIssue(GossipExecutionIssue{Phase: GossipPhaseInbound, PeerID: message.PeerID, Err: err})
			// An active PING must still receive its responder messages even if
			// its summary event encountered queue backpressure.
			if message.Type == gossip.MessagePing {
				continue
			}
			return err
		case gossip.InboundRespondPing:
			if err := runtime.respondGossipPing(ctx, action, controller); err != nil {
				return err
			}
		case gossip.InboundRespondFetchCatalogPage:
			runtime.respondGossipCatalogPage(ctx, message, controller)
		case gossip.InboundRespondFetchZone:
			if err := controller.RespondGossipFetchZone(ctx, message.PeerID, message.FetchZone); err != nil {
				return err
			}
		case gossip.InboundHandleAnnounce:
			if err := controller.HandleGossipAnnounceHint(ctx, message.PeerID); err != nil {
				return err
			}
		case gossip.InboundHandleObjectChunk:
			if err := controller.HandleGossipObjectChunk(ctx, message); err != nil {
				return err
			}
		case gossip.InboundHandleObjectChunkNACK:
			if err := controller.HandleGossipObjectChunkNACK(ctx, message); err != nil {
				return err
			}
		}
	}
	return nil
}

func (runtime *Runtime) respondGossipPing(ctx context.Context, action gossip.InboundAction, controller GossipInboundController) error {
	message := action.Message
	if message == nil || message.Ping == nil {
		return nil
	}
	view := controller.GossipStateView(ctx)
	if !view.Loaded {
		return nil
	}
	summary := corestate.CatalogSummaryForDigests(view.Digests)
	controller.ObserveGossipCatalogSummary(message.PeerID, summary)
	for _, response := range gossip.PlanPingResponse(message.Ping, summary) {
		if err := controller.SendGossip(ctx, gossip.OutboundMessage{PeerID: message.PeerID, Message: response}); err != nil {
			controller.ReportGossipIssue(GossipExecutionIssue{Phase: GossipPhaseSend, PeerID: message.PeerID, Err: err})
		}
	}
	if action.ActiveSession || message.Ping.Summary == nil {
		return nil
	}
	if !gossip.CatalogRootsMatch(message.Ping.Summary, summary) {
		return controller.HandleGossipAnnounceHint(ctx, message.PeerID)
	}
	return controller.RecordGossipSummaryMatch(ctx, message.PeerID)
}

func (runtime *Runtime) respondGossipCatalogPage(ctx context.Context, message *gossip.Message, controller GossipInboundController) {
	if message == nil || message.FetchCatalogPage == nil {
		return
	}
	view := controller.GossipStateView(ctx)
	if !view.Loaded {
		return
	}
	cursor := message.FetchCatalogPage.Cursor
	page, err := gossip.CatalogPageForDigests(view.Digests, cursor, controller.GossipDatagramBudget())
	if err != nil {
		controller.ObserveGossipCatalogReject(message.PeerID, cursor, err)
		return
	}
	controller.ObserveGossipCatalogPage(message.PeerID, page)
	if err := controller.SendGossip(ctx, gossip.OutboundMessage{
		PeerID: message.PeerID,
		Message: &gossip.Message{
			Type:        gossip.MessageCatalogPage,
			CatalogPage: page,
		},
	}); err != nil {
		controller.ReportGossipIssue(GossipExecutionIssue{Phase: GossipPhaseSend, PeerID: message.PeerID, Err: err})
	}
}
