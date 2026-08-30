package host

import (
	"context"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
)

const GossipPhaseInbound = "inbound"

// executeGossipPacketActions executes the ordered decisions produced by
// gossip.PlanInboundPacket. Platforms no longer switch on InboundActionKind.
func (runtime *Runtime) executeGossipPacketActions(ctx context.Context, actions []gossip.InboundAction, sender GossipSender, budget int) error {
	if runtime == nil {
		return ErrRuntimeStopped
	}
	if sender == nil {
		return errGossipSenderRequired
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
			runtime.reportGossipIssue(GossipExecutionIssue{Phase: GossipPhaseInbound, PeerID: message.PeerID, Err: err})
			// An active PING must still receive its responder messages even if
			// its summary event encountered queue backpressure.
			if message.Type == gossip.MessagePing {
				continue
			}
			return err
		case gossip.InboundRespondPing:
			if err := runtime.respondGossipPing(ctx, action, sender); err != nil {
				return err
			}
		case gossip.InboundRespondFetchCatalogPage:
			runtime.respondGossipCatalogPage(ctx, message, sender, budget)
		case gossip.InboundRespondFetchZone:
			if err := runtime.respondGossipFetchZone(ctx, message.PeerID, message.FetchZone, sender, budget); err != nil {
				return err
			}
		case gossip.InboundHandleAnnounce:
			if err := runtime.StartGossipSession(message.PeerID, "announce_hint"); err != nil {
				return err
			}
		case gossip.InboundHandleObjectChunk:
			result, err := runtime.HandleGossipObjectChunk(ctx, message, runtime.schedulerForRead().clock.Now())
			if result.CheckpointErr != nil {
				runtime.logGossip("warn", "chunk_reject_state_commit_failed", result.PeerID, "checkpoint", result.CheckpointErr, map[string]any{"zone": result.Zone})
			}
			if result.ChunkFallback {
				runtime.observeChunkFallback(result.PeerID, 1, runtime.schedulerForRead().clock.Now())
			}
			if err != nil {
				return err
			}
		case gossip.InboundHandleObjectChunkNACK:
			if err := runtime.handleGossipObjectChunkNACK(ctx, message, sender); err != nil {
				return err
			}
		}
	}
	return nil
}

func (runtime *Runtime) respondGossipPing(ctx context.Context, action gossip.InboundAction, sender GossipSender) error {
	message := action.Message
	if message == nil || message.Ping == nil {
		return nil
	}
	view := runtime.gossipStateView()
	if !view.Loaded {
		return nil
	}
	summary := corestate.CatalogSummaryForDigests(view.Digests)
	runtime.observeCatalogSummary(message.PeerID, summary, runtime.schedulerForRead().clock.Now())
	for _, response := range gossip.PlanPingResponse(message.Ping, summary) {
		if err := sender.SendGossip(ctx, gossip.OutboundMessage{PeerID: message.PeerID, Message: response}); err != nil {
			runtime.reportGossipIssue(GossipExecutionIssue{Phase: GossipPhaseSend, PeerID: message.PeerID, Err: err})
		}
	}
	if action.ActiveSession || message.Ping.Summary == nil {
		return nil
	}
	if !gossip.CatalogRootsMatch(message.Ping.Summary, summary) {
		return runtime.StartGossipSession(message.PeerID, "announce_hint")
	}
	if err := runtime.commitGossipEventCheckpoint(ctx, &gossip.SyncSession{PeerID: message.PeerID, State: gossip.SyncSessionCompleted}, nil, runtime.schedulerForRead().clock.Now()); err != nil {
		return err
	}
	runtime.observeSyncHint(message.PeerID, "ping_summary_match", "", true, runtime.schedulerForRead().clock.Now())
	runtime.logGossip("debug", "ping_summary_shortcut", message.PeerID, "session", nil, map[string]any{"reason": "catalog_root_match"})
	return nil
}

func (runtime *Runtime) respondGossipCatalogPage(ctx context.Context, message *gossip.Message, sender GossipSender, budget int) {
	if message == nil || message.FetchCatalogPage == nil {
		return
	}
	view := runtime.gossipStateView()
	if !view.Loaded {
		return
	}
	cursor := message.FetchCatalogPage.Cursor
	page, err := gossip.CatalogPageForDigests(view.Digests, cursor, budget, view.SenderPeerID)
	if err != nil {
		runtime.observeDatagramTooLarge(message.PeerID, "catalog_page", "", "", 0, budget, runtime.schedulerForRead().clock.Now())
		runtime.observeCatalogReject(message.PeerID, cursor, gossip.RejectReason(err), runtime.schedulerForRead().clock.Now())
		runtime.logGossip("warn", "catalog_page_failed", message.PeerID, "responder", err, map[string]any{"cursor": cursor})
		return
	}
	runtime.observeCatalogPage(message.PeerID, page, runtime.schedulerForRead().clock.Now())
	runtime.observeReadOnlyResponder(message.PeerID, "catalog_page", "", runtime.schedulerForRead().clock.Now())
	if err := sender.SendGossip(ctx, gossip.OutboundMessage{
		PeerID: message.PeerID,
		Message: &gossip.Message{
			Type:        gossip.MessageCatalogPage,
			CatalogPage: page,
		},
	}); err != nil {
		runtime.reportGossipIssue(GossipExecutionIssue{Phase: GossipPhaseSend, PeerID: message.PeerID, Err: err})
	}
}
