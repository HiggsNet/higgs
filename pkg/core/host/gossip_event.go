package host

import (
	"context"
	"errors"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
)

type GossipEventController interface {
	GossipActionController
	ObserveGossipCatalogSummary(string, *corestate.CatalogSummary)
	ObserveGossipCatalogPage(string, *corestate.CatalogPage)
	FilterGossipCatalogPage(context.Context, string, *corestate.CatalogPage, time.Time) ([]corestate.ZoneDigest, *corestate.CatalogPage)
	ObserveGossipChunkRepair(string)
}

var (
	ErrGossipEventPeerRequired = errors.New("gossip event peer is required")
	ErrGossipSessionNotFound   = errors.New("gossip session not found")
)

// GossipEventResult is the platform-neutral outcome of advancing one session
// event and executing every action it produced.
type GossipEventResult struct {
	PeerID         string
	OldState       gossip.SyncSessionState
	NewState       gossip.SyncSessionState
	Pending        int
	Inflight       int
	Done           bool
	NetworkChanged bool
	ProtocolErr    error
}

// HandleGossipEvent is the single common bridge from Engine/FSM advancement
// to ordered HostRuntime effects. Platform code may enrich an event before
// calling it and observe the detached result afterwards, but cannot implement
// a second Engine-to-action loop.
func (runtime *Runtime) HandleGossipEvent(ctx context.Context, event gossip.SyncEvent, now time.Time, controller GossipEventController) (GossipEventResult, error) {
	var out GossipEventResult
	if runtime == nil {
		return out, ErrRuntimeStopped
	}
	if controller == nil {
		return out, ErrGossipControllerRequired
	}
	peerID := gossip.SyncEventPeerID(event)
	if peerID == "" {
		return out, ErrGossipEventPeerRequired
	}
	session := runtime.Gossip.Session(peerID)
	if session == nil {
		return out, ErrGossipSessionNotFound
	}
	if _, ok := event.(*gossip.RoundTimeoutEvent); ok {
		runtime.dropGossipPeerChunks(peerID)
	}
	if typed, ok := event.(*gossip.ChunkRepairTimeoutEvent); ok {
		nack := runtime.gossipChunks.BuildRepairNACK(peerID, typed.TransferID)
		out = GossipEventResult{PeerID: peerID, OldState: session.State, NewState: session.State, Pending: session.PendingCount(), Inflight: session.InflightCount(), Done: session.Done()}
		if nack == nil {
			return out, nil
		}
		err := controller.SendGossip(ctx, gossip.OutboundMessage{PeerID: peerID, Message: &gossip.Message{Type: gossip.MessageObjectChunkNACK, ObjectChunkNACK: nack}})
		if err != nil {
			controller.ReportGossipIssue(GossipExecutionIssue{Phase: GossipPhaseSend, PeerID: peerID, Err: err})
			return out, nil
		}
		controller.ObserveGossipChunkRepair(peerID)
		return out, nil
	}
	switch typed := event.(type) {
	case *gossip.PongReceivedEvent:
		if typed.Pong != nil && typed.Pong.Summary != nil {
			controller.ObserveGossipCatalogSummary(peerID, typed.Pong.Summary)
		}
	case *gossip.CatalogSummaryReceivedEvent:
		controller.ObserveGossipCatalogSummary(peerID, typed.Summary)
	case *gossip.CatalogPageReceivedEvent:
		typed.LocalEntries, typed.Page = controller.FilterGossipCatalogPage(ctx, peerID, typed.Page, now)
		controller.ObserveGossipCatalogPage(peerID, typed.Page)
	}
	engineResult := runtime.Gossip.HandleEvent(event, now)
	execution := runtime.ExecuteGossipActions(ctx, session, engineResult.Actions, controller)
	session.AccumulateNetworkChanged(execution.NetworkChanged)
	out = GossipEventResult{
		PeerID:         peerID,
		OldState:       engineResult.OldState,
		NewState:       session.State,
		Pending:        session.PendingCount(),
		Inflight:       session.InflightCount(),
		Done:           session.Done(),
		NetworkChanged: execution.NetworkChanged,
		ProtocolErr:    engineResult.Err,
	}
	return out, nil
}
