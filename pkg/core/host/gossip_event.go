package host

import (
	"context"
	"errors"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
)

// GossipIO is the remaining platform datagram boundary. Runtime owns protocol
// state, scheduling, persistence, logging and observability; implementations
// only prepare ephemeral ingress routing and send encoded gossip messages.
type GossipIO interface {
	GossipSender
	GossipDatagramBudget() int
	PrepareGossipInbound(context.Context, *gossip.Packet, time.Time) error
}

// StartGossipSession creates and queues one common gossip pull session. It is
// also the only announce-hint suppression/defer boundary.
func (runtime *Runtime) StartGossipSession(peerID, reason string) error {
	if runtime == nil {
		return ErrRuntimeStopped
	}
	if peerID == "" {
		return nil
	}
	now := runtime.schedulerForRead().clock.Now()
	if runtime.Gossip.HasActiveSession(peerID) {
		runtime.Gossip.DeferHint(peerID)
		runtime.observeSyncHint(peerID, reason, "session_active", false, now)
		runtime.logGossip("debug", "announce_hint_suppressed", peerID, "session", nil, map[string]any{"reason": "session_active"})
		return nil
	}
	summary := runtime.GossipCatalogSummary()
	if summary == nil {
		return nil
	}
	session := runtime.Gossip.NewSession(peerID)
	if err := runtime.PostGossip(&gossip.SyncTimerEvent{PeerID: peerID, LocalSummary: summary}); err != nil {
		runtime.Gossip.RemoveSession(peerID)
		runtime.logGossip("warn", "event_dropped", peerID, "session", err, map[string]any{"reason": "sync_events_full"})
		return err
	}
	runtime.observeSyncHint(peerID, reason, "", true, now)
	runtime.observeActivePull(peerID, "hint_queued", session, now)
	runtime.logGossip("debug", "hinted_sync_started", peerID, "session", nil, map[string]any{"reason": reason})
	return nil
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

// GossipHostEventResult describes the common gossip work performed for one
// Runtime event. It does not expose the received packet or logging outcome;
// platform composition only observes session changes needed during migration.
type GossipHostEventResult struct {
	Handled bool
	Session GossipEventResult
}

// HandleGossipHostEvent is the only switch from Runtime queue events to the
// gossip inbound planner or session FSM. Packet, timer and object-pull
// completion producers therefore share one consumer on every platform.
func (runtime *Runtime) HandleGossipHostEvent(ctx context.Context, hostEvent Event, now time.Time, controller GossipIO) (GossipHostEventResult, error) {
	var out GossipHostEventResult
	if runtime == nil {
		return out, ErrRuntimeStopped
	}
	if controller == nil {
		return out, ErrGossipIORequired
	}
	if received, ok := hostEvent.(GossipPacketReceived); ok {
		out.Handled = true
		if received.Packet == nil {
			return out, nil
		}
		if err := controller.PrepareGossipInbound(ctx, received.Packet, now); err != nil {
			runtime.logGossipPacketFailure(received.Packet, err)
			return out, err
		}
		err := runtime.executeGossipPacketActions(ctx, runtime.Gossip.PlanInbound(received.Packet), controller)
		if err != nil {
			runtime.logGossipPacketFailure(received.Packet, err)
		}
		return out, err
	}
	event, ok := runtime.GossipSessionEventFor(hostEvent)
	if !ok {
		return out, nil
	}
	out.Handled = true
	result, err := runtime.handleGossipSessionEvent(ctx, event, now, controller)
	out.Session = result
	return out, err
}

func (runtime *Runtime) logGossipPacketFailure(packet *gossip.Packet, err error) {
	peerID := ""
	fields := map[string]any{"reason": gossip.RejectReason(err)}
	if packet != nil && packet.Message != nil {
		peerID = packet.Message.PeerID
		fields["type"] = packet.Message.Type
	}
	runtime.logGossip("warn", "packet_failed", peerID, "packet", err, fields)
}

// handleGossipSessionEvent is the internal bridge from Engine/FSM advancement
// to ordered HostRuntime effects. Platform code may enrich an event before
// calling it and observe the detached result afterwards, but cannot implement
// a second Engine-to-action loop.
func (runtime *Runtime) handleGossipSessionEvent(ctx context.Context, event gossip.SyncEvent, now time.Time, controller GossipSender) (GossipEventResult, error) {
	var out GossipEventResult
	if runtime == nil {
		return out, ErrRuntimeStopped
	}
	if controller == nil {
		return out, ErrGossipIORequired
	}
	peerID := gossip.SyncEventPeerID(event)
	if peerID == "" {
		runtime.logGossip("debug", "event_dropped", "", "session", ErrGossipEventPeerRequired, nil)
		return out, ErrGossipEventPeerRequired
	}
	session := runtime.Gossip.Session(peerID)
	if session == nil {
		runtime.logGossip("debug", "event_dropped", peerID, "session", ErrGossipSessionNotFound, nil)
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
			runtime.reportGossipIssue(GossipExecutionIssue{Phase: GossipPhaseSend, PeerID: peerID, Err: err})
			return out, nil
		}
		runtime.observeChunkRepair(peerID, false, 0, now)
		return out, nil
	}
	switch typed := event.(type) {
	case *gossip.PongReceivedEvent:
		if typed.Pong != nil && typed.Pong.Summary != nil {
			runtime.observeCatalogSummary(peerID, typed.Pong.Summary, now)
		}
	case *gossip.CatalogSummaryReceivedEvent:
		runtime.observeCatalogSummary(peerID, typed.Summary, now)
	case *gossip.CatalogPageReceivedEvent:
		typed.LocalEntries, typed.Page = FilterGossipCatalogPage(runtime.GossipDiscoveryInput(nil), peerID, typed.Page, now)
		runtime.observeCatalogPage(peerID, typed.Page, now)
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
	runtime.observeActivePull(peerID, gossip.SyncEventName(event), session, now)
	if out.ProtocolErr != nil {
		runtime.logGossip("warn", "session_event_error", peerID, "session", out.ProtocolErr, nil)
	}
	if out.NewState != out.OldState {
		runtime.logGossip("debug", "session_state_changed", peerID, "session", nil, map[string]any{
			"event": gossip.SyncEventName(event), "old_state": out.OldState, "new_state": out.NewState,
			"pending": out.Pending, "inflight": out.Inflight,
		})
	}
	return out, nil
}
