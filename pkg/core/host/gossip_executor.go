package host

import (
	"context"
	"errors"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
)

const (
	GossipPhaseStateRead   = "state_read"
	GossipPhaseApply       = "snapshot_apply"
	GossipPhaseSend        = "send"
	GossipPhaseObjectPull  = "object_pull"
	GossipPhaseTimer       = "timer"
	GossipPhaseBackoff     = "backoff"
	GossipPhasePersistence = "persistence"
)

var ErrGossipControllerRequired = errors.New("gossip action controller is required")

// GossipStateView is the bounded read projection required by the common
// executor after snapshot application. It never exposes a live state root.
type GossipStateView struct {
	Loaded       bool
	Digests      []corestate.ZoneDigest
	SenderPeerID string
}

// GossipSnapshotApplyResult reports the two independent consequences of a
// snapshot batch: committed metadata may require persistence even when no
// verified network object was accepted.
type GossipSnapshotApplyResult struct {
	StateCommitted bool
	NetworkChanged bool
}

// GossipCompletionIntent is detached sync metadata emitted with a terminal
// persistence action.
type GossipCompletionIntent struct {
	PeerID string
	Err    error
}

// GossipExecutionIssue reports a failed effect without making platform
// logging part of protocol policy.
type GossipExecutionIssue struct {
	Phase  string
	PeerID string
	Err    error
}

// GossipActionController is the platform/runtime-state capability boundary.
// Implementations perform effects but never reinterpret SyncAction types or
// reorder phases.
type GossipActionController interface {
	GossipStateView(context.Context) GossipStateView
	ApplyGossipSnapshots(context.Context, string, []gossip.ApplySnapshotAction) (GossipSnapshotApplyResult, error)
	SendGossip(context.Context, gossip.OutboundMessage) error
	RecordGossipBackoffs(context.Context, []gossip.RecordBackoffAction) error
	PersistGossip(context.Context, GossipPersistenceIntent, *GossipCompletionIntent) error
	ReportGossipIssue(GossipExecutionIssue)
}

// GossipExecutionResult is the common executor outcome consumed by the host
// event loop. Aborted means state read/apply failed and later effects were not
// executed.
type GossipExecutionResult struct {
	NetworkChanged bool
	Aborted        bool
}

// ExecuteGossipActions owns the shared effect ordering for one FSM event:
// read/apply, refresh/reconcile, send, object pull, timer, backoff and
// persistence. Controllers supply capabilities only.
func (runtime *Runtime) ExecuteGossipActions(
	ctx context.Context,
	session *gossip.SyncSession,
	actions []gossip.SyncAction,
	controller GossipActionController,
) GossipExecutionResult {
	var result GossipExecutionResult
	if runtime == nil || controller == nil {
		if controller != nil {
			controller.ReportGossipIssue(GossipExecutionIssue{Phase: GossipPhaseStateRead, Err: ErrRuntimeStopped})
		}
		result.Aborted = true
		return result
	}
	if ctx == nil {
		ctx = context.Background()
	}
	view := controller.GossipStateView(ctx)
	if !view.Loaded {
		return result
	}

	plan := PlanGossipActions(actions)
	applyResult := GossipSnapshotApplyResult{}
	if len(plan.Snapshots) > 0 {
		peerID := ""
		if session != nil {
			peerID = session.PeerID
		}
		var err error
		applyResult, err = controller.ApplyGossipSnapshots(ctx, peerID, plan.Snapshots)
		if err != nil {
			controller.ReportGossipIssue(GossipExecutionIssue{Phase: GossipPhaseApply, PeerID: peerID, Err: err})
			result.Aborted = true
			return result
		}
		result.NetworkChanged = applyResult.NetworkChanged
		if result.NetworkChanged {
			view = controller.GossipStateView(ctx)
			if !view.Loaded {
				controller.ReportGossipIssue(GossipExecutionIssue{Phase: GossipPhaseStateRead, PeerID: peerID, Err: errors.New("gossip state unavailable after snapshot apply")})
				result.Aborted = true
				return result
			}
		}
	}

	if session != nil && !session.Done() && view.Loaded {
		actions = append(actions, session.ReconcilePendingWithDigests(view.Digests)...)
		plan = PlanGossipActions(actions)
	}

	for _, outbound := range plan.Outbound {
		if err := controller.SendGossip(ctx, outbound); err != nil {
			controller.ReportGossipIssue(GossipExecutionIssue{Phase: GossipPhaseSend, PeerID: outbound.PeerID, Err: err})
		}
	}
	for _, pull := range plan.ObjectPulls {
		if err := runtime.SubmitGossipObjectPull(pull); err != nil {
			controller.ReportGossipIssue(GossipExecutionIssue{Phase: GossipPhaseObjectPull, PeerID: pull.PeerID, Err: err})
			_ = runtime.PostGossipObjectPullCompletion(GossipObjectPullCompletion{PeerID: pull.PeerID, Zone: pull.Zone, Err: err})
		}
	}
	for _, timer := range plan.Timers {
		if _, err := runtime.ApplyGossipTimerAction(timer); err != nil {
			controller.ReportGossipIssue(GossipExecutionIssue{Phase: GossipPhaseTimer, PeerID: syncActionPeerID(timer), Err: err})
		}
	}
	if len(plan.Backoffs) > 0 {
		if err := controller.RecordGossipBackoffs(ctx, plan.Backoffs); err != nil {
			controller.ReportGossipIssue(GossipExecutionIssue{Phase: GossipPhaseBackoff, PeerID: plan.Backoffs[0].PeerID, Err: err})
		}
	}

	intent := plan.Persistence
	if applyResult.StateCommitted {
		if !intent.Requested {
			intent.Requested = true
			intent.Scope = gossip.SyncPersistenceMeta
			intent.Reason = "snapshot_batch"
		}
	}
	if result.NetworkChanged {
		intent.Requested = true
		intent.Scope = gossip.SyncPersistenceNetwork
		if intent.Reason == "" {
			intent.Reason = "snapshot_batch"
		}
	}
	if intent.Requested {
		var completion *GossipCompletionIntent
		if session != nil && session.Done() {
			completion = &GossipCompletionIntent{PeerID: session.PeerID, Err: session.LastError()}
		}
		if err := controller.PersistGossip(ctx, intent, completion); err != nil {
			peerID := ""
			if session != nil {
				peerID = session.PeerID
			}
			controller.ReportGossipIssue(GossipExecutionIssue{Phase: GossipPhasePersistence, PeerID: peerID, Err: err})
		}
	}
	return result
}

func syncActionPeerID(action gossip.SyncAction) string {
	switch typed := action.(type) {
	case gossip.StartTimerAction:
		return typed.PeerID
	case gossip.CancelTimerAction:
		return typed.PeerID
	default:
		return ""
	}
}
