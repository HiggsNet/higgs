package host

import (
	"context"
	"errors"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

// GossipStateStore is the common committed-state dependency owned by one
// HostRuntime. Platform composition may serialize this store with its own
// runtime bucket, but it must not reinterpret the returned verified state or
// maintain a second gossip projection.
type GossipStateStore interface {
	ReadView() corestate.View
	ApplyRemoteBatch(context.Context, string, []corestate.RemoteSnapshot, time.Time) (corestate.RemoteBatchResult, error)
	UpdatePeerCheckpoints(context.Context, map[string]corestate.PeerCheckpointPatch) (corestate.CommitResult, error)
}

// GossipRuntimeConfig contains platform-neutral values fixed when one
// HostRuntime is constructed. Socket addresses and platform handles do not
// belong here.
type GossipRuntimeConfig struct {
	PeerID    string
	Limits    corestate.SyncLimits
	Discovery GossipDiscoveryConfig
	Log       func(GossipRuntimeLog)
}

type GossipRuntimeLog struct {
	Level  string
	Event  string
	PeerID string
	Phase  string
	Err    error
	Fields map[string]any
}

func (runtime *Runtime) logGossip(level, event, peerID, phase string, err error, fields map[string]any) {
	if runtime != nil && runtime.gossipConfig.Log != nil {
		runtime.gossipConfig.Log(GossipRuntimeLog{Level: level, Event: event, PeerID: peerID, Phase: phase, Err: err, Fields: fields})
	}
}

func (runtime *Runtime) reportGossipIssue(issue GossipExecutionIssue) {
	event := "gossip_effect_failed"
	switch issue.Phase {
	case GossipPhaseApply:
		event = "snapshot_batch_commit_failed"
	case GossipPhaseInbound:
		event = "event_dropped"
	case GossipPhaseTimer:
		event = "timer_action_failed"
	case GossipPhasePersistence:
		event = "save_failed"
	}
	runtime.logGossip("warn", event, issue.PeerID, issue.Phase, issue.Err, nil)
}

// GossipSnapshotObservation is detached diagnostic output from the common
// remote-state transaction. It cannot alter commit ordering or protocol state.
type GossipSnapshotObservation struct {
	PeerID         string
	ManagedZone    zone.ZonePath
	Action         gossip.ApplySnapshotAction
	Outcome        corestate.RemoteApplyOutcome
	SkippedOwnZone bool
}

func (runtime *Runtime) gossipStateView() GossipStateView {
	if runtime == nil || runtime.gossipState == nil {
		return GossipStateView{}
	}
	view := runtime.gossipState.ReadView()
	if view.State == nil || view.State.Network == nil {
		return GossipStateView{}
	}
	return GossipStateView{
		Loaded:       true,
		ManagedZone:  view.State.ManagedZone,
		Digests:      corestate.ZoneDigests(view.State.Network),
		SenderPeerID: runtime.gossipConfig.PeerID,
	}
}

// GossipCatalogSummary returns the current committed catalog summary without
// exposing the verified Network back to platform orchestration.
func (runtime *Runtime) GossipCatalogSummary() *corestate.CatalogSummary {
	view := runtime.gossipStateView()
	if !view.Loaded {
		return nil
	}
	return corestate.CatalogSummaryForDigests(view.Digests)
}

func (runtime *Runtime) applyGossipSnapshots(
	ctx context.Context,
	peerID string,
	actions []gossip.ApplySnapshotAction,
	view GossipStateView,
	controller GossipActionController,
) (GossipSnapshotApplyResult, error) {
	if runtime == nil || runtime.gossipState == nil {
		return GossipSnapshotApplyResult{}, errors.New("gossip state store is not configured")
	}
	managedZone := view.ManagedZone
	selected := make([]gossip.ApplySnapshotAction, 0, len(actions))
	batch := make([]corestate.RemoteSnapshot, 0, len(actions))
	for _, action := range actions {
		if action.Snapshot == nil {
			continue
		}
		if action.Snapshot.Zone == managedZone {
			controller.ObserveGossipSnapshot(GossipSnapshotObservation{PeerID: peerID, ManagedZone: managedZone, Action: action, SkippedOwnZone: true})
			continue
		}
		limits := runtime.gossipConfig.Limits
		if limits.MaxZones <= 0 || limits.MaxRecords <= 0 || limits.MaxBytes <= 0 {
			limits = corestate.DefaultSyncLimits()
		}
		if action.RelaxedLimits {
			limits.MaxBytes = 8 << 20
		}
		selected = append(selected, action)
		batch = append(batch, corestate.RemoteSnapshot{
			Snapshot: action.Snapshot, ExpectedRoot: append([]byte(nil), action.ExpectedRoot...), Limits: limits,
		})
	}
	if len(batch) == 0 {
		return GossipSnapshotApplyResult{}, nil
	}
	result, err := runtime.gossipState.ApplyRemoteBatch(ctx, peerID, batch, runtime.schedulerForRead().clock.Now())
	if err != nil {
		return GossipSnapshotApplyResult{}, err
	}
	for index, action := range selected {
		outcome := corestate.RemoteApplyOutcome{Zone: action.Snapshot.Zone}
		if index < len(result.Outcomes) {
			outcome = result.Outcomes[index]
		} else {
			outcome.Err = errors.New("snapshot apply produced no outcome")
		}
		controller.ObserveGossipSnapshot(GossipSnapshotObservation{PeerID: peerID, ManagedZone: managedZone, Action: action, Outcome: outcome})
		if action.ReportResult {
			_ = runtime.PostGossip(&gossip.SnapshotAppliedEvent{PeerID: peerID, Zone: action.Snapshot.Zone, Err: outcome.Err})
		}
	}
	return GossipSnapshotApplyResult{NetworkChanged: result.Changes.NetworkChanged}, nil
}
