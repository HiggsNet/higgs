package host

import (
	"context"
	"errors"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

// RecordGossipObservedPath persists one authenticated packet source after
// validating it against the Runtime's current verified state.
func (runtime *Runtime) RecordGossipObservedPath(ctx context.Context, peerID, endpoint string, suppressed map[string]bool, now time.Time) (bool, error) {
	if runtime == nil || runtime.gossipState == nil {
		return false, ErrRuntimeStopped
	}
	patch, ok := PlanVerifiedObservedCheckpoint(runtime.GossipDiscoveryInput(suppressed), peerID, endpoint, now)
	if !ok {
		return false, nil
	}
	_, err := runtime.gossipState.UpdatePeerCheckpoints(ctx, map[string]corestate.PeerCheckpointPatch{peerID: patch})
	return err == nil, err
}

// RecordGossipRejectedObject stores a bounded retry-suppression hint for a
// chunk whose advertised object could not be decoded or verified.
func (runtime *Runtime) RecordGossipRejectedObject(ctx context.Context, peerID string, chunk *gossip.ObjectChunk, rejection error, now time.Time) error {
	if runtime == nil || runtime.gossipState == nil {
		return ErrRuntimeStopped
	}
	if peerID == "" || chunk == nil || chunk.Object != gossip.ObjectPullZone || !chunk.Zone.Valid() || len(chunk.RootHash) == 0 {
		return nil
	}
	reason := gossip.RejectReason(rejection)
	if reason == "" {
		reason = "verify_failed"
	}
	_, err := runtime.gossipState.UpdatePeerCheckpoints(ctx, map[string]corestate.PeerCheckpointPatch{peerID: {
		Reject: map[zone.ZonePath]corestate.RejectedObject{chunk.Zone: {
			RootHash: append([]byte(nil), chunk.RootHash...), Reason: reason,
			UpdatedUnix: now.Unix(), UntilUnix: now.Add(corestate.RejectedObjectTTL).Unix(),
		}},
	}})
	return err
}

// RecordGossipRelay persists relay throttling state without reading or
// rewriting unrelated peer checkpoint fields.
func (runtime *Runtime) RecordGossipRelay(ctx context.Context, peerID, catalogRoot string, now time.Time) (bool, error) {
	if runtime == nil || runtime.gossipState == nil {
		return false, ErrRuntimeStopped
	}
	if peerID == "" {
		return false, errors.New("gossip relay peer is required")
	}
	result, err := runtime.gossipState.UpdatePeerCheckpoints(ctx, map[string]corestate.PeerCheckpointPatch{peerID: {
		LastRelayUnix:    corestate.PatchField[int64]{Set: true, Value: now.Unix()},
		LastRelayRootHex: corestate.PatchField[string]{Set: true, Value: catalogRoot},
	}})
	return result.Committed, err
}

// commitGossipEventCheckpoint folds every restart-hint mutation produced by
// one FSM event into one checkpoint-only Store transaction. Backoff actions
// retain protocol order and terminal completion is applied last, matching the
// session's final outcome without involving a platform mutation batch.
func (runtime *Runtime) commitGossipEventCheckpoint(ctx context.Context, session *gossip.SyncSession, backoffs []gossip.RecordBackoffAction, now time.Time) error {
	if runtime == nil || runtime.gossipState == nil {
		return nil
	}
	if len(backoffs) == 0 && (session == nil || !session.Done()) {
		return nil
	}
	view := runtime.gossipState.ReadView()
	peers := make(map[string]corestate.PeerCheckpoint)
	patches := make(map[string]corestate.PeerCheckpointPatch)
	if view.Gossip != nil {
		for peerID, checkpoint := range view.Gossip.Peers {
			peers[peerID] = checkpoint
		}
	}
	for _, action := range backoffs {
		if action.PeerID == "" {
			continue
		}
		peer := peers[action.PeerID]
		applyGossipBackoffCheckpoint(&peer, action.Err, now)
		peers[action.PeerID] = peer
		patch := patches[action.PeerID]
		patch.LastAttemptUnix = corestate.PatchField[int64]{Set: true, Value: peer.LastAttemptUnix}
		patch.BackoffUntilUnix = corestate.PatchField[int64]{Set: true, Value: peer.BackoffUntilUnix}
		if action.Err != nil {
			patch.LastFailure = corestate.PatchField[*corestate.PeerFailure]{Set: true, Value: peer.LastFailure}
		}
		patches[action.PeerID] = patch
	}
	if session != nil && session.Done() && session.PeerID != "" {
		peer := peers[session.PeerID]
		applyGossipCompletionCheckpoint(&peer, session.LastError(), now)
		peers[session.PeerID] = peer
		patch := patches[session.PeerID]
		patch.LastAttemptUnix = corestate.PatchField[int64]{Set: true, Value: peer.LastAttemptUnix}
		patch.BackoffUntilUnix = corestate.PatchField[int64]{Set: true, Value: peer.BackoffUntilUnix}
		patch.FailureCount = corestate.PatchField[int]{Set: true, Value: peer.FailureCount}
		patch.LastFailure = corestate.PatchField[*corestate.PeerFailure]{Set: true, Value: peer.LastFailure}
		if session.LastError() == nil {
			patch.LastSyncUnix = corestate.PatchField[int64]{Set: true, Value: peer.LastSyncUnix}
			if peer.ObservedEndpoint != "" && peer.ObservedUntilUnix != 0 && now.Before(time.Unix(peer.ObservedUntilUnix, 0)) {
				patch.ObservedSyncUnix = corestate.PatchField[int64]{Set: true, Value: peer.ObservedLastSyncUnix}
				patch.ObservedFailures = corestate.PatchField[int]{Set: true, Value: peer.ObservedFailureCount}
			}
		}
		patches[session.PeerID] = patch
	}
	_, err := runtime.gossipState.UpdatePeerCheckpoints(ctx, patches)
	return err
}

func applyGossipCompletionCheckpoint(peer *corestate.PeerCheckpoint, syncErr error, now time.Time) {
	peer.LastAttemptUnix = now.Unix()
	if syncErr != nil {
		peer.FailureCount++
		peer.BackoffUntilUnix = now.Add(gossipFailureBackoff(peer.FailureCount)).Unix()
		peer.LastFailure = &corestate.PeerFailure{Code: corestate.PeerFailureUnknown, Message: syncErr.Error(), AtUnix: now.Unix()}
		return
	}
	peer.LastSyncUnix = now.Unix()
	peer.BackoffUntilUnix = 0
	peer.FailureCount = 0
	peer.LastFailure = nil
	if peer.ObservedEndpoint != "" && peer.ObservedUntilUnix != 0 && now.Before(time.Unix(peer.ObservedUntilUnix, 0)) {
		peer.ObservedLastSyncUnix = now.Unix()
		peer.ObservedFailureCount = 0
	}
}

func applyGossipBackoffCheckpoint(peer *corestate.PeerCheckpoint, actionErr error, now time.Time) {
	peer.LastAttemptUnix = now.Unix()
	if actionErr != nil {
		peer.LastFailure = &corestate.PeerFailure{Code: corestate.PeerFailureUnknown, Message: actionErr.Error(), AtUnix: now.Unix()}
	}
	peer.BackoffUntilUnix = now.Add(gossipFailureBackoff(peer.FailureCount)).Unix()
}

func gossipFailureBackoff(failures int) time.Duration {
	if failures > 6 {
		failures = 6
	}
	if failures < 0 {
		failures = 0
	}
	return time.Duration(1<<failures) * time.Second
}
