package state

import (
	"context"
	"errors"
	"reflect"

	"github.com/HiggsNet/photon/pkg/core/zone"
)

// PatchField distinguishes an omitted field from an explicit zero value.
type PatchField[T any] struct {
	Set   bool
	Value T
}

// PeerCheckpointPatch is a replayable, typed restart-hint mutation. It
// cannot modify verified Network state or install live session resources.
type PeerCheckpointPatch struct {
	LastSyncUnix       PatchField[int64]
	LastAttemptUnix    PatchField[int64]
	BackoffUntilUnix   PatchField[int64]
	FailureCount       PatchField[int]
	LastRelayUnix      PatchField[int64]
	LastRelayRootHex   PatchField[string]
	DiscoveredEndpoint PatchField[string]
	DiscoveredAtUnix   PatchField[int64]
	ObservedEndpoint   PatchField[string]
	ObservedFirstUnix  PatchField[int64]
	ObservedLastUnix   PatchField[int64]
	ObservedSyncUnix   PatchField[int64]
	ObservedUntilUnix  PatchField[int64]
	ObservedFailures   PatchField[int]
	ObservedGrace      PatchField[[]ObservedGraceEndpoint]
	LastFailure        PatchField[*PeerFailure]
	Reject             map[zone.ZonePath]RejectedObject
	ClearRejected      []zone.ZonePath
}

// UpdatePeerCheckpoint commits a loss-tolerant checkpoint transaction. The verified
// revision and Network pointer are unaffected; persistence callback still observes the
// same commit-before-publish ordering as verified transactions.
func (store *Store) UpdatePeerCheckpoint(ctx context.Context, peerID string, patch PeerCheckpointPatch) (CommitResult, error) {
	var out CommitResult
	if store == nil {
		return out, ErrVerifiedStoreClosed
	}
	if peerID == "" {
		return out, errors.New("peer id is empty")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	store.writeMu.Lock()
	defer store.writeMu.Unlock()

	store.mu.RLock()
	if store.closed {
		store.mu.RUnlock()
		return out, ErrVerifiedStoreClosed
	}
	baseRevision := store.revision
	verified := cloneVerifiedState(store.state)
	candidate := cloneGossipCheckpoint(store.gossip)
	store.mu.RUnlock()
	before, existed := candidate.Peers[peerID]
	after := clonePeerCheckpoint(before)
	applyPeerCheckpointPatch(&after, patch)
	if (!existed && peerCheckpointEmpty(after)) || (existed && reflect.DeepEqual(before, after)) {
		out.Changes.VerifiedRevision = baseRevision
		return out, nil
	}
	candidate.Peers[peerID] = after
	changes := ChangeSet{VerifiedRevision: baseRevision, GossipCheckpointChanged: true}
	if store.commit != nil {
		if err := store.commit(ctx, cloneCommitCandidate(verified, candidate), changes); err != nil {
			return CommitResult{}, err
		}
	}
	store.mu.Lock()
	store.gossip = candidate
	store.mu.Unlock()
	return CommitResult{Committed: true, Changes: changes}, nil
}

func applyPeerCheckpointPatch(metadata *PeerCheckpoint, patch PeerCheckpointPatch) {
	if metadata == nil {
		return
	}
	applyPatchField(&metadata.LastSyncUnix, patch.LastSyncUnix)
	applyPatchField(&metadata.LastAttemptUnix, patch.LastAttemptUnix)
	applyPatchField(&metadata.BackoffUntilUnix, patch.BackoffUntilUnix)
	applyPatchField(&metadata.FailureCount, patch.FailureCount)
	applyPatchField(&metadata.LastRelayUnix, patch.LastRelayUnix)
	applyPatchField(&metadata.LastRelayCatalogRootHex, patch.LastRelayRootHex)
	applyPatchField(&metadata.DiscoveredEndpoint, patch.DiscoveredEndpoint)
	applyPatchField(&metadata.DiscoveredAtUnix, patch.DiscoveredAtUnix)
	applyPatchField(&metadata.ObservedEndpoint, patch.ObservedEndpoint)
	applyPatchField(&metadata.ObservedFirstSeenUnix, patch.ObservedFirstUnix)
	applyPatchField(&metadata.ObservedLastSeenUnix, patch.ObservedLastUnix)
	applyPatchField(&metadata.ObservedLastSyncUnix, patch.ObservedSyncUnix)
	applyPatchField(&metadata.ObservedUntilUnix, patch.ObservedUntilUnix)
	applyPatchField(&metadata.ObservedFailureCount, patch.ObservedFailures)
	if patch.ObservedGrace.Set {
		metadata.ObservedGraceEndpoints = append([]ObservedGraceEndpoint(nil), patch.ObservedGrace.Value...)
	}
	if patch.LastFailure.Set {
		metadata.LastFailure = clonePeerFailure(patch.LastFailure.Value)
	}
	if len(patch.Reject) > 0 && metadata.RejectedObjects == nil {
		metadata.RejectedObjects = make(map[zone.ZonePath]RejectedObject, len(patch.Reject))
	}
	for path, rejected := range patch.Reject {
		if !path.Valid() {
			continue
		}
		rejected.RootHash = append([]byte(nil), rejected.RootHash...)
		metadata.RejectedObjects[path] = rejected
	}
	for _, path := range patch.ClearRejected {
		delete(metadata.RejectedObjects, path)
	}
}

func applyPatchField[T any](target *T, field PatchField[T]) {
	if field.Set {
		*target = field.Value
	}
}

func clonePeerCheckpoint(metadata PeerCheckpoint) PeerCheckpoint {
	out := metadata
	out.LastFailure = clonePeerFailure(metadata.LastFailure)
	out.ObservedGraceEndpoints = append([]ObservedGraceEndpoint(nil), metadata.ObservedGraceEndpoints...)
	if metadata.RejectedObjects != nil {
		out.RejectedObjects = make(map[zone.ZonePath]RejectedObject, len(metadata.RejectedObjects))
		for path, rejected := range metadata.RejectedObjects {
			rejected.RootHash = append([]byte(nil), rejected.RootHash...)
			out.RejectedObjects[path] = rejected
		}
	}
	return out
}

func clonePeerFailure(failure *PeerFailure) *PeerFailure {
	if failure == nil {
		return nil
	}
	out := *failure
	return &out
}

func peerCheckpointEmpty(metadata PeerCheckpoint) bool {
	metadata.ObservedGraceEndpoints = nil
	metadata.RejectedObjects = nil
	return reflect.DeepEqual(metadata, PeerCheckpoint{})
}
