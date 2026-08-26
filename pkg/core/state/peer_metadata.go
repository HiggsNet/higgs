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

// PeerMetadataPatch is a replayable, typed peer-sync metadata mutation. It
// cannot modify verified Network state or install live session resources.
type PeerMetadataPatch struct {
	LastSyncUnix       PatchField[int64]
	LastAttemptUnix    PatchField[int64]
	BackoffUntilUnix   PatchField[int64]
	FailureCount       PatchField[int]
	LastError          PatchField[string]
	DiscoveredEndpoint PatchField[string]
	DiscoveredAtUnix   PatchField[int64]
	ObservedEndpoint   PatchField[string]
	ObservedUntilUnix  PatchField[int64]
	HintAccepted       PatchField[int64]
	HintSuppressed     PatchField[int64]
	Datagram           PatchField[PeerDatagramCounters]
	ObjectPull         PatchField[PeerObjectPullCounters]
	Reject             map[zone.ZonePath]RejectedObject
	ClearRejected      []zone.ZonePath
}

// UpdatePeerMetadata commits a metadata-only transaction. The verified
// revision and Network pointer are unaffected; Repository still observes the
// same commit-before-publish ordering as verified transactions.
func (store *Store) UpdatePeerMetadata(ctx context.Context, expected Revisions, peerID string, patch PeerMetadataPatch) (CommitResult, error) {
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
	baseRevisions := store.revisions
	candidate := cloneVerifiedState(store.state)
	store.mu.RUnlock()
	if expected != baseRevisions {
		return out, ErrVerifiedRevisionStale
	}

	before, existed := candidate.Peers[peerID]
	after := clonePeerSyncMetadata(before)
	applyPeerMetadataPatch(&after, patch)
	if (!existed && peerMetadataEmpty(after)) || (existed && reflect.DeepEqual(before, after)) {
		out.Changes.Revisions = baseRevisions
		return out, nil
	}
	candidate.Peers[peerID] = after
	nextRevisions := baseRevisions
	nextRevisions.Metadata++
	changes := ChangeSet{Revisions: nextRevisions, PeerMetadataChanged: true}
	if store.repository != nil {
		if err := store.repository.Commit(ctx, baseRevisions, cloneVerifiedState(candidate), changes); err != nil {
			return CommitResult{}, err
		}
	}
	store.mu.Lock()
	store.state = candidate
	store.revisions = nextRevisions
	store.mu.Unlock()
	return CommitResult{Committed: true, Changes: changes}, nil
}

func applyPeerMetadataPatch(metadata *PeerSyncMetadata, patch PeerMetadataPatch) {
	if metadata == nil {
		return
	}
	applyPatchField(&metadata.LastSyncUnix, patch.LastSyncUnix)
	applyPatchField(&metadata.LastAttemptUnix, patch.LastAttemptUnix)
	applyPatchField(&metadata.BackoffUntilUnix, patch.BackoffUntilUnix)
	applyPatchField(&metadata.FailureCount, patch.FailureCount)
	applyPatchField(&metadata.LastError, patch.LastError)
	applyPatchField(&metadata.DiscoveredEndpoint, patch.DiscoveredEndpoint)
	applyPatchField(&metadata.DiscoveredAtUnix, patch.DiscoveredAtUnix)
	applyPatchField(&metadata.ObservedEndpoint, patch.ObservedEndpoint)
	applyPatchField(&metadata.ObservedUntilUnix, patch.ObservedUntilUnix)
	applyPatchField(&metadata.HintAccepted, patch.HintAccepted)
	applyPatchField(&metadata.HintSuppressed, patch.HintSuppressed)
	applyPatchField(&metadata.Datagram, patch.Datagram)
	applyPatchField(&metadata.ObjectPull, patch.ObjectPull)
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

func clonePeerSyncMetadata(metadata PeerSyncMetadata) PeerSyncMetadata {
	out := metadata
	if metadata.RejectedObjects != nil {
		out.RejectedObjects = make(map[zone.ZonePath]RejectedObject, len(metadata.RejectedObjects))
		for path, rejected := range metadata.RejectedObjects {
			rejected.RootHash = append([]byte(nil), rejected.RootHash...)
			out.RejectedObjects[path] = rejected
		}
	}
	return out
}

func peerMetadataEmpty(metadata PeerSyncMetadata) bool {
	metadata.RejectedObjects = nil
	return reflect.DeepEqual(metadata, PeerSyncMetadata{})
}
