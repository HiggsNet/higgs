package state

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
)

var (
	ErrVerifiedRevisionStale = errors.New("verified state revision is stale")
	ErrSnapshotRootMismatch  = errors.New("snapshot root does not match advertised catalog digest")
	ErrVerifiedStoreClosed   = errors.New("verified state store is closed")
)

// VerifiedState is the platform-neutral persisted root owned by Store. It
// deliberately excludes controller observations such as SAs, routes, firewall
// rules, BIRD processes and tunnel handles.
type VerifiedState struct {
	ManagedZone     zone.ZonePath
	Network         *zone.NetworkState
	TrustedRootHash []byte
	// Private keys are intentionally part of the persisted local root. API,
	// observer and gossip projections must use DTOs that omit these fields.
	RootPrivateKey     ed25519.PrivateKey
	IdentityPrivateKey ed25519.PrivateKey
	Peers              map[string]PeerSyncMetadata
}

// PeerSyncMetadata contains only durable protocol metadata. Live sessions,
// timers, channels and worker state never belong in VerifiedState.
type PeerSyncMetadata struct {
	LastSyncUnix       int64
	LastAttemptUnix    int64
	BackoffUntilUnix   int64
	FailureCount       int
	LastError          string
	DiscoveredEndpoint string
	DiscoveredAtUnix   int64
	ObservedEndpoint   string
	ObservedUntilUnix  int64
	HintAccepted       int64
	HintSuppressed     int64
	Datagram           PeerDatagramCounters
	ObjectPull         PeerObjectPullCounters
	RejectedObjects    map[zone.ZonePath]RejectedObject
}

type PeerDatagramCounters struct {
	TooLargeDropped     int64
	DigestOnlyAnnounces int64
	ChunkFallbacks      int64
	ChunkRepairNACKs    int64
	ChunkRepairChunks   int64
}

type PeerObjectPullCounters struct {
	Attempts               int64
	Successes              int64
	Failures               int64
	LargeObjectUnreachable int64
}

type RejectedObject struct {
	RootHash    []byte
	Reason      string
	UpdatedUnix int64
}

type Revisions struct {
	Verified uint64
	Metadata uint64
}

// View is a detached read model. Callers may freely retain or mutate it.
type View struct {
	State     *VerifiedState
	Revisions Revisions
}

type ChangeSet struct {
	Revisions           Revisions
	ChangedZones        []zone.ZonePath
	NetworkChanged      bool
	PeerMetadataChanged bool
	SecurityPriority    bool
}

type CommitResult struct {
	Committed bool
	Changes   ChangeSet
}

type RemoteSnapshot struct {
	Snapshot     *ZoneSnapshot
	ExpectedRoot []byte
	Limits       SyncLimits
}

type RemoteApplyOutcome struct {
	Zone               zone.ZonePath
	Result             *ApplyResult
	ManagedZoneAdopted bool
	AuthorityRefreshed bool
	RejectReason       string
	Err                error
}

type RemoteBatchResult struct {
	CommitResult
	Outcomes []RemoteApplyOutcome
}

// Repository persists one complete detached candidate. Store calls Commit
// before publishing the candidate in memory. Implementations must treat the
// expected revisions as a CAS token and must not retain mutable pointers.
type Repository interface {
	Commit(context.Context, Revisions, *VerifiedState, ChangeSet) error
}

// Store is an in-memory single-owner verified aggregate. Its mutex protects
// readers and the CAS/publication boundary; verification and repository I/O
// run without holding the read lock.
type Store struct {
	writeMu    sync.Mutex
	mu         sync.RWMutex
	state      *VerifiedState
	revisions  Revisions
	repository Repository
	closed     bool
}

func NewStore(initial *VerifiedState, repository Repository) *Store {
	return &Store{state: cloneVerifiedState(initial), repository: repository}
}

func (store *Store) ReadView() View {
	if store == nil {
		return View{}
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	return View{State: cloneVerifiedState(store.state), Revisions: store.revisions}
}

func (store *Store) ZoneDigests() ([]ZoneDigest, Revisions) {
	if store == nil {
		return nil, Revisions{}
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	return ZoneDigests(store.state.Network), store.revisions
}

// ApplyRemoteBatch applies every item with an independent savepoint. A
// rejected item records bounded peer metadata and does not discard earlier or
// later successful items. Publication is one CAS commit for the whole batch.
func (store *Store) ApplyRemoteBatch(ctx context.Context, expected Revisions, peerID string, batch []RemoteSnapshot, now time.Time) (RemoteBatchResult, error) {
	var out RemoteBatchResult
	if store == nil {
		return out, ErrVerifiedStoreClosed
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
	base := cloneVerifiedState(store.state)
	store.mu.RUnlock()
	if expected != baseRevisions {
		return out, ErrVerifiedRevisionStale
	}

	candidate := base
	changedZones := make([]zone.ZonePath, 0, len(batch))
	metadataChanged := false
	for _, item := range batch {
		outcome := RemoteApplyOutcome{}
		if item.Snapshot != nil {
			outcome.Zone = item.Snapshot.Zone
		}
		if item.Snapshot == nil {
			outcome.Err = errors.New("zone snapshot is nil")
		} else if item.Snapshot.Zone == candidate.ManagedZone {
			// A remote peer never owns the managed Zone contents. Its parent
			// may update only the authority envelope through a delegation.
			out.Outcomes = append(out.Outcomes, outcome)
			continue
		} else if len(item.ExpectedRoot) > 0 {
			actual := ZoneRoot(ZoneStateFromSnapshot(item.Snapshot))
			if !bytes.Equal(actual, item.ExpectedRoot) {
				outcome.Err = fmt.Errorf("%w for %s: expected %x, received %x", ErrSnapshotRootMismatch, item.Snapshot.Zone, item.ExpectedRoot, actual)
			}
		}
		if outcome.Err == nil {
			next, result, err := ApplySnapshot(candidate.Network, item.Snapshot, now, item.Limits)
			if err != nil {
				outcome.Err = err
			} else {
				reconciled, managedResult, reconcileErr := ReconcileManagedAuthority(next, candidate.ManagedZone, identityPublicKey(candidate.IdentityPrivateKey), now)
				if reconcileErr != nil {
					outcome.Err = fmt.Errorf("reconcile managed zone authority: %w", reconcileErr)
				} else {
					candidate.Network = reconciled
					outcome.Result = result
					outcome.ManagedZoneAdopted = managedResult.Adopted
					outcome.AuthorityRefreshed = managedResult.Refreshed
					if result.NetworkChanged {
						changedZones = appendZoneOnce(changedZones, result.Zone)
					}
					if managedResult.Adopted || managedResult.Refreshed {
						changedZones = appendZoneOnce(changedZones, candidate.ManagedZone)
					}
					if clearRejectedObject(candidate, peerID, item.Snapshot.Zone) {
						metadataChanged = true
					}
				}
			}
		}
		if outcome.Err != nil {
			outcome.RejectReason = remoteRejectReason(outcome.Err)
			if item.Snapshot != nil && recordRejectedObject(candidate, peerID, item.Snapshot.Zone, rejectedRoot(item), outcome.RejectReason, now) {
				metadataChanged = true
			}
		}
		out.Outcomes = append(out.Outcomes, outcome)
	}

	networkChanged := len(changedZones) > 0
	if !networkChanged && !metadataChanged {
		out.Changes.Revisions = baseRevisions
		return out, nil
	}
	nextRevisions := baseRevisions
	if networkChanged {
		nextRevisions.Verified++
	}
	if metadataChanged {
		nextRevisions.Metadata++
	}
	changes := ChangeSet{
		Revisions:           nextRevisions,
		ChangedZones:        append([]zone.ZonePath(nil), changedZones...),
		NetworkChanged:      networkChanged,
		PeerMetadataChanged: metadataChanged,
	}

	store.mu.RLock()
	if store.closed {
		store.mu.RUnlock()
		return RemoteBatchResult{}, ErrVerifiedStoreClosed
	}
	if store.revisions != baseRevisions {
		store.mu.RUnlock()
		return RemoteBatchResult{}, ErrVerifiedRevisionStale
	}
	store.mu.RUnlock()
	if store.repository != nil {
		if err := store.repository.Commit(ctx, baseRevisions, cloneVerifiedState(candidate), changes); err != nil {
			return RemoteBatchResult{}, err
		}
	}
	store.mu.Lock()
	store.state = candidate
	store.revisions = nextRevisions
	store.mu.Unlock()
	out.Committed = true
	out.Changes = changes
	return out, nil
}

func (store *Store) Close() {
	if store == nil {
		return
	}
	store.writeMu.Lock()
	defer store.writeMu.Unlock()
	store.mu.Lock()
	store.closed = true
	store.mu.Unlock()
}

func cloneVerifiedState(value *VerifiedState) *VerifiedState {
	if value == nil {
		return &VerifiedState{Network: zone.NewNetworkState(), Peers: make(map[string]PeerSyncMetadata)}
	}
	out := &VerifiedState{
		ManagedZone:        value.ManagedZone,
		Network:            zone.CloneNetworkState(value.Network),
		TrustedRootHash:    append([]byte(nil), value.TrustedRootHash...),
		RootPrivateKey:     append(ed25519.PrivateKey(nil), value.RootPrivateKey...),
		IdentityPrivateKey: append(ed25519.PrivateKey(nil), value.IdentityPrivateKey...),
		Peers:              make(map[string]PeerSyncMetadata, len(value.Peers)),
	}
	if out.Network == nil {
		out.Network = zone.NewNetworkState()
	}
	for peerID, metadata := range value.Peers {
		cloned := metadata
		cloned.RejectedObjects = make(map[zone.ZonePath]RejectedObject, len(metadata.RejectedObjects))
		for path, rejected := range metadata.RejectedObjects {
			rejected.RootHash = append([]byte(nil), rejected.RootHash...)
			cloned.RejectedObjects[path] = rejected
		}
		out.Peers[peerID] = cloned
	}
	return out
}

func identityPublicKey(privateKey ed25519.PrivateKey) ed25519.PublicKey {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil
	}
	return append(ed25519.PublicKey(nil), privateKey.Public().(ed25519.PublicKey)...)
}

func appendZoneOnce(paths []zone.ZonePath, path zone.ZonePath) []zone.ZonePath {
	for _, existing := range paths {
		if existing == path {
			return paths
		}
	}
	return append(paths, path)
}

func rejectedRoot(item RemoteSnapshot) []byte {
	if len(item.ExpectedRoot) > 0 {
		return append([]byte(nil), item.ExpectedRoot...)
	}
	if item.Snapshot == nil {
		return nil
	}
	return ZoneRoot(ZoneStateFromSnapshot(item.Snapshot))
}

func remoteRejectReason(err error) string {
	if errors.Is(err, ErrSnapshotRootMismatch) {
		return "root_mismatch"
	}
	if errors.Is(err, ErrZoneSnapshotTooLarge) {
		return "snapshot_too_large"
	}
	if errors.Is(err, ErrUntrustedZone) {
		return "untrusted_zone"
	}
	return "invalid_snapshot"
}

func recordRejectedObject(state *VerifiedState, peerID string, path zone.ZonePath, root []byte, reason string, now time.Time) bool {
	if state == nil || peerID == "" || !path.Valid() {
		return false
	}
	metadata := state.Peers[peerID]
	if metadata.RejectedObjects == nil {
		metadata.RejectedObjects = make(map[zone.ZonePath]RejectedObject)
	}
	previous, ok := metadata.RejectedObjects[path]
	if ok && previous.Reason == reason && bytes.Equal(previous.RootHash, root) {
		return false
	}
	metadata.RejectedObjects[path] = RejectedObject{RootHash: append([]byte(nil), root...), Reason: reason, UpdatedUnix: now.Unix()}
	state.Peers[peerID] = metadata
	return true
}

func clearRejectedObject(state *VerifiedState, peerID string, path zone.ZonePath) bool {
	if state == nil || peerID == "" {
		return false
	}
	metadata, ok := state.Peers[peerID]
	if !ok || metadata.RejectedObjects == nil {
		return false
	}
	if _, ok := metadata.RejectedObjects[path]; !ok {
		return false
	}
	delete(metadata.RejectedObjects, path)
	state.Peers[peerID] = metadata
	return true
}
