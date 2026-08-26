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
}

// GossipCheckpoint is a loss-tolerant restart hint. None of its fields may be
// required for signature verification, authorization or eventual convergence.
// Live sessions, timers, cursors, chunk assembly and in-flight pulls belong to
// gossip.Engine/HostRuntime memory and are deliberately absent here.
type GossipCheckpoint struct {
	Peers map[string]PeerCheckpoint
}

// PeerCheckpoint contains only restart hints that affect retry/discovery
// efficiency. Pure diagnostics and counters belong in observability stores.
type PeerCheckpoint struct {
	LastSyncUnix            int64
	LastAttemptUnix         int64
	BackoffUntilUnix        int64
	FailureCount            int
	LastRelayUnix           int64
	LastRelayCatalogRootHex string
	LastRelaySuppressedAt   int64
	DiscoveredEndpoint      string
	DiscoveredAtUnix        int64
	ObservedEndpoint        string
	ObservedFirstSeenUnix   int64
	ObservedLastSeenUnix    int64
	ObservedLastSyncUnix    int64
	ObservedUntilUnix       int64
	ObservedFailureCount    int
	ObservedGraceEndpoints  []ObservedGraceEndpoint
	RejectedObjects         map[zone.ZonePath]RejectedObject
}

type ObservedGraceEndpoint struct {
	Endpoint  string
	UntilUnix int64
}

type RejectedObject struct {
	RootHash    []byte
	Reason      string
	UpdatedUnix int64
	UntilUnix   int64
}

// CommitCandidate is the atomic common-state repository candidate. Verified facts and the
// loss-tolerant gossip checkpoint remain distinct sub-roots.
type CommitCandidate struct {
	Verified *VerifiedState
	Gossip   *GossipCheckpoint
}

type Revisions struct {
	Verified   uint64
	Checkpoint uint64
}

// View is a detached read model. Callers may freely retain or mutate it.
type View struct {
	State     *VerifiedState
	Gossip    *GossipCheckpoint
	Revisions Revisions
}

type ChangeSet struct {
	Revisions               Revisions
	ChangedZones            []zone.ZonePath
	NetworkChanged          bool
	GossipCheckpointChanged bool
	SecurityPriority        bool
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
	Commit(context.Context, Revisions, *CommitCandidate, ChangeSet) error
}

// Store is an in-memory single-owner common-state aggregate. Verified facts
// and loss-tolerant gossip checkpoints are separate sub-roots. Its mutex protects
// readers and the CAS/publication boundary; verification and repository I/O
// run without holding the read lock.
type Store struct {
	writeMu    sync.Mutex
	mu         sync.RWMutex
	state      *VerifiedState
	gossip     *GossipCheckpoint
	revisions  Revisions
	repository Repository
	closed     bool
}

func NewStore(initial *VerifiedState, repository Repository) *Store {
	return NewStoreWithCheckpoint(initial, nil, repository)
}

func NewStoreWithCheckpoint(initial *VerifiedState, checkpoint *GossipCheckpoint, repository Repository) *Store {
	return &Store{state: cloneVerifiedState(initial), gossip: cloneGossipCheckpoint(checkpoint), repository: repository}
}

func (store *Store) ReadView() View {
	if store == nil {
		return View{}
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	return View{State: cloneVerifiedState(store.state), Gossip: cloneGossipCheckpoint(store.gossip), Revisions: store.revisions}
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
// rejected item records a bounded peer checkpoint and does not discard earlier or
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
	baseGossip := cloneGossipCheckpoint(store.gossip)
	store.mu.RUnlock()
	if expected != baseRevisions {
		return out, ErrVerifiedRevisionStale
	}

	candidate := base
	gossipCandidate := baseGossip
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
					if clearRejectedObject(gossipCandidate, peerID, item.Snapshot.Zone) {
						metadataChanged = true
					}
				}
			}
		}
		if outcome.Err != nil {
			outcome.RejectReason = remoteRejectReason(outcome.Err)
			if item.Snapshot != nil && recordRejectedObject(gossipCandidate, peerID, item.Snapshot.Zone, rejectedRoot(item), outcome.RejectReason, now) {
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
		nextRevisions.Checkpoint++
	}
	changes := ChangeSet{
		Revisions:               nextRevisions,
		ChangedZones:            append([]zone.ZonePath(nil), changedZones...),
		NetworkChanged:          networkChanged,
		GossipCheckpointChanged: metadataChanged,
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
		if err := store.repository.Commit(ctx, baseRevisions, cloneCommitCandidate(candidate, gossipCandidate), changes); err != nil {
			return RemoteBatchResult{}, err
		}
	}
	store.mu.Lock()
	store.state = candidate
	store.gossip = gossipCandidate
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
		return &VerifiedState{Network: zone.NewNetworkState()}
	}
	out := &VerifiedState{
		ManagedZone:        value.ManagedZone,
		Network:            zone.CloneNetworkState(value.Network),
		TrustedRootHash:    append([]byte(nil), value.TrustedRootHash...),
		RootPrivateKey:     append(ed25519.PrivateKey(nil), value.RootPrivateKey...),
		IdentityPrivateKey: append(ed25519.PrivateKey(nil), value.IdentityPrivateKey...),
	}
	if out.Network == nil {
		out.Network = zone.NewNetworkState()
	}
	return out
}

func cloneGossipCheckpoint(value *GossipCheckpoint) *GossipCheckpoint {
	out := &GossipCheckpoint{Peers: make(map[string]PeerCheckpoint)}
	if value == nil {
		return out
	}
	for peerID, metadata := range value.Peers {
		out.Peers[peerID] = clonePeerCheckpoint(metadata)
	}
	return out
}

func cloneCommitCandidate(verified *VerifiedState, gossip *GossipCheckpoint) *CommitCandidate {
	return &CommitCandidate{Verified: cloneVerifiedState(verified), Gossip: cloneGossipCheckpoint(gossip)}
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

func recordRejectedObject(state *GossipCheckpoint, peerID string, path zone.ZonePath, root []byte, reason string, now time.Time) bool {
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

func clearRejectedObject(state *GossipCheckpoint, peerID string, path zone.ZonePath) bool {
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
