package main

import (
	"context"
	"errors"
	"maps"
	"reflect"
	"sync"
	"time"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

var errDaemonStateRevisionStale = errors.New("daemon state revision is stale")

const maxSyncPeerUpdateAttempts = 4

type daemonDirtyFlags struct {
	IPsec    bool `json:"ipsec,omitempty"`
	Routing  bool `json:"routing,omitempty"`
	Firewall bool `json:"firewall,omitempty"`
}

type daemonReconcileStatus struct {
	IPsec    bool `json:"ipsec,omitempty"`
	Routing  bool `json:"routing,omitempty"`
	Firewall bool `json:"firewall,omitempty"`
}

type daemonStateStoreMeta struct {
	Revision          uint64
	SnapshotTime      time.Time
	Dirty             daemonDirtyFlags
	ReconcileProgress daemonReconcileStatus
}

type DaemonStateStore struct {
	writeMu           sync.Mutex
	mu                sync.RWMutex
	committed         *stateFile
	common            *corestate.Store
	runtime           *linuxRuntimeState
	commitRuntime     func(corestate.VerifiedRevision, *linuxRuntimeState) error
	revision          uint64
	snapshotTime      time.Time
	dirty             daemonDirtyFlags
	reconcileProgress daemonReconcileStatus
	now               func() time.Time
}

type DaemonStateUpdate struct {
	store   *DaemonStateStore
	baseRev uint64
	state   *stateFile
	closed  bool
}

type syncPeerMutationView struct {
	ManagedZone  zone.ZonePath
	Network      *zone.NetworkState
	SyncPeers    map[string]syncPeerState
	PeerCleanups map[string]peerLifecycleCleanupState
}

func NewDaemonStateStore(initial *stateFile) *DaemonStateStore {
	store := &DaemonStateStore{now: time.Now}
	store.ReplaceCommitted(initial)
	return store
}

// NewComposedDaemonStateStore creates the E-stage Linux composition boundary.
// committed is only a detached compatibility read view; common and runtime are
// its owners. Legacy stateFile writers are rejected in this mode so the view
// cannot silently become a second source of truth.
func NewComposedDaemonStateStore(common *corestate.Store, runtime *linuxRuntimeState) (*DaemonStateStore, error) {
	return newComposedDaemonStateStore(common, runtime, nil)
}

func newPersistedComposedDaemonStateStore(common *corestate.Store, runtime *linuxRuntimeState, boltStore *corestate.BoltStore) (*DaemonStateStore, error) {
	if boltStore == nil {
		return nil, errors.New("bbolt state store is nil")
	}
	return newComposedDaemonStateStore(common, runtime, func(revision corestate.VerifiedRevision, candidate *linuxRuntimeState) error {
		return commitLinuxRuntime(boltStore, revision, candidate)
	})
}

func newComposedDaemonStateStore(common *corestate.Store, runtime *linuxRuntimeState, commitRuntime func(corestate.VerifiedRevision, *linuxRuntimeState) error) (*DaemonStateStore, error) {
	if common == nil {
		return nil, errors.New("common state store is nil")
	}
	store := &DaemonStateStore{
		common:        common,
		runtime:       cloneLinuxRuntimeState(runtime),
		commitRuntime: commitRuntime,
		now:           time.Now,
	}
	store.refreshComposedView()
	if store.committed == nil {
		return nil, errors.New("composed daemon state is nil")
	}
	return store, nil
}

// ApplyCommonLocalIntent is the only common writer exposed by the first
// composition cut. Store performs validation/signing/persistence; only after
// successful publication do we refresh the detached Linux compatibility view.
func (s *DaemonStateStore) ApplyCommonLocalIntent(ctx context.Context, intent corestate.LocalIntent, dryRun bool, now time.Time) (corestate.LocalIntentResult, error) {
	if s == nil || s.common == nil {
		return corestate.LocalIntentResult{}, errors.New("daemon common state store is not initialized")
	}
	if dryRun {
		return s.common.PreviewLocalIntent(intent, now)
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	result, err := s.common.ApplyLocalIntent(ctx, intent, now)
	if err != nil {
		return corestate.LocalIntentResult{}, err
	}
	if result.Committed {
		s.refreshComposedView()
	}
	return result, nil
}

func (s *DaemonStateStore) ApplyCommonRemoteBatch(ctx context.Context, peerID string, batch []corestate.RemoteSnapshot, now time.Time) (corestate.RemoteBatchResult, error) {
	if s == nil || s.common == nil {
		return corestate.RemoteBatchResult{}, errors.New("daemon common state store is not initialized")
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	result, err := s.common.ApplyRemoteBatch(ctx, peerID, batch, now)
	if err != nil {
		return corestate.RemoteBatchResult{}, err
	}
	if result.Committed {
		s.refreshComposedView()
	}
	return result, nil
}

func (s *DaemonStateStore) UpdateCommonPeerCheckpoint(ctx context.Context, peerID string, patch corestate.PeerCheckpointPatch) (corestate.CommitResult, error) {
	if s == nil || s.common == nil {
		return corestate.CommitResult{}, errors.New("daemon common state store is not initialized")
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	result, err := s.common.UpdatePeerCheckpoint(ctx, peerID, patch)
	if err != nil {
		return corestate.CommitResult{}, err
	}
	if result.Committed {
		s.refreshComposedView()
	}
	return result, nil
}

func (s *DaemonStateStore) commitComposedRuntime(sourceRevision uint64, mutate func(*linuxRuntimeState)) (uint64, bool, error) {
	if s == nil || s.common == nil {
		return 0, false, errors.New("daemon composed state is not initialized")
	}
	if mutate == nil {
		return sourceRevision, false, errors.New("Linux runtime mutation is nil")
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.mu.RLock()
	currentRevision := s.revision
	baseRuntime := cloneLinuxRuntimeState(s.runtime)
	s.mu.RUnlock()
	if currentRevision != sourceRevision {
		return currentRevision, false, nil
	}
	candidate := cloneLinuxRuntimeState(baseRuntime)
	mutate(candidate)
	if reflect.DeepEqual(baseRuntime, candidate) {
		return sourceRevision, false, nil
	}
	if s.commitRuntime != nil {
		if err := s.commitRuntime(corestate.VerifiedRevision(sourceRevision), cloneLinuxRuntimeState(candidate)); err != nil {
			return sourceRevision, false, err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.revision != sourceRevision {
		return s.revision, false, errDaemonStateRevisionStale
	}
	s.runtime = candidate
	commonView := s.common.ReadView()
	s.committed = composeLinuxStateView(commonView, s.runtime)
	if s.now != nil {
		s.snapshotTime = s.now()
	} else {
		s.snapshotTime = time.Now()
	}
	return s.revision, true, nil
}

func (s *DaemonStateStore) commitComposedRoutingIfRevision(revision uint64, birdInstances map[string]*BirdInstanceState, reconcile *routingReconcileState) (uint64, bool, error) {
	return s.commitComposedRuntime(revision, func(runtime *linuxRuntimeState) {
		runtime.BirdInstances = cloneBirdInstances(birdInstances)
		runtime.RoutingReconcile = cloneRoutingReconcileState(reconcile)
	})
}

func (s *DaemonStateStore) commitComposedIPsecIfRevision(revision uint64, transportKey *ipsecTransportKeyState, portRecord *ipsecPortRecordState, linkInstances map[string]linkInstanceState, reconcile *ipsecReconcileState) (uint64, bool, error) {
	return s.commitComposedRuntime(revision, func(runtime *linuxRuntimeState) {
		runtime.IPsecTransportKey = cloneIPsecTransportKeyState(transportKey)
		runtime.IPsecPortRecord = cloneIPsecPortRecordState(portRecord)
		runtime.LinkInstances = cloneLinkInstances(linkInstances)
		runtime.IPsecReconcile = cloneIPsecReconcileState(reconcile)
	})
}

func (s *DaemonStateStore) commitComposedFirewallIfRevision(revision uint64, endpointACLs map[string]endpointACL, reconcile *firewallReconcileState) (uint64, bool, error) {
	return s.commitComposedRuntime(revision, func(runtime *linuxRuntimeState) {
		runtime.EndpointACLs = cloneEndpointACLs(endpointACLs)
		runtime.FirewallReconcile = cloneFirewallReconcileState(reconcile)
	})
}

func (s *DaemonStateStore) refreshComposedView() {
	if s == nil || s.common == nil {
		return
	}
	commonView := s.common.ReadView()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.committed = composeLinuxStateView(commonView, s.runtime)
	s.revision = uint64(commonView.Revision)
	if s.now != nil {
		s.snapshotTime = s.now()
	} else {
		s.snapshotTime = time.Now()
	}
}

func (s *DaemonStateStore) legacyWritable() bool {
	return s != nil && s.common == nil
}

func (s *DaemonStateStore) Snapshot() (*stateFile, uint64) {
	if s == nil {
		return nil, 0
	}
	s.mu.RLock()
	committed := s.committed
	rev := s.revision
	s.mu.RUnlock()
	return cloneStateFile(committed), rev
}

// routingSnapshot returns a routing-owned workspace without serializing the
// complete daemon state. Network and unrelated children remain shared and must
// be treated as immutable. The fields routing reconcile mutates are detached.
func (s *DaemonStateStore) routingSnapshot() (*stateFile, uint64) {
	if s == nil {
		return nil, 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.committed == nil {
		return nil, s.revision
	}
	snapshot := cloneStateFileRootSharingChildren(s.committed)
	snapshot.BirdInstances = cloneBirdInstances(s.committed.BirdInstances)
	snapshot.RoutingReconcile = cloneRoutingReconcileState(s.committed.RoutingReconcile)
	return snapshot, s.revision
}

// ipsecSnapshot returns a workspace that owns the complete IPsec field family.
// Network and unrelated controller state remain shared and read-only.
func (s *DaemonStateStore) ipsecSnapshot() (*stateFile, uint64) {
	if s == nil {
		return nil, 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.committed == nil {
		return nil, s.revision
	}
	snapshot := cloneStateFileRootSharingChildren(s.committed)
	snapshot.IPsecTransportKey = cloneIPsecTransportKeyState(s.committed.IPsecTransportKey)
	snapshot.IPsecPortRecord = cloneIPsecPortRecordState(s.committed.IPsecPortRecord)
	snapshot.LinkInstances = cloneLinkInstances(s.committed.LinkInstances)
	snapshot.IPsecReconcile = cloneIPsecReconcileState(s.committed.IPsecReconcile)
	return snapshot, s.revision
}

// firewallSnapshot returns a workspace that owns the complete firewall field
// family. Network and unrelated controller state remain shared and read-only.
func (s *DaemonStateStore) firewallSnapshot() (*stateFile, uint64) {
	if s == nil {
		return nil, 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.committed == nil {
		return nil, s.revision
	}
	snapshot := cloneStateFileRootSharingChildren(s.committed)
	snapshot.EndpointACLs = cloneEndpointACLs(s.committed.EndpointACLs)
	snapshot.FirewallReconcile = cloneFirewallReconcileState(s.committed.FirewallReconcile)
	return snapshot, s.revision
}

// networkZoneSnapshot returns a workspace that owns exactly one mutable zone.
// An empty path selects the committed managed zone. All other state children
// and Network zones remain shared and read-only.
func (s *DaemonStateStore) networkZoneSnapshot(path zone.ZonePath) (*stateFile, uint64) {
	if s == nil {
		return nil, 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.committed == nil {
		return nil, s.revision
	}
	if path == "" {
		path = s.committed.ManagedZone
	}
	workspace := cloneStateFileRootSharingChildren(s.committed)
	workspace.Network = zone.CloneNetworkStateForZone(s.committed.Network, path)
	if workspace.Network != nil {
		configureValidation(workspace.Network)
	}
	return workspace, s.revision
}

// snapshotApplyWorkspace returns an isolated root for one batch of snapshot
// actions. Network starts shared and immutable; each successful ApplySnapshot
// replaces it with a target-zone COW candidate. SyncPeers and Admission are
// detached because accepted/rejected snapshot bookkeeping mutates them.
func (s *DaemonStateStore) snapshotApplyWorkspace() (*stateFile, uint64) {
	if s == nil {
		return nil, 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.committed == nil {
		return nil, s.revision
	}
	workspace := cloneStateFileRootSharingChildren(s.committed)
	workspace.SyncPeers = cloneSyncPeers(s.committed.SyncPeers)
	workspace.Admission = cloneAdmissionState(s.committed.Admission)
	return workspace, s.revision
}

// ZoneDigests returns a detached digest projection of the committed state.
// It keeps the state pointer private and avoids cloning the complete Network
// for callers that only need its gossip digest.
func (s *DaemonStateStore) ZoneDigests() []corestate.ZoneDigest {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.committed == nil {
		return nil
	}
	return corestate.ZoneDigests(s.committed.Network)
}

func (s *DaemonStateStore) Meta() daemonStateStoreMeta {
	if s == nil {
		return daemonStateStoreMeta{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.metaLocked()
}

func (s *DaemonStateStore) BeginUpdate() (*DaemonStateUpdate, error) {
	if s == nil {
		return nil, errors.New("daemon state store is nil")
	}
	if !s.legacyWritable() {
		return nil, errors.New("legacy daemon state writer is disabled for composed state")
	}
	s.mu.RLock()
	committed := s.committed
	update := &DaemonStateUpdate{
		store:   s,
		baseRev: s.revision,
	}
	s.mu.RUnlock()
	update.state = cloneStateFile(committed)
	return update, nil
}

func (u *DaemonStateUpdate) BaseRevision() uint64 {
	if u == nil {
		return 0
	}
	return u.baseRev
}

func (u *DaemonStateUpdate) Workspace() *stateFile {
	if u == nil {
		return nil
	}
	return u.state
}

func (u *DaemonStateUpdate) Commit() (uint64, bool, error) {
	if u == nil || u.store == nil {
		return 0, false, errors.New("daemon state update is nil")
	}
	if u.closed {
		return 0, false, errors.New("daemon state update is already closed")
	}
	u.closed = true
	return u.store.commitWorkspaceIfRevision(u.baseRev, u.state)
}

func (s *DaemonStateStore) Update(fn func(*stateFile) error) (uint64, error) {
	if fn == nil {
		return 0, errors.New("daemon state update function is nil")
	}
	update, err := s.BeginUpdate()
	if err != nil {
		return 0, err
	}
	if err := fn(update.Workspace()); err != nil {
		return update.BaseRevision(), err
	}
	rev, committed, err := update.Commit()
	if err != nil {
		return rev, err
	}
	if !committed {
		return rev, errDaemonStateRevisionStale
	}
	return rev, nil
}

// UpdateSyncPeer applies a replayable mutation to one peer using local
// copy-on-write. It retains the global revision/CAS ordering while sharing the
// immutable Network and unrelated state blocks. fn may be called more than once
// after a stale revision and must not perform external side effects.
//
// The mutable peer passed to fn and all of its nested mutable values are
// detached again before commit, so retaining the callback pointer cannot mutate
// committed state.
func (s *DaemonStateStore) UpdateSyncPeer(peerID string, fn func(*syncPeerState) error) (uint64, error) {
	if s == nil {
		return 0, errors.New("daemon state store is nil")
	}
	if !s.legacyWritable() {
		return s.Meta().Revision, errors.New("legacy daemon peer writer is disabled for composed state")
	}
	if fn == nil {
		return 0, errors.New("sync peer update function is nil")
	}
	return s.updateSyncPeerWithView(peerID, func(_ syncPeerMutationView, peer *syncPeerState) error {
		return fn(peer)
	})
}

// updateSyncPeerWithView additionally supplies the immutable fields needed to
// derive a peer mutation from the same revision. The view is rebuilt for every
// CAS retry; callers must not mutate or retain values from the view.
func (s *DaemonStateStore) updateSyncPeerWithView(peerID string, fn func(syncPeerMutationView, *syncPeerState) error) (uint64, error) {
	if s == nil {
		return 0, errors.New("daemon state store is nil")
	}
	if !s.legacyWritable() {
		return s.Meta().Revision, errors.New("legacy daemon peer writer is disabled for composed state")
	}
	if peerID == "" {
		return 0, errors.New("sync peer id is empty")
	}
	if fn == nil {
		return 0, errors.New("sync peer update function is nil")
	}
	var currentRev uint64
	for range maxSyncPeerUpdateAttempts {
		s.mu.RLock()
		base := s.committed
		baseRev := s.revision
		var peer syncPeerState
		if base != nil && base.SyncPeers != nil {
			peer = cloneSyncPeerState(base.SyncPeers[peerID])
		}
		view := syncPeerMutationView{}
		if base != nil {
			view.ManagedZone = base.ManagedZone
			view.Network = base.Network
			view.SyncPeers = base.SyncPeers
			view.PeerCleanups = base.PeerCleanups
		}
		s.mu.RUnlock()

		if err := fn(view, &peer); err != nil {
			return baseRev, err
		}
		committedPeer := cloneSyncPeerState(peer)

		next := cloneStateFileRootSharingChildren(base)
		next.SyncPeers = make(map[string]syncPeerState)
		if base != nil && base.SyncPeers != nil {
			next.SyncPeers = make(map[string]syncPeerState, len(base.SyncPeers)+1)
			maps.Copy(next.SyncPeers, base.SyncPeers)
		}
		next.SyncPeers[peerID] = committedPeer
		if cleanup, ok := view.PeerCleanups[peerID]; ok && committedPeer.LastSyncUnix > cleanup.LastActiveUnix {
			next.PeerCleanups = maps.Clone(view.PeerCleanups)
			delete(next.PeerCleanups, peerID)
		}

		s.mu.Lock()
		if s.revision == baseRev {
			s.commitLocked(next)
			currentRev = s.revision
			s.mu.Unlock()
			return currentRev, nil
		}
		currentRev = s.revision
		s.mu.Unlock()
	}
	return currentRev, errDaemonStateRevisionStale
}

// updateSyncPeersWithView applies a replayable batch of peer replacements using
// local copy-on-write. The callback receives an immutable view from one
// revision and returns only the peers that should be replaced. Network and
// unrelated state blocks remain structurally shared. fn may be retried and
// must not mutate or retain any value from the view.
func (s *DaemonStateStore) updateSyncPeersWithView(fn func(syncPeerMutationView) (map[string]syncPeerState, error)) (uint64, bool, error) {
	if s == nil {
		return 0, false, errors.New("daemon state store is nil")
	}
	if !s.legacyWritable() {
		return s.Meta().Revision, false, errors.New("legacy daemon peer writer is disabled for composed state")
	}
	if fn == nil {
		return 0, false, errors.New("sync peers update function is nil")
	}
	var currentRev uint64
	for range maxSyncPeerUpdateAttempts {
		s.mu.RLock()
		base := s.committed
		baseRev := s.revision
		view := syncPeerMutationView{}
		if base != nil {
			view.ManagedZone = base.ManagedZone
			view.Network = base.Network
			view.SyncPeers = base.SyncPeers
			view.PeerCleanups = base.PeerCleanups
		}
		s.mu.RUnlock()
		updates, err := fn(view)
		if err != nil {
			return baseRev, false, err
		}
		if len(updates) == 0 {
			s.mu.RLock()
			if s.revision == baseRev {
				s.mu.RUnlock()
				return baseRev, false, nil
			}
			currentRev = s.revision
			s.mu.RUnlock()
			continue
		}

		next := cloneStateFileRootSharingChildren(base)
		next.SyncPeers = make(map[string]syncPeerState, len(view.SyncPeers)+len(updates))
		maps.Copy(next.SyncPeers, view.SyncPeers)
		for id, state := range updates {
			if id == "" {
				return baseRev, false, errors.New("sync peer id is empty")
			}
			next.SyncPeers[id] = cloneSyncPeerState(state)
		}

		s.mu.Lock()
		if s.revision == baseRev {
			s.commitLocked(next)
			currentRev = s.revision
			s.mu.Unlock()
			return currentRev, true, nil
		}
		currentRev = s.revision
		s.mu.Unlock()
	}
	return currentRev, false, errDaemonStateRevisionStale
}

func (s *DaemonStateStore) CommitIfRevision(rev uint64, fn func(*stateFile) error) (uint64, bool, error) {
	if s == nil {
		return 0, false, errors.New("daemon state store is nil")
	}
	if !s.legacyWritable() {
		return s.Meta().Revision, false, errors.New("legacy daemon state writer is disabled for composed state")
	}
	if fn == nil {
		return 0, false, errors.New("daemon state commit function is nil")
	}
	s.mu.RLock()
	if s.revision != rev {
		currentRev := s.revision
		s.mu.RUnlock()
		return currentRev, false, nil
	}
	committed := s.committed
	s.mu.RUnlock()
	next := cloneStateFile(committed)
	if err := fn(next); err != nil {
		return rev, false, err
	}
	return s.commitWorkspaceIfRevision(rev, next)
}

// commitRoutingIfRevision replaces only routing-owned state. It preserves the
// immutable Network and all unrelated state blocks by structural sharing.
func (s *DaemonStateStore) commitRoutingIfRevision(rev uint64, birdInstances map[string]*BirdInstanceState, reconcile *routingReconcileState) (uint64, bool) {
	if s == nil {
		return 0, false
	}
	if !s.legacyWritable() {
		return s.Meta().Revision, false
	}
	nextBirdInstances := cloneBirdInstances(birdInstances)
	nextReconcile := cloneRoutingReconcileState(reconcile)

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.revision != rev {
		return s.revision, false
	}
	next := cloneStateFileRootSharingChildren(s.committed)
	next.BirdInstances = nextBirdInstances
	next.RoutingReconcile = nextReconcile
	s.commitLocked(next)
	return s.revision, true
}

// commitIPsecIfRevision replaces the complete IPsec-owned field family. A
// stale global revision discards the complete result.
func (s *DaemonStateStore) commitIPsecIfRevision(rev uint64, transportKey *ipsecTransportKeyState, portRecord *ipsecPortRecordState, linkInstances map[string]linkInstanceState, reconcile *ipsecReconcileState) (uint64, bool) {
	if s == nil {
		return 0, false
	}
	if !s.legacyWritable() {
		return s.Meta().Revision, false
	}
	nextTransportKey := cloneIPsecTransportKeyState(transportKey)
	nextPortRecord := cloneIPsecPortRecordState(portRecord)
	nextLinkInstances := cloneLinkInstances(linkInstances)
	nextReconcile := cloneIPsecReconcileState(reconcile)

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.revision != rev {
		return s.revision, false
	}
	next := cloneStateFileRootSharingChildren(s.committed)
	next.IPsecTransportKey = nextTransportKey
	next.IPsecPortRecord = nextPortRecord
	next.LinkInstances = nextLinkInstances
	next.IPsecReconcile = nextReconcile
	s.commitLocked(next)
	return s.revision, true
}

// commitFirewallIfRevision replaces only firewall-owned state. A stale global
// revision discards the complete result instead of retrying it on a newer root.
func (s *DaemonStateStore) commitFirewallIfRevision(rev uint64, endpointACLs map[string]endpointACL, reconcile *firewallReconcileState) (uint64, bool) {
	if s == nil {
		return 0, false
	}
	if !s.legacyWritable() {
		return s.Meta().Revision, false
	}
	nextEndpointACLs := cloneEndpointACLs(endpointACLs)
	nextReconcile := cloneFirewallReconcileState(reconcile)

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.revision != rev {
		return s.revision, false
	}
	next := cloneStateFileRootSharingChildren(s.committed)
	next.EndpointACLs = nextEndpointACLs
	next.FirewallReconcile = nextReconcile
	s.commitLocked(next)
	return s.revision, true
}

// commitNetworkCandidateIfRevision transfers ownership of a detached Network
// COW candidate into the committed root without cloning it again. Callers must
// not retain or mutate candidate after this call.
func (s *DaemonStateStore) commitNetworkCandidateIfRevision(rev uint64, candidate *zone.NetworkState) (uint64, bool) {
	if s == nil || candidate == nil {
		return 0, false
	}
	if !s.legacyWritable() {
		return s.Meta().Revision, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.revision != rev {
		return s.revision, false
	}
	next := cloneStateFileRootSharingChildren(s.committed)
	next.Network = candidate
	s.commitLocked(next)
	return s.revision, true
}

// commitSnapshotApplyIfRevision publishes an owned snapshot batch workspace.
// The workspace must come from snapshotApplyWorkspace and must not be retained
// or mutated after this call. Its unchanged children and non-target zones are
// immutable values shared with the source revision.
func (s *DaemonStateStore) commitSnapshotApplyIfRevision(rev uint64, workspace *stateFile) (uint64, bool) {
	if s == nil || workspace == nil {
		return 0, false
	}
	if !s.legacyWritable() {
		return s.Meta().Revision, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.revision != rev {
		return s.revision, false
	}
	s.commitLocked(workspace)
	return s.revision, true
}

func (s *DaemonStateStore) ReplaceCommitted(state *stateFile) uint64 {
	if s == nil {
		return 0
	}
	if !s.legacyWritable() {
		return s.Meta().Revision
	}
	next := cloneStateFile(state)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.commitLocked(next)
	return s.revision
}

func (s *DaemonStateStore) SetDirty(flags daemonDirtyFlags) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dirty = flags
}

func (s *DaemonStateStore) SetReconcileProgress(status daemonReconcileStatus) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reconcileProgress = status
}

func (s *DaemonStateStore) commitWorkspaceIfRevision(rev uint64, state *stateFile) (uint64, bool, error) {
	next := cloneStateFile(state)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.revision != rev {
		return s.revision, false, nil
	}
	s.commitLocked(next)
	return s.revision, true, nil
}

func (s *DaemonStateStore) commitLocked(state *stateFile) {
	s.committed = state
	s.revision++
	if s.now != nil {
		s.snapshotTime = s.now()
	} else {
		s.snapshotTime = time.Now()
	}
}
