package main

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"time"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

var errDaemonStateRevisionStale = errors.New("daemon state revision is stale")

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

type protocolPublishResult struct {
	RuntimeCommitted bool
	Common           corestate.LocalIntentBatchResult
}

type syncPeerMutationView struct {
	ManagedZone  zone.ZonePath
	Network      *zone.NetworkState
	SyncPeers    map[string]syncPeerState
	PeerCleanups map[string]peerLifecycleCleanupState
}

// NewDaemonStateStore combines the common state owner and Linux runtime owner
// into the detached read view consumed by daemon planners and projections.
func NewDaemonStateStore(common *corestate.Store, runtime *linuxRuntimeState) (*DaemonStateStore, error) {
	return newDaemonStateStore(common, runtime, nil)
}

func newPersistedDaemonStateStore(common *corestate.Store, runtime *linuxRuntimeState, boltStore *corestate.BoltStore) (*DaemonStateStore, error) {
	if boltStore == nil {
		return nil, errors.New("bbolt state store is nil")
	}
	return newDaemonStateStore(common, runtime, func(revision corestate.VerifiedRevision, candidate *linuxRuntimeState) error {
		return commitLinuxRuntime(boltStore, revision, candidate)
	})
}

func newDaemonStateStore(common *corestate.Store, runtime *linuxRuntimeState, commitRuntime func(corestate.VerifiedRevision, *linuxRuntimeState) error) (*DaemonStateStore, error) {
	if common == nil {
		return nil, errors.New("common state store is nil")
	}
	store := &DaemonStateStore{
		common:        common,
		runtime:       cloneLinuxRuntimeState(runtime),
		commitRuntime: commitRuntime,
		now:           time.Now,
	}
	store.refreshView()
	if store.committed == nil {
		return nil, errors.New("daemon state view is nil")
	}
	return store, nil
}

// ApplyCommonLocalIntent validates, signs and persists through the common
// owner; the aggregate read view is refreshed only after publication succeeds.
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
		s.refreshView()
	}
	return result, nil
}

func (s *DaemonStateStore) ApplyCommonLocalIntents(ctx context.Context, intents []corestate.LocalIntent, now time.Time) (corestate.LocalIntentBatchResult, error) {
	if s == nil || s.common == nil {
		return corestate.LocalIntentBatchResult{}, errors.New("daemon common state store is not initialized")
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	result, err := s.common.ApplyLocalIntents(ctx, intents, now)
	if err != nil {
		return corestate.LocalIntentBatchResult{}, err
	}
	if result.Committed {
		s.refreshView()
	}
	return result, nil
}

func (s *DaemonStateStore) InstallCommonIdentity(ctx context.Context, install corestate.IdentityInstall, now time.Time) (corestate.CommitResult, error) {
	if s == nil || s.common == nil {
		return corestate.CommitResult{}, errors.New("daemon common state store is not initialized")
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	result, err := s.common.InstallIdentity(ctx, install, now)
	if err == nil && result.Committed {
		s.refreshView()
	}
	return result, err
}

func (s *DaemonStateStore) RefreshCommonManagedAuthority(ctx context.Context, now time.Time) (corestate.CommitResult, corestate.ManagedAuthorityResult, error) {
	if s == nil || s.common == nil {
		return corestate.CommitResult{}, corestate.ManagedAuthorityResult{}, errors.New("daemon common state store is not initialized")
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	commit, authority, err := s.common.RefreshManagedAuthority(ctx, now)
	if err == nil && commit.Committed {
		s.refreshView()
	}
	return commit, authority, err
}

func (s *DaemonStateStore) ImportCommonRecovery(ctx context.Context, input corestate.RecoveryImport, now time.Time) (corestate.RecoveryImportResult, error) {
	if s == nil || s.common == nil {
		return corestate.RecoveryImportResult{}, errors.New("daemon common state store is not initialized")
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	result, err := s.common.ImportRecoverySnapshot(ctx, input, now)
	if err == nil && result.Committed {
		s.refreshView()
	}
	return result, err
}

func (s *DaemonStateStore) PlanCommonPurge(now time.Time, target zone.ZonePath) (corestate.PurgeRevokedPlan, error) {
	if s == nil || s.common == nil {
		return corestate.PurgeRevokedPlan{}, errors.New("daemon common state store is not initialized")
	}
	return s.common.PlanPurgeRevoked(now, target)
}

func (s *DaemonStateStore) PurgeCommon(ctx context.Context, now time.Time, target zone.ZonePath) (corestate.PurgeRevokedResult, error) {
	if s == nil || s.common == nil {
		return corestate.PurgeRevokedResult{}, errors.New("daemon common state store is not initialized")
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	result, err := s.common.PurgeRevoked(ctx, now, target)
	if err == nil && result.Committed {
		s.refreshView()
	}
	return result, err
}

// publishLocalProtocols commits private/platform runtime before publishing
// public records that may reference it. Both commits are serialized against
// one verified revision and use the same process-wide BoltStore handle.
func (s *DaemonStateStore) publishLocalProtocols(ctx context.Context, sourceRevision uint64, intents []corestate.LocalIntent, runtime *linuxRuntimeState, now time.Time) (protocolPublishResult, error) {
	var out protocolPublishResult
	if s == nil || s.common == nil {
		return out, errors.New("daemon common state store is not initialized")
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	s.mu.RLock()
	currentRevision := s.revision
	currentRuntime := cloneLinuxRuntimeState(s.runtime)
	s.mu.RUnlock()
	if currentRevision != sourceRevision {
		return out, errDaemonStateRevisionStale
	}
	if runtime != nil && !reflect.DeepEqual(currentRuntime, runtime) {
		if s.commitRuntime != nil {
			if err := s.commitRuntime(corestate.VerifiedRevision(sourceRevision), cloneLinuxRuntimeState(runtime)); err != nil {
				return out, err
			}
		}
		s.mu.Lock()
		s.runtime = cloneLinuxRuntimeState(runtime)
		s.mu.Unlock()
		out.RuntimeCommitted = true
	}
	if len(intents) > 0 {
		result, err := s.common.ApplyLocalIntents(ctx, intents, now)
		if err != nil {
			s.refreshView()
			return out, err
		}
		out.Common = result
	}
	if out.RuntimeCommitted || out.Common.Committed {
		s.refreshView()
	}
	return out, nil
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
		s.refreshView()
	}
	return result, nil
}

func (s *DaemonStateStore) UpdateCommonPeerCheckpoint(ctx context.Context, peerID string, patch corestate.PeerCheckpointPatch) (corestate.CommitResult, error) {
	return s.UpdateCommonPeerCheckpoints(ctx, map[string]corestate.PeerCheckpointPatch{peerID: patch})
}

func (s *DaemonStateStore) UpdateCommonPeerCheckpoints(ctx context.Context, patches map[string]corestate.PeerCheckpointPatch) (corestate.CommitResult, error) {
	if s == nil || s.common == nil {
		return corestate.CommitResult{}, errors.New("daemon common state store is not initialized")
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	result, err := s.common.UpdatePeerCheckpoints(ctx, patches)
	if err != nil {
		return corestate.CommitResult{}, err
	}
	if result.Committed {
		s.refreshView()
	}
	return result, nil
}

func (s *DaemonStateStore) DeleteCommonPeerCheckpoints(ctx context.Context, peerIDs []string) (corestate.CommitResult, error) {
	if s == nil || s.common == nil {
		return corestate.CommitResult{}, errors.New("daemon common state store is not initialized")
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	result, err := s.common.DeletePeerCheckpoints(ctx, peerIDs)
	if err == nil && result.Committed {
		s.refreshView()
	}
	return result, err
}

func (s *DaemonStateStore) commitRuntimeIfRevision(sourceRevision uint64, mutate func(*linuxRuntimeState)) (uint64, bool, error) {
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

func (s *DaemonStateStore) commitRoutingIfRevision(revision uint64, birdInstances map[string]*BirdInstanceState, reconcile *routingReconcileState) (uint64, bool, error) {
	return s.commitRuntimeIfRevision(revision, func(runtime *linuxRuntimeState) {
		runtime.BirdInstances = cloneBirdInstances(birdInstances)
		runtime.RoutingReconcile = cloneRoutingReconcileState(reconcile)
	})
}

func (s *DaemonStateStore) commitIPsecIfRevision(revision uint64, transportKey *ipsecTransportKeyState, portRecord *ipsecPortRecordState, linkInstances map[string]linkInstanceState, reconcile *ipsecReconcileState) (uint64, bool, error) {
	return s.commitRuntimeIfRevision(revision, func(runtime *linuxRuntimeState) {
		runtime.IPsecTransportKey = cloneIPsecTransportKeyState(transportKey)
		runtime.IPsecPortRecord = cloneIPsecPortRecordState(portRecord)
		runtime.LinkInstances = cloneLinkInstances(linkInstances)
		runtime.IPsecReconcile = cloneIPsecReconcileState(reconcile)
	})
}

func (s *DaemonStateStore) commitFirewallIfRevision(revision uint64, endpointACLs map[string]endpointACL, reconcile *firewallReconcileState) (uint64, bool, error) {
	return s.commitRuntimeIfRevision(revision, func(runtime *linuxRuntimeState) {
		runtime.EndpointACLs = cloneEndpointACLs(endpointACLs)
		runtime.FirewallReconcile = cloneFirewallReconcileState(reconcile)
	})
}

func (s *DaemonStateStore) commitBirdGCIfRevision(revision uint64, remove []string) (uint64, bool, error) {
	return s.commitRuntimeIfRevision(revision, func(runtime *linuxRuntimeState) {
		for _, netns := range remove {
			delete(runtime.BirdInstances, netns)
		}
	})
}

func (s *DaemonStateStore) commitPurgeRuntimeIfRevision(revision uint64, linkIDs, peerIDs []string) (uint64, bool, error) {
	return s.commitRuntimeIfRevision(revision, func(runtime *linuxRuntimeState) {
		for _, id := range linkIDs {
			delete(runtime.LinkInstances, id)
		}
		for _, peerID := range peerIDs {
			delete(runtime.PeerCleanups, peerID)
		}
	})
}

func (s *DaemonStateStore) commitPeerCleanupsIfRevision(revision uint64, cleanups map[string]peerLifecycleCleanupState) (uint64, bool, error) {
	return s.commitRuntimeIfRevision(revision, func(runtime *linuxRuntimeState) {
		runtime.PeerCleanups = clonePeerCleanups(cleanups)
	})
}

func (s *DaemonStateStore) refreshView() {
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
