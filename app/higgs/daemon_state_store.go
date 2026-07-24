package main

import (
	"errors"
	"sync"
	"time"

	"github.com/Catofes/higgs/pkg/core/gossip"
	"github.com/Catofes/higgs/pkg/core/zone"
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
	mu                sync.RWMutex
	committed         *stateFile
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
	ManagedZone zone.ZonePath
	Network     *zone.NetworkState
	SyncPeers   map[string]syncPeerState
}

func NewDaemonStateStore(initial *stateFile) *DaemonStateStore {
	store := &DaemonStateStore{now: time.Now}
	store.ReplaceCommitted(initial)
	return store
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

// ZoneDigests returns a detached digest projection of the committed state.
// It keeps the state pointer private and avoids cloning the complete Network
// for callers that only need its gossip digest.
func (s *DaemonStateStore) ZoneDigests() []gossip.ZoneDigest {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.committed == nil {
		return nil
	}
	return gossip.ZoneDigests(s.committed.Network)
}

// ReadCommitted invokes fn while holding a read lock on the immutable
// committed state. The callback must not retain or mutate state. It is for
// inexpensive predicates that can avoid creating a full copy-on-write
// workspace when no update is necessary.
func (s *DaemonStateStore) ReadCommitted(fn func(*stateFile)) {
	if s == nil || fn == nil {
		return
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	fn(s.committed)
}

func (s *DaemonStateStore) Meta() daemonStateStoreMeta {
	if s == nil {
		return daemonStateStoreMeta{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return daemonStateStoreMeta{
		Revision:          s.revision,
		SnapshotTime:      s.snapshotTime,
		Dirty:             s.dirty,
		ReconcileProgress: s.reconcileProgress,
	}
}

func (s *DaemonStateStore) BeginUpdate() (*DaemonStateUpdate, error) {
	if s == nil {
		return nil, errors.New("daemon state store is nil")
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
	if peerID == "" {
		return 0, errors.New("sync peer id is empty")
	}
	if fn == nil {
		return 0, errors.New("sync peer update function is nil")
	}
	var currentRev uint64
	for attempt := 0; attempt < maxSyncPeerUpdateAttempts; attempt++ {
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
			for id, state := range base.SyncPeers {
				next.SyncPeers[id] = state
			}
		}
		next.SyncPeers[peerID] = committedPeer

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
	if fn == nil {
		return 0, false, errors.New("sync peers update function is nil")
	}
	var currentRev uint64
	for attempt := 0; attempt < maxSyncPeerUpdateAttempts; attempt++ {
		s.mu.RLock()
		base := s.committed
		baseRev := s.revision
		view := syncPeerMutationView{}
		if base != nil {
			view.ManagedZone = base.ManagedZone
			view.Network = base.Network
			view.SyncPeers = base.SyncPeers
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
		for id, state := range view.SyncPeers {
			next.SyncPeers[id] = state
		}
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

func (s *DaemonStateStore) ReplaceCommitted(state *stateFile) uint64 {
	if s == nil {
		return 0
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
