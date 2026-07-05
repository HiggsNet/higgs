package main

import (
	"errors"
	"sync"
	"time"
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
