package observability

import (
	"sync"
	"time"

	photonstate "github.com/HiggsNet/photon/internal/state"
)

// PeerSnapshot contains diagnostics that are safe to lose on daemon restart.
// Values returned by PeerObservabilityStore are detached from the mutable store.
type PeerSnapshot struct {
	DatagramStats   *photonstate.PeerDatagramStats
	ObjectPullStats *photonstate.PeerObjectPullStats
}

type peerEntry struct {
	snapshot  PeerSnapshot
	updatedAt time.Time
}

// PeerObservabilityStore owns bounded, non-persistent per-peer diagnostics.
type PeerObservabilityStore struct {
	mu         sync.RWMutex
	entries    map[string]peerEntry
	maxEntries int
	ttl        time.Duration
}

func NewPeerObservabilityStore(maxEntries int, ttl time.Duration) *PeerObservabilityStore {
	if maxEntries < 1 {
		maxEntries = 1
	}
	return &PeerObservabilityStore{
		entries:    make(map[string]peerEntry),
		maxEntries: maxEntries,
		ttl:        ttl,
	}
}

// Update applies a mutation while holding the store lock. The callback must
// not retain snapshot or any pointer stored inside it.
func (s *PeerObservabilityStore) Update(peerID string, now time.Time, fn func(*PeerSnapshot)) {
	if s == nil || peerID == "" || fn == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.purgeExpiredLocked(now)
	entry, exists := s.entries[peerID]
	if !exists && len(s.entries) >= s.maxEntries {
		s.evictOldestLocked()
	}
	fn(&entry.snapshot)
	entry.updatedAt = now
	s.entries[peerID] = entry
}

func (s *PeerObservabilityStore) Snapshot(peerID string, now time.Time) (PeerSnapshot, bool) {
	if s == nil || peerID == "" {
		return PeerSnapshot{}, false
	}
	s.mu.RLock()
	entry, ok := s.entries[peerID]
	expired := ok && s.expired(entry, now)
	if ok && !expired {
		out := clonePeerSnapshot(entry.snapshot)
		s.mu.RUnlock()
		return out, true
	}
	s.mu.RUnlock()
	if expired {
		s.mu.Lock()
		if current, exists := s.entries[peerID]; exists && s.expired(current, now) {
			delete(s.entries, peerID)
		}
		s.mu.Unlock()
	}
	return PeerSnapshot{}, false
}

func (s *PeerObservabilityStore) Snapshots(now time.Time) map[string]PeerSnapshot {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.purgeExpiredLocked(now)
	out := make(map[string]PeerSnapshot, len(s.entries))
	for peerID, entry := range s.entries {
		out[peerID] = clonePeerSnapshot(entry.snapshot)
	}
	return out
}

func (s *PeerObservabilityStore) Delete(peerID string) {
	if s == nil || peerID == "" {
		return
	}
	s.mu.Lock()
	delete(s.entries, peerID)
	s.mu.Unlock()
}

func (s *PeerObservabilityStore) PurgeExpired(now time.Time) int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.purgeExpiredLocked(now)
}

func (s *PeerObservabilityStore) Len(now time.Time) int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.purgeExpiredLocked(now)
	return len(s.entries)
}

func (s *PeerObservabilityStore) expired(entry peerEntry, now time.Time) bool {
	return s.ttl > 0 && !now.IsZero() && !entry.updatedAt.IsZero() && !now.Before(entry.updatedAt.Add(s.ttl))
}

func (s *PeerObservabilityStore) purgeExpiredLocked(now time.Time) int {
	if s.ttl <= 0 || now.IsZero() {
		return 0
	}
	purged := 0
	for peerID, entry := range s.entries {
		if s.expired(entry, now) {
			delete(s.entries, peerID)
			purged++
		}
	}
	return purged
}

func (s *PeerObservabilityStore) evictOldestLocked() {
	var oldestID string
	var oldest time.Time
	for peerID, entry := range s.entries {
		if oldestID == "" || entry.updatedAt.Before(oldest) || entry.updatedAt.Equal(oldest) && peerID < oldestID {
			oldestID = peerID
			oldest = entry.updatedAt
		}
	}
	if oldestID != "" {
		delete(s.entries, oldestID)
	}
}

func clonePeerSnapshot(in PeerSnapshot) PeerSnapshot {
	out := PeerSnapshot{}
	if in.DatagramStats != nil {
		stats := *in.DatagramStats
		out.DatagramStats = &stats
	}
	if in.ObjectPullStats != nil {
		stats := *in.ObjectPullStats
		out.ObjectPullStats = &stats
	}
	return out
}
