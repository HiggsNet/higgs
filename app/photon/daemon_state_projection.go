package main

import (
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

func (s *DaemonStateStore) metaLocked() daemonStateStoreMeta {
	return daemonStateStoreMeta{
		Revision:          s.revision,
		SnapshotTime:      s.snapshotTime,
		Dirty:             s.dirty,
		ReconcileProgress: s.reconcileProgress,
	}
}

func (s *DaemonStateStore) peerLifecycleCleanupProjection(now time.Time, cfg inspect.PeerLifecycleConfig) bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return peerLifecycleCleanupRequired(s.committed, now, cfg)
}

func (s *DaemonStateStore) revocationImpactProjection(config *syncConfigFile, now time.Time) ([]inspect.RevocationImpact, daemonStateStoreMeta, bool) {
	if s == nil {
		return nil, daemonStateStoreMeta{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.committed == nil {
		return nil, s.metaLocked(), false
	}
	return AllRevocationImpact(s.committed, config, now), s.metaLocked(), true
}

type revocationCleanupProjection struct {
	revokedZones      map[zone.ZonePath]bool
	needsStateCleanup bool
}

func (s *DaemonStateStore) revocationCleanupProjection(now time.Time) revocationCleanupProjection {
	if s == nil {
		return revocationCleanupProjection{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.committed == nil || s.committed.Network == nil {
		return revocationCleanupProjection{}
	}
	revokedZones := CollectAllRevokedZones(s.committed, now)
	projection := revocationCleanupProjection{revokedZones: revokedZones}
	for peerID, peer := range s.committed.SyncPeers {
		if revokedZones[zone.ZonePath(peerID)] && peerNeedsRevocationCleanup(peer) {
			projection.needsStateCleanup = true
			break
		}
	}
	return projection
}
