package main

import (
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/health"
	"github.com/HiggsNet/photon/pkg/routing"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func (s *DaemonStateStore) metaLocked() daemonStateStoreMeta {
	return daemonStateStoreMeta{
		Revision:          s.revision,
		SnapshotTime:      s.snapshotTime,
		Dirty:             s.dirty,
		ReconcileProgress: s.reconcileProgress,
	}
}

type linksStatusProjection struct {
	loaded    bool
	build     linkInspectionBuild
	actualSAs []linkSAState
	meta      daemonStateStoreMeta
}

func (s *DaemonStateStore) linksStatusProjection(rt *Runtime, healthLinks []healthLinkJSON) linksStatusProjection {
	var out linksStatusProjection
	if s == nil {
		return out
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out.meta = s.metaLocked()
	if s.committed == nil {
		return out
	}
	out.loaded = true
	out.build = buildLinkInspectionFromReconcile(rt, s.committed, healthLinks)
	if s.committed.IPsecReconcile != nil {
		out.actualSAs = append([]linkSAState(nil), s.committed.IPsecReconcile.ActualSAs...)
	}
	return out
}

func (s *DaemonStateStore) peerStatusProjection(now time.Time, cfg inspect.PeerLifecycleConfig, hasOverlay bool) ([]inspect.PeerStatusInfo, daemonStateStoreMeta, bool) {
	if s == nil {
		return nil, daemonStateStoreMeta{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.committed == nil {
		return nil, s.metaLocked(), false
	}
	return derivePeerStatuses(s.committed, now, cfg, hasOverlay), s.metaLocked(), true
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

// committedStateLease is the only read API allowed to retain a committed root.
// Published roots are immutable, so the persistence adapter can encode this
// revision after releasing the store lock. The lease must never be used as a
// general-purpose state accessor.
func (s *DaemonStateStore) healthTargetsProjection(groups []ipsec.LinkGroupSpec) (string, []health.ProbeTarget) {
	if s == nil {
		return "", nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.committed == nil {
		return "", nil
	}
	localZone := s.committed.ManagedZone.String()
	return localZone, healthTargetsFromState(s.committed, localZone, groups)
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

func (s *DaemonStateStore) autoAnnouncePlanProjection(d *DaemonService, ars *routing.AuthorizedRouteSet) (autoAnnouncePlan, error) {
	if s == nil {
		return autoAnnouncePlan{}, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return d.autoAnnounceAssignedIPsPlanForState(s.committed, ars)
}

func (s *DaemonStateStore) stateGCPlanProjection(config *appConfig) *stateGCPlan {
	if s == nil {
		return &stateGCPlan{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return buildStateGCPlan(config, s.committed)
}
