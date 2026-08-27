package main

import (
	"crypto/ed25519"
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
	inspecthttp "github.com/HiggsNet/photon/internal/inspect/http"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/health"
	"github.com/HiggsNet/photon/pkg/routing"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

type daemonStatusProjection struct {
	loaded             bool
	meta               daemonStateStoreMeta
	managedZone        zone.ZonePath
	knownZones         int
	knownPeers         int
	lastSyncUnix       int64
	linkInstances      int
	desiredLinks       int
	lastLinkError      string
	lastRoutingError   string
	ipsecLastRunUnix   int64
	routingLastRunUnix int64
}

func (s *DaemonStateStore) statusProjection() daemonStatusProjection {
	var out daemonStatusProjection
	if s == nil {
		return out
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out.meta = s.metaLocked()
	state := s.committed
	if state == nil {
		return out
	}
	out.loaded = true
	out.managedZone = state.ManagedZone
	out.linkInstances = len(state.LinkInstances)
	out.knownPeers = len(state.SyncPeers)
	if state.Network != nil {
		out.knownZones = len(state.Network.Zones)
	}
	for _, peer := range state.SyncPeers {
		if peer.LastSyncUnix > out.lastSyncUnix {
			out.lastSyncUnix = peer.LastSyncUnix
		}
	}
	if state.IPsecReconcile != nil {
		out.desiredLinks = state.IPsecReconcile.DesiredLinks
		out.lastLinkError = state.IPsecReconcile.LastError
		out.ipsecLastRunUnix = state.IPsecReconcile.LastRunUnix
	}
	if state.RoutingReconcile != nil {
		out.lastRoutingError = state.RoutingReconcile.LastError
		out.routingLastRunUnix = state.RoutingReconcile.LastRunUnix
	}
	return out
}

func (s *DaemonStateStore) metaLocked() daemonStateStoreMeta {
	return daemonStateStoreMeta{
		Revision:          s.revision,
		SnapshotTime:      s.snapshotTime,
		Dirty:             s.dirty,
		ReconcileProgress: s.reconcileProgress,
	}
}

type routesProjection struct {
	loaded bool
	routes *inspecthttp.RoutesResponse
	bird   map[string]*BirdInstanceState
	meta   daemonStateStoreMeta
	err    error
}

func (s *DaemonStateStore) routesProjection(now time.Time) routesProjection {
	var out routesProjection
	if s == nil {
		return out
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out.meta = s.metaLocked()
	state := s.committed
	if state == nil || state.Network == nil {
		return out
	}
	out.loaded = true
	ars, err := routing.BuildAuthorizedRouteSet(state.Network, now)
	if err != nil {
		out.err = err
		return out
	}
	out.routes = inspecthttp.RoutesFromAuthorizedSet(state.ManagedZone, ars)
	out.bird = cloneBirdInstances(state.BirdInstances)
	return out
}

func (s *DaemonStateStore) admissionProjection(now time.Time) (inspect.AdmissionDiagnosis, daemonStateStoreMeta, bool) {
	if s == nil {
		return inspect.AdmissionDiagnosis{}, daemonStateStoreMeta{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.committed == nil {
		return inspect.AdmissionDiagnosis{}, s.metaLocked(), false
	}
	return diagnoseAutoJoinAdmission(s.committed, now), s.metaLocked(), true
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

type autoJoinLogProjection struct {
	pending     bool
	managedZone zone.ZonePath
	joinRequest string
}

func (s *DaemonStateStore) autoJoinLogProjection() autoJoinLogProjection {
	var out autoJoinLogProjection
	if s == nil {
		return out
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	state := s.committed
	if !autoJoinPending(state) || len(state.ZonePrivateKey) != ed25519.PrivateKeySize {
		return out
	}
	pub := state.ZonePrivateKey.Public().(ed25519.PublicKey)
	text, err := encodeBase64JSON(&joinRequest{Version: 1, Zone: state.ManagedZone, PublicKey: pub})
	if err != nil {
		return out
	}
	out.pending = true
	out.managedZone = state.ManagedZone
	out.joinRequest = text
	return out
}

func (s *DaemonStateStore) autoAnnouncePlanProjection(d *DaemonService, ars *routing.AuthorizedRouteSet) (autoAnnouncePlan, error) {
	if s == nil {
		return autoAnnouncePlan{}, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return d.autoAnnounceAssignedIPsPlanForState(s.committed, ars)
}

func (s *DaemonStateStore) healthContextProjection(links []healthLinkJSON) []inspecthttp.HealthContextItem {
	if s == nil {
		return inspecthttp.BuildHealthContext(inspecthttp.HealthContextInput{HealthLinks: inspectHealthLinks(links)})
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	state := s.committed
	if state == nil {
		return inspecthttp.BuildHealthContext(inspecthttp.HealthContextInput{HealthLinks: inspectHealthLinks(links)})
	}
	desiredByID := map[string]desiredLinkState{}
	if state.IPsecReconcile != nil {
		desiredByID = desiredByInstanceID(state.IPsecReconcile.Desired)
	}
	return inspecthttp.BuildHealthContext(inspecthttp.HealthContextInput{
		HealthLinks: inspectHealthLinks(links),
		Instances:   inspectHealthInstances(state.LinkInstances),
		Desired:     inspectHealthDesired(desiredByID),
		Unknown: func(instanceID string) any {
			return healthLinkJSON{InstanceID: instanceID, State: "unknown"}
		},
	})
}

func (s *DaemonStateStore) stateGCPlanProjection(config *appConfig) *stateGCPlan {
	if s == nil {
		return &stateGCPlan{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return buildStateGCPlan(config, s.committed)
}
