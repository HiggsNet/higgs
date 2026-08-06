package main

import (
	"crypto/ed25519"
	"sort"
	"time"

	"github.com/Catofes/photon/internal/inspect"
	inspecthttp "github.com/Catofes/photon/internal/inspect/http"
	"github.com/Catofes/photon/internal/observability"
	"github.com/Catofes/photon/pkg/core/gossip"
	"github.com/Catofes/photon/pkg/core/zone"
	"github.com/Catofes/photon/pkg/health"
	"github.com/Catofes/photon/pkg/routing"
	"github.com/Catofes/photon/pkg/transport/ipsec"
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

func (s *DaemonStateStore) recordDetailProjection(path zone.ZonePath, key string, history int) (*inspect.RecordDetailView, daemonStateStoreMeta, error) {
	if s == nil {
		return nil, daemonStateStoreMeta{}, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	view, err := lookupRecordDetail(s.committed, path, key, history)
	return view, s.metaLocked(), err
}

func (s *DaemonStateStore) endpointACLProjection() ([]endpointACL, daemonStateStoreMeta) {
	if s == nil {
		return nil, daemonStateStoreMeta{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	var acls []endpointACL
	if s.committed != nil {
		for _, acl := range s.committed.EndpointACLs {
			acl.Selectors = append([]string(nil), acl.Selectors...)
			acls = append(acls, acl)
		}
		sort.Slice(acls, func(i, j int) bool { return acls[i].Name < acls[j].Name })
	}
	return acls, s.metaLocked()
}

type birdStatusProjection struct {
	loaded           bool
	instances        map[string]*BirdInstanceState
	lastRoutingError string
	meta             daemonStateStoreMeta
}

func (s *DaemonStateStore) birdStatusProjection() birdStatusProjection {
	var out birdStatusProjection
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
	out.instances = cloneBirdInstances(s.committed.BirdInstances)
	if s.committed.RoutingReconcile != nil {
		out.lastRoutingError = s.committed.RoutingReconcile.LastError
	}
	return out
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

func (s *DaemonStateStore) firewallStatusProjection() (*firewallReconcileState, daemonStateStoreMeta, bool) {
	if s == nil {
		return nil, daemonStateStoreMeta{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.committed == nil {
		return nil, s.metaLocked(), false
	}
	return cloneFirewallReconcileState(s.committed.FirewallReconcile), s.metaLocked(), true
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

type zonesProjection struct {
	loaded bool
	found  bool
	detail inspect.ZoneDetail
	list   inspecthttp.ZonesResponse
}

func (s *DaemonStateStore) zonesProjection(path zone.ZonePath, now time.Time) zonesProjection {
	var out zonesProjection
	if s == nil {
		return out
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	state := s.committed
	if state == nil || state.Network == nil {
		return out
	}
	out.loaded = true
	if path == "" {
		out.list = inspecthttp.ZonesFromNetwork(state.Network, now.Unix())
		return out
	}
	zs := state.Network.Zones[path]
	if zs == nil {
		return out
	}
	out.found = true
	out.detail = inspect.BuildZoneDetail(inspect.ZoneDetailInput{
		Path: path, State: zs, Network: state.Network, Now: now, IncludeHistory: true,
	})
	return out
}

type peersProjection struct {
	loaded bool
	known  map[string]bool
	order  []string
	peers  map[string]inspecthttp.PeerJSON
}

func (s *DaemonStateStore) peersProjection(config *syncConfigFile, now time.Time, observations map[string]observability.PeerSnapshot) peersProjection {
	out := peersProjection{known: make(map[string]bool), peers: make(map[string]inspecthttp.PeerJSON)}
	if s == nil {
		return out
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	state := s.committed
	if state == nil {
		return out
	}
	out.loaded = true
	peerSet := inspectPeerSetInput(state, config, now)
	for peerID := range observations {
		peerSet.RuntimeIDs = append(peerSet.RuntimeIDs, peerID)
	}
	for _, id := range inspect.BuildPeerIDs(peerSet) {
		if out.known[id] {
			continue
		}
		out.known[id] = true
		out.order = append(out.order, id)
		ps := cloneSyncPeerState(state.SyncPeers[id])
		if observed, ok := observations[id]; ok {
			ps.DatagramStats = observed.DatagramStats
			ps.ObjectPullStats = observed.ObjectPullStats
			ps = cloneSyncPeerState(ps)
		}
		out.peers[id] = inspecthttp.PeerFromInputs(
			id,
			bootstrapAddrForPeer(config, id),
			inspectPeerEndpoints(id, ps, config, state.Network, now),
			ps,
		)
	}
	return out
}

// committedStateLease is the only read API allowed to retain a committed root.
// Published roots are immutable, so the persistence adapter can encode this
// revision after releasing the store lock. The lease must never be used as a
// general-purpose state accessor.
type committedStateLease struct {
	state    *stateFile
	revision uint64
}

func (s *DaemonStateStore) persistenceLease() committedStateLease {
	if s == nil {
		return committedStateLease{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return committedStateLease{state: s.committed, revision: s.revision}
}

type syncTimerProjection struct {
	loaded     bool
	peers      []string
	peerStates map[string]syncPeerState
	summary    *gossip.CatalogSummary
	digests    []gossip.ZoneDigest
	err        error
}

func (s *DaemonStateStore) syncTimerProjection(config *syncConfigFile, now time.Time, budget int) syncTimerProjection {
	var out syncTimerProjection
	if s == nil {
		return out
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	state := s.committed
	if state == nil || state.Network == nil {
		return out
	}
	out.loaded = true
	out.peers = outboundSyncPeersAt(state, config, now)
	out.peerStates = make(map[string]syncPeerState, len(out.peers))
	for _, peerID := range out.peers {
		out.peerStates[peerID] = cloneSyncPeerState(state.SyncPeers[peerID])
	}
	out.summary, out.err = gossip.CatalogSummaryFor(state.Network, budget)
	if out.err == nil {
		out.digests = gossip.ZoneDigests(state.Network)
	}
	return out
}

func (s *DaemonStateStore) catalogSummaryProjection(budget int) (*gossip.CatalogSummary, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.committed == nil || s.committed.Network == nil {
		return nil, nil
	}
	return gossip.CatalogSummaryFor(s.committed.Network, budget)
}

func (s *DaemonStateStore) catalogStateProjection(budget int) (*gossip.CatalogSummary, []gossip.ZoneDigest, error) {
	if s == nil {
		return nil, nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.committed == nil || s.committed.Network == nil {
		return nil, nil, nil
	}
	summary, err := gossip.CatalogSummaryFor(s.committed.Network, budget)
	if err != nil {
		return nil, nil, err
	}
	return summary, gossip.ZoneDigests(s.committed.Network), nil
}

func (s *DaemonStateStore) catalogPageProjection(cursor string, budget int) (*gossip.CatalogPage, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.committed == nil || s.committed.Network == nil {
		return nil, nil
	}
	return gossip.CatalogPageFor(s.committed.Network, cursor, budget)
}

type syncStateProjection struct {
	loaded      bool
	managedZone zone.ZonePath
	digests     []gossip.ZoneDigest
}

func (s *DaemonStateStore) syncStateProjection() syncStateProjection {
	var out syncStateProjection
	if s == nil {
		return out
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.committed == nil || s.committed.Network == nil {
		return out
	}
	out.loaded = true
	out.managedZone = s.committed.ManagedZone
	out.digests = gossip.ZoneDigests(s.committed.Network)
	return out
}

func (s *DaemonStateStore) filteredCatalogProjection(peerID string, page *gossip.CatalogPage, now time.Time) ([]gossip.ZoneDigest, *gossip.CatalogPage) {
	if s == nil {
		return nil, page
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.committed == nil || s.committed.Network == nil {
		return nil, page
	}
	return gossip.ZoneDigests(s.committed.Network), filterRemoteCatalogPage(s.committed, peerID, page, now)
}

func (s *DaemonStateStore) fetchZonePlanProjection(path zone.ZonePath, budget int, now time.Time) (snapshotDatagramPlan, error) {
	if s == nil {
		return snapshotDatagramPlan{}, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.committed == nil || s.committed.Network == nil {
		return snapshotDatagramPlan{}, nil
	}
	if s.committed.Network.Zones[path] == nil {
		return snapshotDatagramPlan{}, &zoneNotFoundProjectionError{path: path}
	}
	return planSnapshotDatagrams(s.committed.Network, []zone.ZonePath{path}, budget, now), nil
}

func (s *DaemonStateStore) fetchZoneChunkProjection(path zone.ZonePath, budget int, now time.Time) (snapshotDatagramPlan, *gossip.ZoneSnapshot, error) {
	if s == nil {
		return snapshotDatagramPlan{}, nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.committed == nil || s.committed.Network == nil {
		return snapshotDatagramPlan{}, nil, nil
	}
	network := s.committed.Network
	if network.Zones[path] == nil {
		return snapshotDatagramPlan{}, nil, &zoneNotFoundProjectionError{path: path}
	}
	plan := planSnapshotDatagrams(network, []zone.ZonePath{path}, budget, now)
	if network.IsZoneRevoked(path, now) {
		return plan, nil, nil
	}
	snapshot, err := gossip.Snapshot(network, path)
	return plan, snapshot, err
}

type zoneNotFoundProjectionError struct{ path zone.ZonePath }

func (e *zoneNotFoundProjectionError) Error() string { return "zone not found: " + e.path.String() }
func (e *zoneNotFoundProjectionError) Unwrap() error { return zone.ErrZoneNotFound }

func (s *DaemonStateStore) objectPullProjection(req *gossip.ObjectPullRequest, now time.Time) *gossip.ObjectPullResponse {
	if s == nil {
		return &gossip.ObjectPullResponse{Error: "invalid request"}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return objectPullResponseFromState(s.committed, req, now)
}

func (s *DaemonStateStore) peerTCPAddrProjection(config *syncConfigFile, peerID string) (string, bool) {
	if s == nil {
		return "", false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.committed == nil {
		return "", false
	}
	return resolvePeerTCPAddr(s.committed, config, peerID), true
}

type relayProjection struct {
	digests    []gossip.ZoneDigest
	peers      []string
	peerStates map[string]syncPeerState
}

func (s *DaemonStateStore) relayProjection(config *syncConfigFile, now time.Time) relayProjection {
	var out relayProjection
	if s == nil {
		return out
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.committed == nil || s.committed.Network == nil {
		return out
	}
	out.digests = gossip.ZoneDigests(s.committed.Network)
	out.peers = outboundSyncPeersAt(s.committed, config, now)
	out.peerStates = make(map[string]syncPeerState, len(out.peers))
	for _, peerID := range out.peers {
		out.peerStates[peerID] = cloneSyncPeerState(s.committed.SyncPeers[peerID])
	}
	return out
}

func (s *DaemonStateStore) observedPathsProjection(peerID string, now time.Time) ([]gossip.ObservedPath, bool, bool) {
	if s == nil || peerID == "" {
		return nil, false, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.committed == nil {
		return nil, false, false
	}
	state := s.committed
	return plannedObservedPaths(syncPeerMutationView{
		ManagedZone: state.ManagedZone,
		Network:     state.Network,
		SyncPeers:   state.SyncPeers,
	}, peerID, cloneSyncPeerState(state.SyncPeers[peerID]), now)
}

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

func (s *DaemonStateStore) revokedZonesProjection(now time.Time) map[zone.ZonePath]bool {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.committed == nil || s.committed.Network == nil {
		return nil
	}
	return CollectAllRevokedZones(s.committed, now)
}

func (s *DaemonStateStore) identityKeyPathProjection() string {
	if s == nil {
		return ""
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.committed == nil {
		return ""
	}
	return s.committed.IdentityKeyPath
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

func (s *DaemonStateStore) hasLinkInstancesProjection() bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.committed != nil && len(s.committed.LinkInstances) > 0
}

func (s *DaemonStateStore) linkIDsProjection() []string {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.committed == nil {
		return nil
	}
	ids := make([]string, 0, len(s.committed.LinkInstances))
	for id := range s.committed.LinkInstances {
		ids = append(ids, id)
	}
	return ids
}

func (s *DaemonStateStore) peerIDsProjection() []string {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.committed == nil {
		return nil
	}
	ids := make([]string, 0, len(s.committed.SyncPeers))
	for id := range s.committed.SyncPeers {
		ids = append(ids, id)
	}
	return ids
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

func (s *DaemonStateStore) purgePlanProjection(now time.Time, target zone.ZonePath) (*purgePlan, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return planPurgeRevokedZones(s.committed, now, target)
}
