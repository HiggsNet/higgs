package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/Catofes/higgs/internal/inspect"
	"github.com/Catofes/higgs/internal/observer"
	"github.com/Catofes/higgs/pkg/core/gossip"
	"github.com/Catofes/higgs/pkg/core/zone"
	higgscrypto "github.com/Catofes/higgs/pkg/crypto"
	"github.com/Catofes/higgs/pkg/routing"
)

type observerServer struct {
	daemon   *DaemonService
	config   observerConfig
	provider *observerProvider
	server   *observer.Server
	hub      *observer.Hub
}

type observerProvider struct {
	daemon *DaemonService
}

// newObserverServer creates a new read-only HTTP observer from the daemon
// service and observer configuration. Returns nil if observer is disabled.
func newObserverServer(d *DaemonService, cfg observerConfig) *observerServer {
	if !cfg.Enabled || d == nil {
		return nil
	}
	provider := &observerProvider{daemon: d}
	server := observer.NewServer(provider, observer.Config{
		Enabled:            cfg.Enabled,
		BindAddr:           cfg.BindAddr,
		Port:               cfg.Port,
		EventBufferSeconds: cfg.EventBufferSeconds,
	})
	if server == nil {
		return nil
	}
	return &observerServer{
		daemon:   d,
		config:   cfg,
		provider: provider,
		server:   server,
		hub:      server.Hub(),
	}
}

// startObserverServer starts the HTTP observer if enabled. It returns a
// cleanup function that gracefully shuts down the server.
func (d *DaemonService) startObserverServer(_ context.Context) (func(), error) {
	if d == nil || d.Sync == nil || d.Sync.App == nil || d.Sync.App.Config == nil {
		return func() {}, nil
	}
	cfg := d.Sync.App.Config.Observer
	if !cfg.Enabled {
		return func() {}, nil
	}
	srv := newObserverServer(d, cfg)
	if srv == nil {
		return func() {}, nil
	}
	// Wire the observer hub so notifyObserver can broadcast events.
	d.observerHub = srv.hub
	addr := cfg.listenAddr()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("observer listen %s: %w", addr, err)
	}
	httpServer := observer.DefaultHTTPServer(srv.handler())
	go func() {
		_ = httpServer.Serve(ln)
	}()
	if !cfg.isLoopbackBind() {
		d.logWarn("observer", "non_loopback_bind", map[string]any{
			"addr":    addr,
			"warning": "observer is bound to a non-loopback address; ensure external access control is in place",
		})
	}
	d.logInfo("observer", "started", map[string]any{"addr": addr})
	return func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdownCtx)
	}, nil
}

// notifyObserver broadcasts an SSE event to all subscribers. Safe to call
// even when the observer is disabled (no-op if hub is nil).
func (d *DaemonService) notifyObserver(eventType string, payload any) {
	if d == nil || d.observerHub == nil {
		return
	}
	d.observerHub.Broadcast(observer.Event{Type: eventType, Payload: payload})
}

// handler returns the HTTP handler for the observer, including REST APIs,
// SSE events, and static UI.
func (s *observerServer) handler() http.Handler {
	return s.server.Handler()
}

type apiResponse = observer.APIResponse

func (s *observerServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	s.server.HandleStatus(w, r)
}
func (s *observerServer) handleZones(w http.ResponseWriter, r *http.Request) {
	s.server.HandleZones(w, r)
}
func (s *observerServer) handlePeers(w http.ResponseWriter, r *http.Request) {
	s.server.HandlePeers(w, r)
}
func (s *observerServer) handleLinks(w http.ResponseWriter, r *http.Request) {
	s.server.HandleLinks(w, r)
}
func (s *observerServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	s.server.HandleHealth(w, r)
}
func (s *observerServer) handleRoutes(w http.ResponseWriter, r *http.Request) {
	s.server.HandleRoutes(w, r)
}
func (s *observerServer) handleBird(w http.ResponseWriter, r *http.Request) {
	s.server.HandleBird(w, r)
}
func (s *observerServer) handleEvents(w http.ResponseWriter, r *http.Request) {
	s.server.HandleEvents(w, r)
}
func (s *observerServer) handleStatic(w http.ResponseWriter, r *http.Request) {
	s.server.HandleStatic(w, r)
}

func (p *observerProvider) Status() (any, error) {
	d := p.daemon
	if d == nil || d.Sync == nil {
		return map[string]any{"daemon_online": false}, nil
	}
	state, _, meta := d.snapshotState()
	if state == nil {
		return map[string]any{"daemon_online": false}, nil
	}
	var linkInstances int
	var desiredLinks int
	var lastLinkError string
	var lastRoutingError string
	if state.IPsecReconcile != nil {
		lastLinkError = state.IPsecReconcile.LastError
		desiredLinks = state.IPsecReconcile.DesiredLinks
	}
	if state.RoutingReconcile != nil {
		lastRoutingError = state.RoutingReconcile.LastError
	}
	linkInstances = len(state.LinkInstances)
	knownZones := 0
	if state.Network != nil {
		knownZones = len(state.Network.Zones)
	}
	knownPeers := len(state.SyncPeers)
	var lastSyncUnix int64
	var lastReconcileUnix int64
	for _, peer := range state.SyncPeers {
		if peer.LastSyncUnix > lastSyncUnix {
			lastSyncUnix = peer.LastSyncUnix
		}
	}
	if state.IPsecReconcile != nil && state.IPsecReconcile.LastRunUnix > lastReconcileUnix {
		lastReconcileUnix = state.IPsecReconcile.LastRunUnix
	}
	if state.RoutingReconcile != nil && state.RoutingReconcile.LastRunUnix > lastReconcileUnix {
		lastReconcileUnix = state.RoutingReconcile.LastRunUnix
	}
	peerID := ""
	listenAddr := ""
	managedZone := ""
	if d.Sync.Config != nil {
		peerID = d.Sync.Config.PeerID
		listenAddr = d.Sync.Config.ListenAddr
	}
	managedZone = string(state.ManagedZone)
	return map[string]any{
		"peer_id":             peerID,
		"managed_zone":        managedZone,
		"listen_addr":         listenAddr,
		"daemon_online":       true,
		"state_revision":      meta.Revision,
		"snapshot_time_unix":  meta.SnapshotTime.Unix(),
		"dirty":               meta.Dirty,
		"reconcile_progress":  meta.ReconcileProgress,
		"known_zones":         knownZones,
		"known_peers":         knownPeers,
		"link_instances":      linkInstances,
		"desired_links":       desiredLinks,
		"last_link_error":     lastLinkError,
		"last_routing_error":  lastRoutingError,
		"last_sync_unix":      lastSyncUnix,
		"last_reconcile_unix": lastReconcileUnix,
	}, nil
}

// zoneSummaryJSON is the per-zone summary for /api/v1/zones
type zoneSummaryJSON struct {
	Path        string `json:"path"`
	Records     int    `json:"records"`
	Delegations int    `json:"delegations"`
	Revocations int    `json:"revocations"`
	Revoked     bool   `json:"revoked"`
	RootHashHex string `json:"root_hash"`
}

func (p *observerProvider) Zones(zoneFilter string) (any, error) {
	d := p.daemon
	if d == nil || d.Sync == nil {
		return map[string]any{"zones": []any{}}, nil
	}
	state, _, _ := d.snapshotState()
	if state == nil {
		return map[string]any{"zones": []any{}}, nil
	}
	if state.Network == nil {
		return map[string]any{"zones": []any{}}, nil
	}
	now := d.Sync.now()
	// Single zone detail
	if zoneFilter != "" {
		zp := zone.ZonePath(zoneFilter)
		zs := state.Network.Zones[zp]
		if zs == nil {
			return nil, observer.Errorf(http.StatusNotFound, "zone not found")
		}
		return inspect.BuildZoneDetail(inspect.ZoneDetailInput{
			Path:           zp,
			State:          zs,
			Network:        state.Network,
			Now:            now,
			IncludeHistory: true,
		}), nil
	}
	// All zones summary
	zones := make([]zoneSummaryJSON, 0, len(state.Network.Zones))
	paths := make([]zone.ZonePath, 0, len(state.Network.Zones))
	for p := range state.Network.Zones {
		paths = append(paths, p)
	}
	sort.Slice(paths, func(i, j int) bool { return observerZoneLess(string(paths[i]), string(paths[j])) })
	for _, p := range paths {
		zs := state.Network.Zones[p]
		if zs == nil {
			continue
		}
		revoked := state.Network.IsZoneRevoked(p, now)
		rootHash := ""
		if zs.Authority != nil {
			rootHash = hex.EncodeToString(higgscrypto.AuthorityHash(zs.Authority))
		}
		zones = append(zones, zoneSummaryJSON{
			Path:        string(p),
			Records:     len(zs.Records),
			Delegations: len(zs.Delegations),
			Revocations: len(zs.Revocations),
			Revoked:     revoked,
			RootHashHex: rootHash,
		})
	}
	globalRoot := ""
	digests := gossip.ZoneDigests(state.Network)
	if root := globalRootHash(digests); root != nil {
		globalRoot = hex.EncodeToString(root)
	}
	return map[string]any{
		"zones":       zones,
		"global_root": globalRoot,
	}, nil
}

// peerJSON is the per-peer view for /api/v1/peers
type peerJSON struct {
	PeerID                string                         `json:"peer_id"`
	Source                string                         `json:"source,omitempty"`
	ConfiguredAddr        string                         `json:"configured_addr,omitempty"`
	LastSyncUnix          int64                          `json:"last_sync_unix"`
	LastAttemptUnix       int64                          `json:"last_attempt_unix"`
	BackoffUntilUnix      int64                          `json:"backoff_until_unix"`
	LastRelayUnix         int64                          `json:"last_relay_unix,omitempty"`
	FailureCount          int                            `json:"failure_count"`
	LastError             string                         `json:"last_error,omitempty"`
	LastUpdateSource      string                         `json:"last_update_source,omitempty"`
	LastRelaySuppression  string                         `json:"last_relay_suppression,omitempty"`
	LastRelaySuppressedAt int64                          `json:"last_relay_suppressed_at,omitempty"`
	DiscoveredAddr        string                         `json:"discovered_addr,omitempty"`
	DiscoveredAtUnix      int64                          `json:"discovered_at_unix,omitempty"`
	ObservedAddr          string                         `json:"observed_addr,omitempty"`
	ObservedFirstSeenUnix int64                          `json:"observed_first_seen_unix,omitempty"`
	ObservedLastSeenUnix  int64                          `json:"observed_last_seen_unix,omitempty"`
	ObservedLastSyncUnix  int64                          `json:"observed_last_sync_unix,omitempty"`
	ObservedUntilUnix     int64                          `json:"observed_until_unix,omitempty"`
	ObservedSource        string                         `json:"observed_source,omitempty"`
	ObservedFailureCount  int                            `json:"observed_failure_count,omitempty"`
	ObservedGraceAddrs    []observedGraceAddrState       `json:"observed_grace_addrs,omitempty"`
	Endpoints             []inspect.PeerEndpointView     `json:"endpoints,omitempty"`
	DatagramStats         *datagramStats                 `json:"datagram_stats,omitempty"`
	ObjectPullStats       *objectPullStats               `json:"object_pull_stats,omitempty"`
	RejectedDigests       map[string]rejectedDigestState `json:"rejected_digests,omitempty"`
}

func (p *observerProvider) Peers(peerFilter string) (any, error) {
	d := p.daemon
	if d == nil || d.Sync == nil {
		return map[string]any{"peers": []any{}}, nil
	}
	state, _, _ := d.snapshotState()
	if state == nil {
		return map[string]any{"peers": []any{}}, nil
	}
	peerIDs := make([]string, 0, len(state.SyncPeers))
	for id := range state.SyncPeers {
		if isLocalObserverPeer(id, d.Sync.Config, state) {
			continue
		}
		peerIDs = append(peerIDs, id)
	}
	for _, peer := range configuredBootstrapPeers(d.Sync.Config) {
		if isLocalObserverPeer(peer.ID, d.Sync.Config, state) {
			continue
		}
		if _, ok := state.SyncPeers[peer.ID]; !ok {
			peerIDs = append(peerIDs, peer.ID)
		}
	}
	for id := range gossip.ExtractPeerEndpointsAt(state.Network, d.Sync.now()) {
		if isLocalObserverPeer(id, d.Sync.Config, state) {
			continue
		}
		if _, ok := state.SyncPeers[id]; !ok {
			peerIDs = append(peerIDs, id)
		}
	}
	sort.Slice(peerIDs, func(i, j int) bool { return observerZoneLess(peerIDs[i], peerIDs[j]) })
	// Single peer detail
	if peerFilter != "" {
		ps, ok := state.SyncPeers[peerFilter]
		if isLocalObserverPeer(peerFilter, d.Sync.Config, state) || (!ok && !peerKnownFromConfigOrDiscovery(peerFilter, d.Sync.Config, state.Network, d.Sync.now())) {
			return nil, observer.Errorf(http.StatusNotFound, "peer not found")
		}
		return peerJSONFromState(peerFilter, ps, d.Sync.Config, state.Network, d.Sync.now()), nil
	}
	// All peers
	peers := make([]peerJSON, 0, len(peerIDs))
	seen := make(map[string]bool, len(peerIDs))
	for _, id := range peerIDs {
		if seen[id] {
			continue
		}
		seen[id] = true
		peers = append(peers, peerJSONFromState(id, state.SyncPeers[id], d.Sync.Config, state.Network, d.Sync.now()))
	}
	return map[string]any{"peers": peers}, nil
}

func peerJSONFromState(id string, ps syncPeerState, config *syncConfigFile, ns *zone.NetworkState, now time.Time) peerJSON {
	configuredAddr := bootstrapAddrForPeer(config, id)
	source := "discovered"
	if configuredAddr != "" {
		source = "bootstrap"
	} else if ps.ObservedAddr != "" {
		source = "observed"
	}
	return peerJSON{
		PeerID:                id,
		Source:                source,
		ConfiguredAddr:        configuredAddr,
		LastSyncUnix:          ps.LastSyncUnix,
		LastAttemptUnix:       ps.LastAttemptUnix,
		BackoffUntilUnix:      ps.BackoffUntilUnix,
		LastRelayUnix:         ps.LastRelayUnix,
		FailureCount:          ps.FailureCount,
		LastError:             ps.LastError,
		LastUpdateSource:      ps.LastUpdateSource,
		LastRelaySuppression:  ps.LastRelaySuppression,
		LastRelaySuppressedAt: ps.LastRelaySuppressedAt,
		DiscoveredAddr:        ps.DiscoveredAddr,
		DiscoveredAtUnix:      ps.DiscoveredAtUnix,
		ObservedAddr:          ps.ObservedAddr,
		ObservedFirstSeenUnix: ps.ObservedFirstSeenUnix,
		ObservedLastSeenUnix:  ps.ObservedLastSeenUnix,
		ObservedLastSyncUnix:  ps.ObservedLastSyncUnix,
		ObservedUntilUnix:     ps.ObservedUntilUnix,
		ObservedSource:        ps.ObservedSource,
		ObservedFailureCount:  ps.ObservedFailureCount,
		ObservedGraceAddrs:    ps.ObservedGraceAddrs,
		Endpoints:             peerEndpointsJSON(id, ps, config, ns, now),
		DatagramStats:         ps.DatagramStats,
		ObjectPullStats:       ps.ObjectPullStats,
		RejectedDigests:       ps.RejectedDigests,
	}
}

func observerZoneLess(a, b string) bool {
	aLabels, aOK := observerZoneLabels(a)
	bLabels, bOK := observerZoneLabels(b)
	if !aOK || !bOK {
		return a < b
	}
	for i := 0; i < len(aLabels) && i < len(bLabels); i++ {
		if aLabels[i] != bLabels[i] {
			return aLabels[i] < bLabels[i]
		}
	}
	if len(aLabels) != len(bLabels) {
		return len(aLabels) < len(bLabels)
	}
	return a < b
}

func observerZoneLabels(path string) ([]string, bool) {
	zp := zone.ZonePath(path)
	if !zp.Valid() {
		return nil, false
	}
	if zp.IsRoot() {
		return nil, true
	}
	labels := strings.Split(strings.TrimSuffix(path, "."), ".")
	for i, j := 0, len(labels)-1; i < j; i, j = i+1, j-1 {
		labels[i], labels[j] = labels[j], labels[i]
	}
	return labels, true
}

func isLocalObserverPeer(peerID string, config *syncConfigFile, state *stateFile) bool {
	if peerID == "" {
		return false
	}
	if config != nil && peerID == config.PeerID {
		return true
	}
	return state != nil && peerID == string(state.ManagedZone)
}

func configuredBootstrapPeers(config *syncConfigFile) []syncConfigPeer {
	if config == nil {
		return nil
	}
	return config.Bootstrap
}

func bootstrapAddrForPeer(config *syncConfigFile, peerID string) string {
	if config == nil {
		return ""
	}
	for _, peer := range config.Bootstrap {
		if peer.ID == peerID {
			return peer.Addr
		}
	}
	return ""
}

func peerKnownFromConfigOrDiscovery(peerID string, config *syncConfigFile, ns *zone.NetworkState, now time.Time) bool {
	if bootstrapAddrForPeer(config, peerID) != "" {
		return true
	}
	_, ok := gossip.ExtractPeerEndpointsAt(ns, now)[peerID]
	return ok
}

func peerEndpointsJSON(peerID string, ps syncPeerState, config *syncConfigFile, ns *zone.NetworkState, now time.Time) []inspect.PeerEndpointView {
	input := inspect.PeerEndpointInput{
		BootstrapAddr:  bootstrapAddrForPeer(config, peerID),
		SelectedAddr:   ps.DiscoveredAddr,
		ObservedAddr:   ps.ObservedAddr,
		ObservedSource: ps.ObservedSource,
		Grace:          make([]inspect.PeerGraceEndpoint, 0, len(ps.ObservedGraceAddrs)),
	}
	discovered := gossip.ExtractPeerEndpointsAt(ns, now)
	for _, ep := range discovered[peerID] {
		input.Signed = append(input.Signed, inspect.PeerSignedEndpoint{
			Address:      ep.Address,
			Port:         ep.Port,
			Protocol:     ep.Protocol,
			Scope:        ep.Scope,
			Source:       ep.Source,
			Priority:     ep.Priority,
			LastObserved: ep.LastObserved,
		})
	}
	for _, grace := range ps.ObservedGraceAddrs {
		input.Grace = append(input.Grace, inspect.PeerGraceEndpoint{Addr: grace.Addr})
	}
	return inspect.BuildPeerEndpoints(input)
}

type observerLinksResponse struct {
	Instances    []observerLinkJSON   `json:"instances"`
	LastRunUnix  int64                `json:"last_run_unix,omitempty"`
	DesiredLinks int                  `json:"desired_links,omitempty"`
	ActualSAs    int                  `json:"actual_sas,omitempty"`
	Actions      []inspect.LinkAction `json:"actions,omitempty"`
	Skipped      []inspect.LinkSkip   `json:"skipped,omitempty"`
	LastError    string               `json:"last_error,omitempty"`
}

type observerLinkJSON struct {
	ID              string               `json:"id"`
	PeerZone        string               `json:"peer_zone"`
	GroupID         string               `json:"group_id,omitempty"`
	TransportKind   string               `json:"transport_kind,omitempty"`
	TransportID     string               `json:"transport_id,omitempty"`
	State           string               `json:"state,omitempty"`
	ActualState     string               `json:"actual_state,omitempty"`
	Endpoint        string               `json:"endpoint,omitempty"`
	InterfaceName   string               `json:"interface_name,omitempty"`
	XFRMIfID        uint32               `json:"xfrm_if_id,omitempty"`
	DesiredSpecHash string               `json:"desired_spec_hash,omitempty"`
	Desired         *inspect.DesiredLink `json:"desired,omitempty"`
	ActualSA        *inspect.LinkSA      `json:"actual_sa,omitempty"`
	Health          *inspect.LinkHealth  `json:"health,omitempty"`
	Routing         inspect.LinkRouting  `json:"routing"`
	Rotation        inspect.LinkRotation `json:"rotation"`
	Takeover        inspect.LinkTakeover `json:"takeover"`
	Owner           inspect.LinkOwner    `json:"owner,omitempty"`
	FailureCount    int                  `json:"failure_count,omitempty"`
	BackoffUntil    int64                `json:"backoff_until,omitempty"`
	LastTransition  int64                `json:"last_transition,omitempty"`
	LastError       string               `json:"last_error,omitempty"`
	Raw             inspect.LinkView     `json:"raw"`
}

func (p *observerProvider) Links(linkFilter string) (any, error) {
	d := p.daemon
	if d == nil || d.Sync == nil {
		return map[string]any{"instances": []any{}}, nil
	}
	state, _, _ := d.snapshotState()
	if state == nil {
		return map[string]any{"instances": []any{}}, nil
	}
	build := buildLinkInspectionFromReconcile(observerRuntime(d), state, d.healthStatusResponse())
	view := build.Inspection
	// Single link detail
	if linkFilter != "" {
		for _, link := range view.Links {
			if link.ID == linkFilter {
				return observerLinkFromInspect(link), nil
			}
		}
		return nil, observer.Errorf(http.StatusNotFound, "link not found")
	}
	// All links
	instances := make([]observerLinkJSON, 0, len(view.Links))
	for _, link := range view.Links {
		instances = append(instances, observerLinkFromInspect(link))
	}
	result := observerLinksResponse{
		Instances:    instances,
		LastRunUnix:  view.Summary.LastRunUnix,
		DesiredLinks: view.Summary.DesiredLinks,
		ActualSAs:    view.Summary.ActualSAs,
		Actions:      view.Actions,
		Skipped:      view.Skipped,
		LastError:    view.Summary.LastError,
	}
	return result, nil
}

func observerLinkFromInspect(link inspect.LinkView) observerLinkJSON {
	return observerLinkJSON{
		ID:              link.ID,
		PeerZone:        link.PeerZone,
		GroupID:         link.GroupID,
		TransportKind:   link.TransportKind,
		TransportID:     link.TransportID,
		State:           link.State,
		ActualState:     link.ActualState,
		Endpoint:        link.Endpoint,
		InterfaceName:   link.InterfaceName,
		XFRMIfID:        link.XFRMIfID,
		DesiredSpecHash: link.DesiredSpecHash,
		Desired:         link.Desired,
		ActualSA:        link.ActualSA,
		Health:          link.Health,
		Routing:         link.Routing,
		Rotation:        link.Rotation,
		Takeover:        link.Takeover,
		Owner:           link.Owner,
		FailureCount:    link.FailureCount,
		BackoffUntil:    link.BackoffUntil,
		LastTransition:  link.LastTransition,
		LastError:       link.LastError,
		Raw:             link,
	}
}

func observerRuntime(d *DaemonService) *Runtime {
	if d == nil || d.Sync == nil {
		return nil
	}
	return d.Sync.App
}

func healthLinksWithContext(d *DaemonService, links []healthLinkJSON) ([]map[string]any, error) {
	if d == nil || d.Sync == nil {
		out := make([]map[string]any, 0, len(links))
		for _, link := range links {
			out = append(out, map[string]any{"health": link})
		}
		return out, nil
	}
	state, _, _ := d.snapshotState()
	if state == nil {
		out := make([]map[string]any, 0, len(links))
		for _, link := range links {
			out = append(out, map[string]any{"health": link})
		}
		return out, nil
	}
	reconcile := state.IPsecReconcile
	desiredByID := map[string]desiredLinkState{}
	if reconcile != nil {
		desiredByID = desiredByInstanceID(reconcile.Desired)
	}
	healthBaseIDs := map[string]bool{}
	out := make([]map[string]any, 0, len(links)+len(state.LinkInstances))
	for _, health := range links {
		if health.InstanceID == "" {
			continue
		}
		healthBaseIDs[health.InstanceID] = true
		out = append(out, healthContextItem(health, state.LinkInstances[health.InstanceID], desiredByID[health.InstanceID]))
	}
	ids := make([]string, 0, len(state.LinkInstances))
	for id := range state.LinkInstances {
		if !healthBaseIDs[id] {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	for _, id := range ids {
		health := healthLinkJSON{
			InstanceID: id,
			State:      "unknown",
		}
		out = append(out, healthContextItem(health, state.LinkInstances[id], desiredByID[id]))
	}
	sort.SliceStable(out, func(i, j int) bool {
		hi := out[i]["health"].(healthLinkJSON)
		hj := out[j]["health"].(healthLinkJSON)
		if hi.InstanceID != hj.InstanceID {
			return hi.InstanceID < hj.InstanceID
		}
		return hi.ProbeRole < hj.ProbeRole
	})
	return out, nil
}

func healthContextItem(health healthLinkJSON, inst linkInstanceState, desired desiredLinkState) map[string]any {
	item := map[string]any{"health": health}
	if inst.ID != "" {
		item["instance"] = inst
		item["peer_zone"] = inst.PeerZone
		item["group_id"] = inst.GroupID
		item["interface_name"] = firstNonEmpty(health.InterfaceName, inst.InterfaceName)
		item["endpoint"] = inst.Endpoint
		item["actual_state"] = inst.ActualState
	}
	if desired.InstanceID != "" {
		item["desired"] = desired
		if _, ok := item["peer_zone"]; !ok {
			item["peer_zone"] = desired.PeerZone
		}
		if _, ok := item["group_id"]; !ok {
			item["group_id"] = desired.GroupID
		}
		if _, ok := item["interface_name"]; !ok {
			item["interface_name"] = firstNonEmpty(health.InterfaceName, desired.InterfaceName)
		}
		item["local_tunnel_addr"] = desired.LocalTunnelAddr
		item["peer_tunnel_addr"] = desired.PeerTunnelAddr
	}
	if _, ok := item["interface_name"]; !ok && health.InterfaceName != "" {
		item["interface_name"] = health.InterfaceName
	}
	return item
}

func (p *observerProvider) Health(linkFilter string) (any, error) {
	d := p.daemon
	links := d.healthStatusResponse()
	contextualLinks, err := healthLinksWithContext(d, links)
	if err != nil {
		return nil, err
	}
	// Single link health detail
	if linkFilter != "" {
		for _, item := range contextualLinks {
			if h, ok := item["health"].(healthLinkJSON); ok && (h.InstanceID == linkFilter || h.ProbeID == linkFilter) {
				return item, nil
			}
		}
		return nil, observer.Errorf(http.StatusNotFound, "health data not found for link %s", linkFilter)
	}
	return map[string]any{
		"datasource": healthDatasourceInfo(observerAppConfig(d)),
		"links":      contextualLinks,
	}, nil
}

func (p *observerProvider) HealthSeries(linkID string, query map[string]string) (any, error) {
	config := observerAppConfig(p.daemon)
	if config == nil {
		return nil, observer.Errorf(http.StatusServiceUnavailable, "health datasource not configured")
	}
	rng, err := parseOptionalDuration(query["range"], time.Hour, "range")
	if err != nil {
		return nil, observer.APIError{StatusCode: http.StatusBadRequest, Err: err}
	}
	step, err := parseOptionalDuration(query["step"], 30*time.Second, "step")
	if err != nil {
		return nil, observer.APIError{StatusCode: http.StatusBadRequest, Err: err}
	}
	result, err := queryHealthSpoolSeries(config, linkID, healthSeriesQuery{
		Metric:    query["metric"],
		ProbeRole: query["probe_role"],
		Range:     rng,
		Step:      step,
		Now:       observerNow(p.daemon),
	})
	if errors.Is(err, errHealthSpoolNotConfigured) {
		return nil, observer.Errorf(http.StatusServiceUnavailable, "health datasource not_configured")
	}
	if err != nil {
		return nil, observer.APIError{StatusCode: http.StatusBadRequest, Err: err}
	}
	return map[string]any{
		"datasource": healthDatasourceInfo(config),
		"link_id":    linkID,
		"series":     result,
	}, nil
}

func observerAppConfig(d *DaemonService) *appConfig {
	if d == nil || d.Sync == nil || d.Sync.App == nil {
		return nil
	}
	return d.Sync.App.Config
}

func observerNow(d *DaemonService) time.Time {
	if d != nil && d.Sync != nil {
		return d.Sync.now()
	}
	return time.Now()
}

func parseOptionalDuration(raw string, fallback time.Duration, name string) (time.Duration, error) {
	if strings.TrimSpace(raw) == "" {
		return fallback, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid %s: %q", name, raw)
	}
	if d <= 0 {
		return 0, fmt.Errorf("%s must be positive", name)
	}
	return d, nil
}

func (p *observerProvider) Routes() (any, error) {
	d := p.daemon
	if d == nil || d.Sync == nil {
		return &routesDumpResponse{}, nil
	}
	state, _, _ := d.snapshotState()
	if state == nil {
		return &routesDumpResponse{}, nil
	}
	now := d.Sync.now()
	ars, _ := routing.BuildAuthorizedRouteSet(state.Network, now)
	return buildRoutesDumpResponse(state.ManagedZone, ars), nil
}

func (p *observerProvider) Bird() (any, error) {
	d := p.daemon
	if d == nil || d.Sync == nil {
		return map[string]any{"instances": map[string]any{}}, nil
	}
	state, _, _ := d.snapshotState()
	if state == nil {
		return map[string]any{"instances": map[string]any{}}, nil
	}
	lastRoutingError := ""
	if state.RoutingReconcile != nil {
		lastRoutingError = state.RoutingReconcile.LastError
	}
	return map[string]any{
		"instances":          cloneBirdInstances(state.BirdInstances),
		"last_routing_error": lastRoutingError,
	}, nil
}

// webSubFS returns the embedded web/ directory as an fs.FS for testing.
func webSubFS() fs.FS {
	return observer.WebSubFS()
}
