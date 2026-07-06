package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/Catofes/higgs/internal/inspect"
	inspecthttp "github.com/Catofes/higgs/internal/inspect/http"
	"github.com/Catofes/higgs/internal/observer"
	"github.com/Catofes/higgs/pkg/core/zone"
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
		return inspecthttp.StatusResponse{DaemonOnline: false}, nil
	}
	state, _, meta := d.snapshotState()
	if state == nil {
		return inspecthttp.StatusResponse{DaemonOnline: false}, nil
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
	return inspecthttp.StatusResponse{
		PeerID:            peerID,
		ManagedZone:       managedZone,
		ListenAddr:        listenAddr,
		DaemonOnline:      true,
		StateRevision:     meta.Revision,
		SnapshotTimeUnix:  meta.SnapshotTime.Unix(),
		Dirty:             meta.Dirty,
		ReconcileProgress: meta.ReconcileProgress,
		KnownZones:        knownZones,
		KnownPeers:        knownPeers,
		LinkInstances:     linkInstances,
		DesiredLinks:      desiredLinks,
		LastLinkError:     lastLinkError,
		LastRoutingError:  lastRoutingError,
		LastSyncUnix:      lastSyncUnix,
		LastReconcileUnix: lastReconcileUnix,
	}, nil
}

func (p *observerProvider) Zones(zoneFilter string) (any, error) {
	d := p.daemon
	if d == nil || d.Sync == nil {
		return inspecthttp.ZonesResponse{Zones: []inspecthttp.ZoneSummaryJSON{}}, nil
	}
	state, _, _ := d.snapshotState()
	if state == nil {
		return inspecthttp.ZonesResponse{Zones: []inspecthttp.ZoneSummaryJSON{}}, nil
	}
	if state.Network == nil {
		return inspecthttp.ZonesResponse{Zones: []inspecthttp.ZoneSummaryJSON{}}, nil
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
	return inspecthttp.ZonesFromNetwork(state.Network, now.Unix()), nil
}

func (p *observerProvider) Peers(peerFilter string) (any, error) {
	d := p.daemon
	if d == nil || d.Sync == nil {
		return inspecthttp.PeersResponse{Peers: []inspecthttp.PeerJSON{}}, nil
	}
	state, _, _ := d.snapshotState()
	if state == nil {
		return inspecthttp.PeersResponse{Peers: []inspecthttp.PeerJSON{}}, nil
	}
	peerSet := inspectPeerSetInput(state, d.Sync.Config, d.Sync.now())
	peerIDs := inspect.BuildPeerIDs(peerSet)
	// Single peer detail
	if peerFilter != "" {
		ps := state.SyncPeers[peerFilter]
		if !inspect.PeerKnown(peerSet, peerFilter) {
			return nil, observer.Errorf(http.StatusNotFound, "peer not found")
		}
		return peerJSONFromState(peerFilter, ps, d.Sync.Config, state.Network, d.Sync.now()), nil
	}
	// All peers
	peers := make([]inspecthttp.PeerJSON, 0, len(peerIDs))
	seen := make(map[string]bool, len(peerIDs))
	for _, id := range peerIDs {
		if seen[id] {
			continue
		}
		seen[id] = true
		peers = append(peers, peerJSONFromState(id, state.SyncPeers[id], d.Sync.Config, state.Network, d.Sync.now()))
	}
	return inspecthttp.PeersResponse{Peers: peers}, nil
}

func peerJSONFromState(id string, ps syncPeerState, config *syncConfigFile, ns *zone.NetworkState, now time.Time) inspecthttp.PeerJSON {
	configuredAddr := bootstrapAddrForPeer(config, id)
	source := "discovered"
	if configuredAddr != "" {
		source = "bootstrap"
	} else if ps.ObservedAddr != "" {
		source = "observed"
	}
	return inspecthttp.PeerJSON{
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
		Endpoints:             inspectPeerEndpoints(id, ps, config, ns, now),
		DatagramStats:         ps.DatagramStats,
		ObjectPullStats:       ps.ObjectPullStats,
		RejectedDigests:       ps.RejectedDigests,
	}
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

func (p *observerProvider) Links(linkFilter string) (any, error) {
	d := p.daemon
	if d == nil || d.Sync == nil {
		return inspecthttp.LinksResponse{Instances: []inspecthttp.LinkJSON{}}, nil
	}
	state, _, _ := d.snapshotState()
	if state == nil {
		return inspecthttp.LinksResponse{Instances: []inspecthttp.LinkJSON{}}, nil
	}
	build := buildLinkInspectionFromReconcile(observerRuntime(d), state, d.healthStatusResponse())
	view := build.Inspection
	// Single link detail
	if linkFilter != "" {
		for _, link := range view.Links {
			if link.ID == linkFilter {
				return inspecthttp.LinkFromInspect(link), nil
			}
		}
		return nil, observer.Errorf(http.StatusNotFound, "link not found")
	}
	return inspecthttp.LinksFromInspection(view), nil
}

func observerRuntime(d *DaemonService) *Runtime {
	if d == nil || d.Sync == nil {
		return nil
	}
	return d.Sync.App
}

func healthLinksWithContext(d *DaemonService, links []healthLinkJSON) ([]inspecthttp.HealthContextItem, error) {
	if d == nil || d.Sync == nil {
		out := make([]inspecthttp.HealthContextItem, 0, len(links))
		for _, link := range links {
			out = append(out, inspecthttp.HealthContextItem{Health: link})
		}
		return out, nil
	}
	state, _, _ := d.snapshotState()
	if state == nil {
		out := make([]inspecthttp.HealthContextItem, 0, len(links))
		for _, link := range links {
			out = append(out, inspecthttp.HealthContextItem{Health: link})
		}
		return out, nil
	}
	reconcile := state.IPsecReconcile
	desiredByID := map[string]desiredLinkState{}
	if reconcile != nil {
		desiredByID = desiredByInstanceID(reconcile.Desired)
	}
	healthBaseIDs := map[string]bool{}
	out := make([]inspecthttp.HealthContextItem, 0, len(links)+len(state.LinkInstances))
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
		hi := out[i].Health.(healthLinkJSON)
		hj := out[j].Health.(healthLinkJSON)
		if hi.InstanceID != hj.InstanceID {
			return hi.InstanceID < hj.InstanceID
		}
		return hi.ProbeRole < hj.ProbeRole
	})
	return out, nil
}

func healthContextItem(health healthLinkJSON, inst linkInstanceState, desired desiredLinkState) inspecthttp.HealthContextItem {
	item := inspecthttp.HealthContextItem{Health: health}
	if inst.ID != "" {
		item.Instance = inst
		item.PeerZone = inst.PeerZone
		item.GroupID = inst.GroupID
		item.InterfaceName = firstNonEmpty(health.InterfaceName, inst.InterfaceName)
		item.Endpoint = inst.Endpoint
		item.ActualState = inst.ActualState
	}
	if desired.InstanceID != "" {
		item.Desired = desired
		if item.PeerZone == nil {
			item.PeerZone = desired.PeerZone
		}
		if item.GroupID == "" {
			item.GroupID = desired.GroupID
		}
		if item.InterfaceName == "" {
			item.InterfaceName = firstNonEmpty(health.InterfaceName, desired.InterfaceName)
		}
		item.LocalTunnelAddr = desired.LocalTunnelAddr
		item.PeerTunnelAddr = desired.PeerTunnelAddr
	}
	if item.InterfaceName == "" && health.InterfaceName != "" {
		item.InterfaceName = health.InterfaceName
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
			if h, ok := item.Health.(healthLinkJSON); ok && (h.InstanceID == linkFilter || h.ProbeID == linkFilter) {
				return item, nil
			}
		}
		return nil, observer.Errorf(http.StatusNotFound, "health data not found for link %s", linkFilter)
	}
	return inspecthttp.HealthResponse{
		Datasource: healthDatasourceInfo(observerAppConfig(d)),
		Links:      contextualLinks,
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
	return inspecthttp.HealthSeriesResponse{
		Datasource: healthDatasourceInfo(config),
		LinkID:     linkID,
		Series:     result,
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
		return &inspecthttp.RoutesResponse{}, nil
	}
	state, _, _ := d.snapshotState()
	if state == nil {
		return &inspecthttp.RoutesResponse{}, nil
	}
	now := d.Sync.now()
	ars, _ := routing.BuildAuthorizedRouteSet(state.Network, now)
	return buildRoutesDumpResponse(state.ManagedZone, ars), nil
}

func (p *observerProvider) Bird() (any, error) {
	d := p.daemon
	if d == nil || d.Sync == nil {
		return inspecthttp.BirdResponse{Instances: map[string]any{}}, nil
	}
	state, _, _ := d.snapshotState()
	if state == nil {
		return inspecthttp.BirdResponse{Instances: map[string]any{}}, nil
	}
	lastRoutingError := ""
	if state.RoutingReconcile != nil {
		lastRoutingError = state.RoutingReconcile.LastError
	}
	return inspecthttp.BirdResponse{
		Instances:        cloneBirdInstances(state.BirdInstances),
		LastRoutingError: lastRoutingError,
	}, nil
}

// webSubFS returns the embedded web/ directory as an fs.FS for testing.
func webSubFS() fs.FS {
	return observer.WebSubFS()
}
