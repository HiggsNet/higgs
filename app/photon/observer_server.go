package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
	inspecthttp "github.com/HiggsNet/photon/internal/inspect/http"
	"github.com/HiggsNet/photon/internal/observability"
	"github.com/HiggsNet/photon/internal/observability/healthspool"
	"github.com/HiggsNet/photon/internal/observer"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/health"
	"github.com/HiggsNet/photon/pkg/routing"
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

// observerIDsPayload builds a lightweight {key: [sorted ids]} event payload.
// Payloads carry ids only — never diffs or large objects. Returns nil when
// there are no ids so the payload field is omitted entirely.
func observerIDsPayload(key string, ids []string) map[string]any {
	if len(ids) == 0 {
		return nil
	}
	sort.Strings(ids)
	return map[string]any{key: ids}
}

// observerLinkIDsPayload returns {link_ids: [...]} from Linux runtime state.
func (d *DaemonService) observerLinkIDsPayload() any {
	if d == nil || d.StateStore == nil {
		return nil
	}
	d.StateStore.mu.RLock()
	ids := make([]string, 0, len(d.StateStore.runtime.LinkInstances))
	for id := range d.StateStore.runtime.LinkInstances {
		ids = append(ids, id)
	}
	d.StateStore.mu.RUnlock()
	if len(ids) == 0 {
		return nil
	}
	return observerIDsPayload("link_ids", ids)
}

// observerPeerIDsPayload returns {peer_ids: [...]} from the common gossip
// checkpoint.
func (d *DaemonService) observerPeerIDsPayload() any {
	if d == nil || d.StateStore == nil || d.StateStore.common == nil {
		return nil
	}
	view := d.StateStore.common.ReadView()
	if view.Gossip == nil {
		return nil
	}
	ids := make([]string, 0, len(view.Gossip.Peers))
	for id := range view.Gossip.Peers {
		ids = append(ids, id)
	}
	if len(ids) == 0 {
		return nil
	}
	return observerIDsPayload("peer_ids", ids)
}

// observerHealthLinkIDsPayload returns {link_ids: [...]} derived from the
// health manager's current target snapshot.
func (d *DaemonService) observerHealthLinkIDsPayload() any {
	if d == nil || d.health == nil || d.Sync == nil {
		return nil
	}
	snapshot := d.health.Snapshot(d.Sync.now())
	ids := make([]string, 0, len(snapshot))
	for _, h := range snapshot {
		if h.InstanceID != "" {
			ids = append(ids, h.InstanceID)
		}
	}
	return observerIDsPayload("link_ids", ids)
}

// handler returns the HTTP handler for the observer, including REST APIs,
// SSE events, and static UI.
func (s *observerServer) handler() http.Handler {
	return s.server.Handler()
}

func (p *observerProvider) Status() (any, error) {
	d := p.daemon
	if d == nil || d.Sync == nil || d.StateStore == nil || d.StateStore.common == nil {
		return inspect.DaemonStatusView{DaemonOnline: false}, nil
	}
	store := d.StateStore
	store.writeMu.Lock()
	view := store.common.ReadView()
	store.mu.RLock()
	meta := store.metaLocked()
	linkInstances := 0
	desiredLinks := 0
	lastLinkError := ""
	lastRoutingError := ""
	ipsecLastRunUnix := int64(0)
	routingLastRunUnix := int64(0)
	if store.runtime != nil {
		linkInstances = len(store.runtime.LinkInstances)
		if store.runtime.IPsecReconcile != nil {
			desiredLinks = store.runtime.IPsecReconcile.DesiredLinks
			lastLinkError = store.runtime.IPsecReconcile.LastError
			ipsecLastRunUnix = store.runtime.IPsecReconcile.LastRunUnix
		}
		if store.runtime.RoutingReconcile != nil {
			lastRoutingError = store.runtime.RoutingReconcile.LastError
			routingLastRunUnix = store.runtime.RoutingReconcile.LastRunUnix
		}
	}
	store.mu.RUnlock()
	store.writeMu.Unlock()
	if view.State == nil {
		return inspect.DaemonStatusView{DaemonOnline: false}, nil
	}
	knownZones := 0
	if view.State.Network != nil {
		knownZones = len(view.State.Network.Zones)
	}
	knownPeers := 0
	lastSyncUnix := int64(0)
	if view.Gossip != nil {
		knownPeers = len(view.Gossip.Peers)
		for _, peer := range view.Gossip.Peers {
			if peer.LastSyncUnix > lastSyncUnix {
				lastSyncUnix = peer.LastSyncUnix
			}
		}
	}
	if lastRun := d.routingLastRunUnix.Load(); lastRun != 0 {
		routingLastRunUnix = lastRun
	}
	peerID := ""
	listenAddr := ""
	managedZone := ""
	if d.Sync.Config != nil {
		peerID = d.Sync.Config.PeerID
		listenAddr = d.Sync.Config.ListenAddr
	}
	managedZone = string(view.State.ManagedZone)
	return inspect.BuildDaemonStatus(inspect.DaemonStatusInput{
		PeerID:             peerID,
		ManagedZone:        managedZone,
		ListenAddr:         listenAddr,
		DaemonOnline:       true,
		StateRevision:      meta.Revision,
		SnapshotTimeUnix:   meta.SnapshotTime.Unix(),
		Dirty:              meta.Dirty,
		ReconcileProgress:  meta.ReconcileProgress,
		KnownZones:         knownZones,
		KnownPeers:         knownPeers,
		LinkInstances:      linkInstances,
		DesiredLinks:       desiredLinks,
		LastLinkError:      lastLinkError,
		LastRoutingError:   lastRoutingError,
		LastSyncUnix:       lastSyncUnix,
		IPsecLastRunUnix:   ipsecLastRunUnix,
		RoutingLastRunUnix: routingLastRunUnix,
	}), nil
}

func (p *observerProvider) Zones(zoneFilter string) (any, error) {
	d := p.daemon
	if d == nil || d.Sync == nil || d.StateStore == nil || d.StateStore.common == nil {
		return inspect.ZonesView{Zones: []inspect.ZoneSummaryView{}}, nil
	}
	now := d.Sync.now()
	zp := zone.ZonePath(zoneFilter)
	view := d.StateStore.common.ReadView()
	if view.State == nil || view.State.Network == nil {
		return inspect.ZonesView{Zones: []inspect.ZoneSummaryView{}}, nil
	}
	if zp != "" {
		zs := view.State.Network.Zones[zp]
		if zs == nil {
			return nil, observer.Errorf(http.StatusNotFound, "zone not found")
		}
		return inspect.BuildZoneDetail(inspect.ZoneDetailInput{
			Path: zp, State: zs, Network: view.State.Network, Now: now, IncludeHistory: true,
		}), nil
	}
	return inspect.BuildZonesView(view.State.Network, now), nil
}

func (p *observerProvider) Peers(peerFilter string) (any, error) {
	d := p.daemon
	if d == nil || d.Sync == nil || d.StateStore == nil || d.StateStore.common == nil {
		return inspect.PeersView{Peers: []inspect.PeerView{}}, nil
	}
	view := d.StateStore.common.ReadView()
	if view.State == nil {
		return inspect.PeersView{Peers: []inspect.PeerView{}}, nil
	}
	now := d.Sync.now()
	observabilitySnapshots := d.peerObservabilitySnapshots()
	peers := syncPeerReadView(view.Gossip)
	peerSet := inspectPeerSetInput(view.State.ManagedZone, view.State.Network, peers, d.Sync.Config, now)
	for peerID := range observabilitySnapshots {
		peerSet.RuntimeIDs = append(peerSet.RuntimeIDs, peerID)
	}
	ids := inspect.BuildPeerIDs(peerSet)
	items := make(map[string]inspect.PeerView, len(ids))
	for _, peerID := range ids {
		peer := peers[peerID]
		observed := observabilitySnapshots[peerID]
		items[peerID] = inspect.BuildPeerView(
			peerID,
			bootstrapAddrForPeer(d.Sync.Config, peerID),
			inspectPeerEndpoints(peerID, peer, observed, d.Sync.Config, view.State.Network, now),
			peer,
			observed,
		)
	}
	if peerFilter != "" {
		peer, ok := items[peerFilter]
		if !ok {
			return nil, observer.Errorf(http.StatusNotFound, "peer not found")
		}
		return peer, nil
	}
	response := make([]inspect.PeerView, 0, len(ids))
	for _, peerID := range ids {
		response = append(response, items[peerID])
	}
	return inspect.PeersView{Peers: response}, nil
}

func (d *DaemonService) peerObservabilitySnapshots() map[string]observability.PeerDiagnostics {
	if d == nil || d.PeerObservability == nil {
		return nil
	}
	now := time.Now()
	if d.Sync != nil {
		now = d.Sync.now()
	}
	return d.PeerObservability.Snapshots(now)
}

func (p *observerProvider) Links(linkFilter string) (any, error) {
	d := p.daemon
	if d == nil || d.Sync == nil || d.StateStore == nil {
		return inspecthttp.LinksResponse{Instances: []inspecthttp.LinkJSON{}}, nil
	}
	health := d.healthStatusResponse()
	d.StateStore.mu.RLock()
	build := buildStoredLinkInspection(observerRuntime(d), d.StateStore.runtime.LinkInstances, d.StateStore.runtime.IPsecReconcile, d.StateStore.runtime.BirdInstances, health)
	d.StateStore.mu.RUnlock()
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
	input := inspecthttp.HealthContextInput{HealthLinks: inspectHealthLinks(links)}
	if d == nil || d.Sync == nil || d.StateStore == nil {
		return inspecthttp.BuildHealthContext(input), nil
	}
	d.StateStore.mu.RLock()
	if d.StateStore.runtime == nil {
		d.StateStore.mu.RUnlock()
		return inspecthttp.BuildHealthContext(input), nil
	}
	desiredByID := map[string]desiredLinkState{}
	if d.StateStore.runtime.IPsecReconcile != nil {
		desiredByID = desiredByInstanceID(d.StateStore.runtime.IPsecReconcile.Desired)
	}
	input.Instances = inspectHealthInstances(d.StateStore.runtime.LinkInstances)
	input.Desired = inspectHealthDesired(desiredByID)
	d.StateStore.mu.RUnlock()
	input.Unknown = func(instanceID string) any {
		return healthLinkJSON{InstanceID: instanceID, State: "unknown"}
	}
	return inspecthttp.BuildHealthContext(input), nil
}

func inspectHealthLinks(links []healthLinkJSON) []inspecthttp.HealthLinkContextInput {
	out := make([]inspecthttp.HealthLinkContextInput, 0, len(links))
	for _, health := range links {
		out = append(out, inspecthttp.HealthLinkContextInput{
			InstanceID:    health.InstanceID,
			ProbeID:       health.ProbeID,
			ProbeRole:     health.ProbeRole,
			InterfaceName: health.InterfaceName,
			Health:        health,
		})
	}
	return out
}

func inspectHealthInstances(instances map[string]linkInstanceState) map[string]inspecthttp.HealthInstanceContextInput {
	out := make(map[string]inspecthttp.HealthInstanceContextInput, len(instances))
	for id, inst := range instances {
		out[id] = inspecthttp.HealthInstanceContextInput{
			ID:            inst.ID,
			PeerZone:      inst.PeerZone,
			GroupID:       inst.GroupID,
			InterfaceName: inst.InterfaceName,
			Endpoint:      inst.Endpoint,
			ActualState:   inst.ActualState,
			Instance:      inst,
		}
	}
	return out
}

func inspectHealthDesired(desiredByID map[string]desiredLinkState) map[string]inspecthttp.HealthDesiredContextInput {
	out := make(map[string]inspecthttp.HealthDesiredContextInput, len(desiredByID))
	for id, desired := range desiredByID {
		out[id] = inspecthttp.HealthDesiredContextInput{
			InstanceID:      desired.InstanceID,
			PeerZone:        desired.PeerZone,
			GroupID:         desired.GroupID,
			InterfaceName:   desired.InterfaceName,
			LocalTunnelAddr: desired.LocalTunnelAddr,
			PeerTunnelAddr:  desired.PeerTunnelAddr,
			Desired:         desired,
		}
	}
	return out
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
		Datasource: daemonHealthDatasource(d),
		Links:      contextualLinks,
	}, nil
}

func (p *observerProvider) OpenMetrics() (string, error) {
	d := p.daemon
	config := observerAppConfig(d)
	if config == nil || !config.Health.MetricsEnabled {
		return "", fmt.Errorf("health metrics are not enabled")
	}
	if d == nil || d.health == nil {
		return "", fmt.Errorf("health manager is not configured")
	}
	links := d.health.Snapshot(observerNow(d))
	errorsTotal := make(map[string]int, len(links))
	for _, link := range links {
		key := link.ProbeID
		if key == "" {
			key = link.InstanceID
		}
		errorsTotal[key] = d.health.ErrorsTotal(key)
	}
	var output bytes.Buffer
	if err := health.RenderOpenMetrics(&output, health.CollectMetrics(links), errorsTotal); err != nil {
		return "", err
	}
	return output.String(), nil
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
	if p.daemon == nil || p.daemon.healthSpool == nil {
		return nil, observer.Errorf(http.StatusServiceUnavailable, "health datasource not_configured")
	}
	result, err := p.daemon.healthSpool.Query(linkID, healthspool.SeriesQuery{
		Metric:    query["metric"],
		ProbeRole: query["probe_role"],
		Range:     rng,
		Step:      step,
		Now:       observerNow(p.daemon),
	})
	if errors.Is(err, healthspool.ErrNotConfigured) {
		return nil, observer.Errorf(http.StatusServiceUnavailable, "health datasource not_configured")
	}
	if err != nil {
		return nil, observer.APIError{StatusCode: http.StatusBadRequest, Err: err}
	}
	return inspecthttp.HealthSeriesResponse{
		Datasource: p.daemon.healthSpool.Config().Datasource(),
		LinkID:     linkID,
		Series:     result,
	}, nil
}

func daemonHealthDatasource(d *DaemonService) map[string]any {
	if d == nil || d.healthSpool == nil {
		return healthspool.Config{}.Datasource()
	}
	return d.healthSpool.Config().Datasource()
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
	if d == nil || d.Sync == nil || d.StateStore == nil || d.StateStore.common == nil {
		return &inspecthttp.RoutesResponse{}, nil
	}
	view := d.StateStore.common.ReadView()
	if view.State == nil || view.State.Network == nil {
		return &inspecthttp.RoutesResponse{}, nil
	}
	ars, err := routing.BuildAuthorizedRouteSet(view.State.Network, d.Sync.now())
	if err != nil {
		return &inspecthttp.RoutesResponse{}, nil
	}
	return inspecthttp.RoutesFromAuthorizedSet(view.State.ManagedZone, ars), nil
}

func (p *observerProvider) Bird() (any, error) {
	d := p.daemon
	if d == nil || d.Sync == nil || d.StateStore == nil {
		return inspecthttp.BirdResponse{Instances: map[string]any{}}, nil
	}
	d.StateStore.mu.RLock()
	instances := cloneBirdInstances(d.StateStore.runtime.BirdInstances)
	lastRoutingError := ""
	if d.StateStore.runtime.RoutingReconcile != nil {
		lastRoutingError = d.StateStore.runtime.RoutingReconcile.LastError
	}
	d.StateStore.mu.RUnlock()
	return inspecthttp.BirdResponse{
		Instances:        instances,
		LastRoutingError: lastRoutingError,
	}, nil
}
