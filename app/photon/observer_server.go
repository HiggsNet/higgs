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

	inspecthttp "github.com/HiggsNet/photon/internal/inspect/http"
	"github.com/HiggsNet/photon/internal/observability"
	"github.com/HiggsNet/photon/internal/observer"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/health"
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

// observerLinkIDsPayload returns {link_ids: [...]} derived from the current
// state snapshot's link instance keys.
func (d *DaemonService) observerLinkIDsPayload() any {
	ids := d.StateStore.linkIDsProjection()
	if len(ids) == 0 {
		return nil
	}
	return observerIDsPayload("link_ids", ids)
}

// observerPeerIDsPayload returns {peer_ids: [...]} derived from the current
// state snapshot's sync peer keys.
func (d *DaemonService) observerPeerIDsPayload() any {
	ids := d.StateStore.peerIDsProjection()
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
	if d == nil || d.Sync == nil {
		return inspecthttp.StatusResponse{DaemonOnline: false}, nil
	}
	projection := d.StateStore.statusProjection()
	if !projection.loaded {
		return inspecthttp.StatusResponse{DaemonOnline: false}, nil
	}
	routingLastRunUnix := projection.routingLastRunUnix
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
	managedZone = string(projection.managedZone)
	return inspecthttp.BuildStatusResponse(inspecthttp.StatusInput{
		PeerID:             peerID,
		ManagedZone:        managedZone,
		ListenAddr:         listenAddr,
		DaemonOnline:       true,
		StateRevision:      projection.meta.Revision,
		SnapshotTimeUnix:   projection.meta.SnapshotTime.Unix(),
		Dirty:              projection.meta.Dirty,
		ReconcileProgress:  projection.meta.ReconcileProgress,
		KnownZones:         projection.knownZones,
		KnownPeers:         projection.knownPeers,
		LinkInstances:      projection.linkInstances,
		DesiredLinks:       projection.desiredLinks,
		LastLinkError:      projection.lastLinkError,
		LastRoutingError:   projection.lastRoutingError,
		LastSyncUnix:       projection.lastSyncUnix,
		IPsecLastRunUnix:   projection.ipsecLastRunUnix,
		RoutingLastRunUnix: routingLastRunUnix,
	}), nil
}

func (p *observerProvider) Zones(zoneFilter string) (any, error) {
	d := p.daemon
	if d == nil || d.Sync == nil {
		return inspecthttp.ZonesResponse{Zones: []inspecthttp.ZoneSummaryJSON{}}, nil
	}
	now := d.Sync.now()
	zp := zone.ZonePath(zoneFilter)
	projection := d.StateStore.zonesProjection(zp, now)
	if !projection.loaded {
		return inspecthttp.ZonesResponse{Zones: []inspecthttp.ZoneSummaryJSON{}}, nil
	}
	// Single zone detail
	if zoneFilter != "" {
		if !projection.found {
			return nil, observer.Errorf(http.StatusNotFound, "zone not found")
		}
		return projection.detail, nil
	}
	return projection.list, nil
}

func (p *observerProvider) Peers(peerFilter string) (any, error) {
	d := p.daemon
	if d == nil || d.Sync == nil {
		return inspecthttp.PeersResponse{Peers: []inspecthttp.PeerJSON{}}, nil
	}
	observabilitySnapshots := d.peerObservabilitySnapshots()
	projection := d.StateStore.peersProjection(d.Sync.Config, d.Sync.now(), observabilitySnapshots)
	if !projection.loaded {
		return inspecthttp.PeersResponse{Peers: []inspecthttp.PeerJSON{}}, nil
	}
	// Single peer detail
	if peerFilter != "" {
		if !projection.known[peerFilter] {
			return nil, observer.Errorf(http.StatusNotFound, "peer not found")
		}
		return projection.peers[peerFilter], nil
	}
	// All peers
	peers := make([]inspecthttp.PeerJSON, 0, len(projection.order))
	for _, id := range projection.order {
		peers = append(peers, projection.peers[id])
	}
	return inspecthttp.PeersResponse{Peers: peers}, nil
}

func (d *DaemonService) peerObservabilitySnapshots() map[string]observability.PeerSnapshot {
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
	if d == nil || d.Sync == nil {
		return inspecthttp.LinksResponse{Instances: []inspecthttp.LinkJSON{}}, nil
	}
	projection := d.StateStore.linksStatusProjection(observerRuntime(d), d.healthStatusResponse())
	if !projection.loaded {
		return inspecthttp.LinksResponse{Instances: []inspecthttp.LinkJSON{}}, nil
	}
	view := projection.build.Inspection
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
		return inspecthttp.BuildHealthContext(inspecthttp.HealthContextInput{
			HealthLinks: inspectHealthLinks(links),
		}), nil
	}
	return d.StateStore.healthContextProjection(links), nil
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
		Datasource: healthDatasourceInfo(observerAppConfig(d)),
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
	projection := d.StateStore.routesProjection(d.Sync.now())
	if !projection.loaded || projection.err != nil {
		return &inspecthttp.RoutesResponse{}, nil
	}
	return projection.routes, nil
}

func (p *observerProvider) Bird() (any, error) {
	d := p.daemon
	if d == nil || d.Sync == nil {
		return inspecthttp.BirdResponse{Instances: map[string]any{}}, nil
	}
	projection := d.StateStore.birdStatusProjection()
	if !projection.loaded {
		return inspecthttp.BirdResponse{Instances: map[string]any{}}, nil
	}
	return inspecthttp.BirdResponse{
		Instances:        projection.instances,
		LastRoutingError: projection.lastRoutingError,
	}, nil
}
