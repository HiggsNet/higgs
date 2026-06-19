package main

import (
	"context"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/Catofes/higgs/pkg/core/gossip"
	"github.com/Catofes/higgs/pkg/core/zone"
	higgscrypto "github.com/Catofes/higgs/pkg/crypto"
	"github.com/Catofes/higgs/pkg/routing"
)

//go:embed web/*
var observerWebFS embed.FS

// observerServer is the read-only HTTP observer for daemon live state.
// It serves REST snapshot APIs, SSE events, and a static UI.
type observerServer struct {
	daemon *DaemonService
	config observerConfig
	hub    *sseHub
}

// newObserverServer creates a new read-only HTTP observer from the daemon
// service and observer configuration. Returns nil if observer is disabled.
func newObserverServer(d *DaemonService, cfg observerConfig) *observerServer {
	if !cfg.Enabled || d == nil {
		return nil
	}
	return &observerServer{
		daemon: d,
		config: cfg,
		hub:    newSSEHub(),
	}
}

// startObserverServer starts the HTTP observer if enabled. It returns a
// cleanup function that gracefully shuts down the server.
func (d *DaemonService) startObserverServer(ctx context.Context) (func(), error) {
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
	httpServer := &http.Server{
		Handler:      srv.handler(),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
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
	d.observerHub.broadcast(sseEvent{Type: eventType, Payload: payload})
}

// handler returns the HTTP handler for the observer, including REST APIs,
// SSE events, and static UI.
func (s *observerServer) handler() http.Handler {
	mux := http.NewServeMux()
	// REST API endpoints
	mux.HandleFunc("/api/v1/status", s.handleStatus)
	mux.HandleFunc("/api/v1/zones", s.handleZones)
	mux.HandleFunc("/api/v1/zones/", s.handleZones)
	mux.HandleFunc("/api/v1/peers", s.handlePeers)
	mux.HandleFunc("/api/v1/peers/", s.handlePeers)
	mux.HandleFunc("/api/v1/links", s.handleLinks)
	mux.HandleFunc("/api/v1/links/", s.handleLinks)
	mux.HandleFunc("/api/v1/health", s.handleHealth)
	mux.HandleFunc("/api/v1/health/", s.handleHealth)
	mux.HandleFunc("/api/v1/routes", s.handleRoutes)
	mux.HandleFunc("/api/v1/bird", s.handleBird)
	mux.HandleFunc("/api/v1/events", s.handleEvents)
	// Static UI
	mux.HandleFunc("/", s.handleStatic)
	return mux
}

// apiResponse is the unified response wrapper for all REST endpoints.
type apiResponse struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	Data  any    `json:"data"`
}

func writeJSON(w http.ResponseWriter, statusCode int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(v)
}

func writeAPIOK(w http.ResponseWriter, data any) {
	writeJSON(w, http.StatusOK, apiResponse{OK: true, Data: data})
}

func writeAPIError(w http.ResponseWriter, statusCode int, err error) {
	writeJSON(w, statusCode, apiResponse{OK: false, Error: err.Error()})
}

// handleStatus implements GET /api/v1/status
func (s *observerServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeAPIError(w, http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"))
		return
	}
	d := s.daemon
	if d == nil || d.Sync == nil || d.Sync.State == nil {
		writeAPIOK(w, map[string]any{"daemon_online": false})
		return
	}
	state := d.Sync.State
	state.RLock()
	defer state.RUnlock()
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
	writeAPIOK(w, map[string]any{
		"peer_id":             peerID,
		"managed_zone":        managedZone,
		"listen_addr":         listenAddr,
		"daemon_online":       true,
		"known_zones":         knownZones,
		"known_peers":         knownPeers,
		"link_instances":      linkInstances,
		"desired_links":       desiredLinks,
		"last_link_error":     lastLinkError,
		"last_routing_error":  lastRoutingError,
		"last_sync_unix":      lastSyncUnix,
		"last_reconcile_unix": lastReconcileUnix,
	})
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

// handleZones implements GET /api/v1/zones and GET /api/v1/zones/{zone}
func (s *observerServer) handleZones(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeAPIError(w, http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"))
		return
	}
	d := s.daemon
	if d == nil || d.Sync == nil || d.Sync.State == nil {
		writeAPIOK(w, map[string]any{"zones": []any{}})
		return
	}
	state := d.Sync.State
	state.RLock()
	defer state.RUnlock()
	// Check for /api/v1/zones/{zone} pattern
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/zones")
	zoneFilter := strings.TrimPrefix(path, "/")
	zoneFilter = strings.TrimSuffix(zoneFilter, "/")
	if state.Network == nil {
		writeAPIOK(w, map[string]any{"zones": []any{}})
		return
	}
	now := d.Sync.now()
	// Single zone detail
	if zoneFilter != "" {
		zp := zone.ZonePath(zoneFilter)
		zs := state.Network.Zones[zp]
		if zs == nil {
			writeAPIError(w, http.StatusNotFound, fmt.Errorf("zone not found"))
			return
		}
		writeAPIOK(w, zoneDetailJSON(zs, state.Network, zp, now))
		return
	}
	// All zones summary
	zones := make([]zoneSummaryJSON, 0, len(state.Network.Zones))
	paths := make([]zone.ZonePath, 0, len(state.Network.Zones))
	for p := range state.Network.Zones {
		paths = append(paths, p)
	}
	sort.Slice(paths, func(i, j int) bool { return paths[i] < paths[j] })
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
	writeAPIOK(w, map[string]any{
		"zones":       zones,
		"global_root": globalRoot,
	})
}

// zoneDetailJSON builds the detail view for a single zone
func zoneDetailJSON(zs *zone.ZoneState, ns *zone.NetworkState, path zone.ZonePath, now time.Time) map[string]any {
	revoked := ns.IsZoneRevoked(path, now)
	records := make([]map[string]any, 0, len(zs.Records))
	for key, rec := range zs.Records {
		records = append(records, map[string]any{
			"key":     key,
			"version": rec.Version,
			"type":    rec.Type,
		})
	}
	delegations := make([]map[string]any, 0, len(zs.Delegations))
	for childPath, del := range zs.Delegations {
		delegations = append(delegations, map[string]any{
			"child":           string(childPath),
			"authority_epoch": del.AuthorityEpoch,
		})
	}
	revocations := make([]map[string]any, 0, len(zs.Revocations))
	for childPath, rev := range zs.Revocations {
		revocations = append(revocations, map[string]any{
			"child":      string(childPath),
			"reason":     rev.Reason,
			"revoked_at": rev.RevokedAt,
		})
	}
	return map[string]any{
		"path":         string(path),
		"records":      records,
		"delegations":  delegations,
		"revocations":  revocations,
		"revoked":      revoked,
		"record_count": len(zs.Records),
	}
}

// peerJSON is the per-peer view for /api/v1/peers
type peerJSON struct {
	PeerID            string           `json:"peer_id"`
	LastSyncUnix      int64            `json:"last_sync_unix"`
	LastAttemptUnix   int64            `json:"last_attempt_unix"`
	BackoffUntilUnix  int64            `json:"backoff_until_unix"`
	FailureCount      int              `json:"failure_count"`
	LastError         string           `json:"last_error,omitempty"`
	DiscoveredAddr    string           `json:"discovered_addr,omitempty"`
	ObservedAddr      string           `json:"observed_addr,omitempty"`
	ObservedUntilUnix int64            `json:"observed_until_unix,omitempty"`
	DatagramStats     *datagramStats   `json:"datagram_stats,omitempty"`
	ObjectPullStats   *objectPullStats `json:"object_pull_stats,omitempty"`
}

// handlePeers implements GET /api/v1/peers and GET /api/v1/peers/{peer_id}
func (s *observerServer) handlePeers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeAPIError(w, http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"))
		return
	}
	d := s.daemon
	if d == nil || d.Sync == nil || d.Sync.State == nil {
		writeAPIOK(w, map[string]any{"peers": []any{}})
		return
	}
	state := d.Sync.State
	state.RLock()
	defer state.RUnlock()
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/peers")
	peerFilter := strings.TrimPrefix(path, "/")
	peerFilter = strings.TrimSuffix(peerFilter, "/")
	peerIDs := make([]string, 0, len(state.SyncPeers))
	for id := range state.SyncPeers {
		peerIDs = append(peerIDs, id)
	}
	sort.Strings(peerIDs)
	// Single peer detail
	if peerFilter != "" {
		ps, ok := state.SyncPeers[peerFilter]
		if !ok {
			writeAPIError(w, http.StatusNotFound, fmt.Errorf("peer not found"))
			return
		}
		writeAPIOK(w, peerJSONFromState(peerFilter, ps))
		return
	}
	// All peers
	peers := make([]peerJSON, 0, len(peerIDs))
	for _, id := range peerIDs {
		peers = append(peers, peerJSONFromState(id, state.SyncPeers[id]))
	}
	writeAPIOK(w, map[string]any{"peers": peers})
}

func peerJSONFromState(id string, ps syncPeerState) peerJSON {
	return peerJSON{
		PeerID:            id,
		LastSyncUnix:      ps.LastSyncUnix,
		LastAttemptUnix:   ps.LastAttemptUnix,
		BackoffUntilUnix:  ps.BackoffUntilUnix,
		FailureCount:      ps.FailureCount,
		LastError:         ps.LastError,
		DiscoveredAddr:    ps.DiscoveredAddr,
		ObservedAddr:      ps.ObservedAddr,
		ObservedUntilUnix: ps.ObservedUntilUnix,
		DatagramStats:     ps.DatagramStats,
		ObjectPullStats:   ps.ObjectPullStats,
	}
}

// handleLinks implements GET /api/v1/links and GET /api/v1/links/{link_id}
func (s *observerServer) handleLinks(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeAPIError(w, http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"))
		return
	}
	d := s.daemon
	if d == nil || d.Sync == nil || d.Sync.State == nil {
		writeAPIOK(w, map[string]any{"instances": []any{}})
		return
	}
	state := d.Sync.State
	state.RLock()
	defer state.RUnlock()
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/links")
	linkFilter := strings.TrimPrefix(path, "/")
	linkFilter = strings.TrimSuffix(linkFilter, "/")
	// Single link detail
	if linkFilter != "" {
		li, ok := state.LinkInstances[linkFilter]
		if !ok {
			writeAPIError(w, http.StatusNotFound, fmt.Errorf("link not found"))
			return
		}
		writeAPIOK(w, li)
		return
	}
	// All links
	instances := make([]linkInstanceState, 0, len(state.LinkInstances))
	for _, li := range state.LinkInstances {
		instances = append(instances, li)
	}
	result := map[string]any{
		"instances": instances,
	}
	if state.IPsecReconcile != nil {
		result["last_run_unix"] = state.IPsecReconcile.LastRunUnix
		result["desired_links"] = state.IPsecReconcile.DesiredLinks
		result["actual_sas"] = len(state.IPsecReconcile.ActualSAs)
		result["actions"] = state.IPsecReconcile.Actions
		result["skipped"] = state.IPsecReconcile.Skipped
		result["last_error"] = state.IPsecReconcile.LastError
	}
	writeAPIOK(w, result)
}

// handleHealth implements GET /api/v1/health and GET /api/v1/health/{link_id}
func (s *observerServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeAPIError(w, http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"))
		return
	}
	d := s.daemon
	links := d.healthStatusResponse()
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/health")
	linkFilter := strings.TrimPrefix(path, "/")
	linkFilter = strings.TrimSuffix(linkFilter, "/")
	// Single link health detail
	if linkFilter != "" {
		for _, h := range links {
			if h.InstanceID == linkFilter {
				writeAPIOK(w, h)
				return
			}
		}
		writeAPIError(w, http.StatusNotFound, fmt.Errorf("health data not found for link %s", linkFilter))
		return
	}
	writeAPIOK(w, map[string]any{
		"datasource": map[string]any{
			"configured": false,
			"type":       "none",
		},
		"links": links,
	})
}

// handleRoutes implements GET /api/v1/routes
func (s *observerServer) handleRoutes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeAPIError(w, http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"))
		return
	}
	d := s.daemon
	if d == nil || d.Sync == nil || d.Sync.State == nil {
		writeAPIOK(w, &routesDumpResponse{})
		return
	}
	state := d.Sync.State
	state.RLock()
	defer state.RUnlock()
	now := d.Sync.now()
	ars, _ := routing.BuildAuthorizedRouteSet(state.Network, now)
	writeAPIOK(w, buildRoutesDumpResponse(state.ManagedZone, ars))
}

// handleBird implements GET /api/v1/bird
func (s *observerServer) handleBird(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeAPIError(w, http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"))
		return
	}
	d := s.daemon
	if d == nil || d.Sync == nil || d.Sync.State == nil {
		writeAPIOK(w, map[string]any{"instances": map[string]any{}})
		return
	}
	state := d.Sync.State
	state.RLock()
	defer state.RUnlock()
	lastRoutingError := ""
	if state.RoutingReconcile != nil {
		lastRoutingError = state.RoutingReconcile.LastError
	}
	writeAPIOK(w, map[string]any{
		"instances":          state.BirdInstances,
		"last_routing_error": lastRoutingError,
	})
}

// handleEvents implements GET /api/v1/events (SSE)
func (s *observerServer) handleEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeAPIError(w, http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"))
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeAPIError(w, http.StatusInternalServerError, fmt.Errorf("streaming not supported"))
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	// Send initial connected event
	connected, _ := json.Marshal(sseEvent{Type: "connected", Payload: map[string]any{"client_id": "sse"}})
	fmt.Fprintf(w, "event: connected\ndata: %s\n\n", connected)
	flusher.Flush()
	// Subscribe to events
	ch, unsubscribe := s.hub.subscribe()
	defer unsubscribe()
	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-ch:
			if !ok {
				return
			}
			data, _ := json.Marshal(event)
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event.Type, data)
			flusher.Flush()
		}
	}
}

// handleStatic serves the embedded static UI files.
func (s *observerServer) handleStatic(w http.ResponseWriter, r *http.Request) {
	// Only serve GET requests for static files
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Don't serve API paths here
	if strings.HasPrefix(r.URL.Path, "/api/") {
		writeAPIError(w, http.StatusNotFound, fmt.Errorf("not found"))
		return
	}
	// Get the path relative to web/
	cleanPath := strings.TrimPrefix(r.URL.Path, "/")
	if cleanPath == "" {
		cleanPath = "index.html"
	}
	servedPath := cleanPath
	data, err := observerWebFS.ReadFile("web/" + cleanPath)
	if err != nil {
		// SPA fallback: serve index.html for any non-file path
		data, err = observerWebFS.ReadFile("web/index.html")
		if err != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		servedPath = "index.html"
	}
	// Set content type based on extension
	contentType := "application/octet-stream"
	switch {
	case strings.HasSuffix(servedPath, ".html"):
		contentType = "text/html; charset=utf-8"
	case strings.HasSuffix(servedPath, ".css"):
		contentType = "text/css; charset=utf-8"
	case strings.HasSuffix(servedPath, ".js"):
		contentType = "application/javascript; charset=utf-8"
	case strings.HasSuffix(servedPath, ".json"):
		contentType = "application/json; charset=utf-8"
	case strings.HasSuffix(servedPath, ".svg"):
		contentType = "image/svg+xml"
	}
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// webSubFS returns the embedded web/ directory as an fs.FS for testing.
func webSubFS() fs.FS {
	sub, err := fs.Sub(observerWebFS, "web")
	if err != nil {
		return nil
	}
	return sub
}
