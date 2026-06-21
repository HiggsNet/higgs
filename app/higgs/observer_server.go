package main

import (
	"context"
	"embed"
	"encoding/base64"
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
	recordKeys := make([]string, 0, len(zs.Records))
	for key := range zs.Records {
		recordKeys = append(recordKeys, key)
	}
	sort.Strings(recordKeys)
	for _, key := range recordKeys {
		records = append(records, recordJSON(zs.Records[key], len(zs.RecordHistory[key])))
	}
	delegations := make([]map[string]any, 0, len(zs.Delegations))
	delegationPaths := make([]zone.ZonePath, 0, len(zs.Delegations))
	for childPath := range zs.Delegations {
		delegationPaths = append(delegationPaths, childPath)
	}
	sort.Slice(delegationPaths, func(i, j int) bool { return delegationPaths[i] < delegationPaths[j] })
	for _, childPath := range delegationPaths {
		delegations = append(delegations, delegationJSON(zs.Delegations[childPath]))
	}
	revocations := make([]map[string]any, 0, len(zs.Revocations))
	revocationPaths := make([]zone.ZonePath, 0, len(zs.Revocations))
	for childPath := range zs.Revocations {
		revocationPaths = append(revocationPaths, childPath)
	}
	sort.Slice(revocationPaths, func(i, j int) bool { return revocationPaths[i] < revocationPaths[j] })
	for _, childPath := range revocationPaths {
		revocations = append(revocations, revocationJSON(zs.Revocations[childPath]))
	}
	history := make([]map[string]any, 0)
	historyKeys := make([]string, 0, len(zs.RecordHistory))
	for key := range zs.RecordHistory {
		historyKeys = append(historyKeys, key)
	}
	sort.Strings(historyKeys)
	for _, key := range historyKeys {
		versions := zs.RecordHistory[key]
		for i := len(versions) - 1; i >= 0; i-- {
			history = append(history, recordJSON(versions[i], 0))
		}
	}
	return map[string]any{
		"path":             string(path),
		"parent":           string(path.Parent()),
		"authority":        authorityJSON(zs.Authority),
		"authority_hash":   hexOrEmpty(authorityHash(zs.Authority)),
		"parent_proof":     delegationsJSON(zs.ParentProof),
		"records":          records,
		"record_history":   history,
		"delegations":      delegations,
		"revocations":      revocations,
		"revoked":          revoked,
		"record_count":     len(zs.Records),
		"history_count":    len(history),
		"delegation_count": len(zs.Delegations),
		"revocation_count": len(zs.Revocations),
		"merkle_root":      hexOrEmpty(zs.MerkleRoot),
	}
}

func recordJSON(rec *zone.Record, historyCount int) map[string]any {
	if rec == nil {
		return map[string]any{}
	}
	out := map[string]any{
		"zone":          string(rec.Zone),
		"key":           rec.Key,
		"version":       rec.Version,
		"type":          rec.Type,
		"value":         string(rec.Value),
		"value_b64":     base64.StdEncoding.EncodeToString(rec.Value),
		"value_hash":    hexOrEmpty(rec.ValueHash),
		"record_hash":   hexOrEmpty(higgscrypto.RecordHash(rec)),
		"prev_hash":     hexOrEmpty(rec.PrevHash),
		"timestamp":     rec.Timestamp,
		"signed_by":     hexOrEmpty(rec.SignedBy),
		"signature":     hexOrEmpty(rec.Signature),
		"history_count": historyCount,
	}
	var parsed any
	if len(rec.Value) > 0 && json.Unmarshal(rec.Value, &parsed) == nil {
		out["value_json"] = parsed
	}
	return out
}

func authorityJSON(authority *zone.ZoneAuthority) map[string]any {
	if authority == nil {
		return nil
	}
	keys := make([]map[string]any, 0, len(authority.Keys))
	for _, key := range authority.Keys {
		caps := make([]map[string]any, 0, len(key.Capabilities))
		for _, cap := range key.Capabilities {
			perms := make([]string, 0, len(cap.Permissions))
			for _, perm := range cap.Permissions {
				perms = append(perms, string(perm))
			}
			caps = append(caps, map[string]any{
				"permissions": perms,
				"key_prefix":  cap.KeyPrefix,
			})
		}
		keys = append(keys, map[string]any{
			"key":          hexOrEmpty(key.Key),
			"key_id":       hexOrEmpty(higgscrypto.KeyID(key.Key)),
			"not_before":   key.NotBefore,
			"not_after":    key.NotAfter,
			"capabilities": caps,
		})
	}
	return map[string]any{
		"zone":      string(authority.Zone),
		"epoch":     authority.Epoch,
		"threshold": authority.Threshold,
		"keys":      keys,
	}
}

func delegationJSON(del *zone.Delegation) map[string]any {
	if del == nil {
		return nil
	}
	expiresAt := ""
	if del.ExpiresAt != nil {
		expiresAt = del.ExpiresAt.UTC().Format(time.RFC3339)
	}
	return map[string]any{
		"child":           string(del.ZoneName),
		"scope":           string(del.Scope),
		"authority_epoch": del.AuthorityEpoch,
		"authority_hash":  hexOrEmpty(del.AuthorityHash),
		"authority":       authorityJSON(&del.Authority),
		"expires_at":      expiresAt,
		"signed_by":       hexOrEmpty(del.SignedBy),
		"signature":       hexOrEmpty(del.Signature),
	}
}

func delegationsJSON(delegations []*zone.Delegation) []map[string]any {
	out := make([]map[string]any, 0, len(delegations))
	for _, del := range delegations {
		out = append(out, delegationJSON(del))
	}
	return out
}

func revocationJSON(rev *zone.DelegationRevocation) map[string]any {
	if rev == nil {
		return nil
	}
	return map[string]any{
		"child":                   string(rev.ChildZone),
		"parent":                  string(rev.ParentZone),
		"revoked_authority_epoch": rev.RevokedAuthorityEpoch,
		"revoked_authority_hash":  hexOrEmpty(rev.RevokedAuthorityHash),
		"reason":                  rev.Reason,
		"revoked_at":              rev.RevokedAt,
		"ttl_seconds":             rev.TTLSeconds,
		"grace_seconds":           rev.GraceSeconds,
		"signed_by":               hexOrEmpty(rev.SignedBy),
		"signature":               hexOrEmpty(rev.Signature),
	}
}

func authorityHash(authority *zone.ZoneAuthority) []byte {
	if authority == nil {
		return nil
	}
	return higgscrypto.AuthorityHash(authority)
}

func hexOrEmpty(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	return hex.EncodeToString(data)
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
	Endpoints             []peerEndpointJSON             `json:"endpoints,omitempty"`
	DatagramStats         *datagramStats                 `json:"datagram_stats,omitempty"`
	ObjectPullStats       *objectPullStats               `json:"object_pull_stats,omitempty"`
	RejectedDigests       map[string]rejectedDigestState `json:"rejected_digests,omitempty"`
}

type peerEndpointJSON struct {
	Addr         string `json:"addr"`
	Address      string `json:"address,omitempty"`
	Port         uint16 `json:"port,omitempty"`
	Protocol     string `json:"protocol,omitempty"`
	Scope        string `json:"scope,omitempty"`
	Source       string `json:"source,omitempty"`
	Priority     int    `json:"priority,omitempty"`
	LastObserved int64  `json:"last_observed,omitempty"`
	Selected     bool   `json:"selected,omitempty"`
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
	sort.Strings(peerIDs)
	// Single peer detail
	if peerFilter != "" {
		ps, ok := state.SyncPeers[peerFilter]
		if isLocalObserverPeer(peerFilter, d.Sync.Config, state) || (!ok && !peerKnownFromConfigOrDiscovery(peerFilter, d.Sync.Config, state.Network, d.Sync.now())) {
			writeAPIError(w, http.StatusNotFound, fmt.Errorf("peer not found"))
			return
		}
		writeAPIOK(w, peerJSONFromState(peerFilter, ps, d.Sync.Config, state.Network, d.Sync.now()))
		return
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
	writeAPIOK(w, map[string]any{"peers": peers})
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

func peerEndpointsJSON(peerID string, ps syncPeerState, config *syncConfigFile, ns *zone.NetworkState, now time.Time) []peerEndpointJSON {
	var out []peerEndpointJSON
	appendEndpoint := func(ep peerEndpointJSON) {
		if ep.Addr == "" {
			if ep.Address != "" && ep.Port != 0 {
				ep.Addr = fmt.Sprintf("%s:%d", ep.Address, ep.Port)
			}
		}
		for i := range out {
			if out[i].Addr == ep.Addr && out[i].Source == ep.Source {
				if ep.Selected {
					out[i].Selected = true
				}
				return
			}
		}
		out = append(out, ep)
	}
	if addr := bootstrapAddrForPeer(config, peerID); addr != "" {
		appendEndpoint(peerEndpointJSON{Addr: addr, Source: "bootstrap", Protocol: "udp", Selected: ps.DiscoveredAddr == addr})
	}
	discovered := gossip.ExtractPeerEndpointsAt(ns, now)
	for _, ep := range discovered[peerID] {
		protocol := ep.Protocol
		if protocol == "" {
			protocol = "udp"
		}
		addr := fmt.Sprintf("%s:%d", ep.Address, ep.Port)
		appendEndpoint(peerEndpointJSON{
			Addr:         addr,
			Address:      ep.Address,
			Port:         ep.Port,
			Protocol:     protocol,
			Scope:        ep.Scope,
			Source:       firstNonEmpty(ep.Source, "signed"),
			Priority:     ep.Priority,
			LastObserved: ep.LastObserved,
			Selected:     ps.DiscoveredAddr == addr,
		})
	}
	if ps.DiscoveredAddr != "" {
		appendEndpoint(peerEndpointJSON{Addr: ps.DiscoveredAddr, Source: "selected", Protocol: "udp", Selected: true})
	}
	if ps.ObservedAddr != "" {
		appendEndpoint(peerEndpointJSON{Addr: ps.ObservedAddr, Source: firstNonEmpty(ps.ObservedSource, "observed"), Protocol: "udp", Selected: ps.DiscoveredAddr == ""})
	}
	for _, grace := range ps.ObservedGraceAddrs {
		appendEndpoint(peerEndpointJSON{Addr: grace.Addr, Source: "observed_grace", Protocol: "udp"})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Selected != out[j].Selected {
			return out[i].Selected
		}
		if out[i].Source != out[j].Source {
			return out[i].Source < out[j].Source
		}
		return out[i].Addr < out[j].Addr
	})
	return out
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
