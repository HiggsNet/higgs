package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Catofes/higgs/internal/observer"
	"github.com/Catofes/higgs/pkg/core/gossip"
	"github.com/Catofes/higgs/pkg/core/zone"
	higgscrypto "github.com/Catofes/higgs/pkg/crypto"
	"github.com/Catofes/higgs/pkg/transport/ipsec"
)

// ===== Observer Config Tests =====

func TestParseObserverConfigDefault(t *testing.T) {
	cfg, err := parseObserverConfig(nil)
	if err != nil {
		t.Fatalf("parseObserverConfig(nil) error: %v", err)
	}
	if cfg.Enabled {
		t.Error("default observer should be disabled")
	}
	if cfg.BindAddr != "127.0.0.1" {
		t.Errorf("default bind_addr = %q, want 127.0.0.1", cfg.BindAddr)
	}
	if cfg.Port != 8080 {
		t.Errorf("default port = %d, want 8080", cfg.Port)
	}
}

func TestParseObserverConfigEnabled(t *testing.T) {
	cfg, err := parseObserverConfig(&observerConfigYAML{
		Listen: "0.0.0.0:9090",
	})
	if err != nil {
		t.Fatalf("parseObserverConfig error: %v", err)
	}
	if !cfg.Enabled {
		t.Error("observer should be enabled")
	}
	if cfg.BindAddr != "0.0.0.0" {
		t.Errorf("bind_addr = %q, want 0.0.0.0", cfg.BindAddr)
	}
	if cfg.Port != 9090 {
		t.Errorf("port = %d, want 9090", cfg.Port)
	}
	if cfg.isLoopbackBind() {
		t.Error("0.0.0.0 should not be loopback")
	}
}

func TestParseObserverConfigListen(t *testing.T) {
	cfg, err := parseObserverConfig(&observerConfigYAML{
		Listen: "127.0.0.1:9090",
	})
	if err != nil {
		t.Fatalf("parseObserverConfig error: %v", err)
	}
	if !cfg.Enabled {
		t.Error("observer should be enabled")
	}
	if cfg.BindAddr != "127.0.0.1" {
		t.Errorf("bind_addr = %q, want 127.0.0.1", cfg.BindAddr)
	}
	if cfg.Port != 9090 {
		t.Errorf("port = %d, want 9090", cfg.Port)
	}
}

func TestParseObserverConfigDisabled(t *testing.T) {
	disabled := true
	cfg, err := parseObserverConfig(&observerConfigYAML{Disabled: &disabled})
	if err != nil {
		t.Fatalf("parseObserverConfig error: %v", err)
	}
	if cfg.Enabled {
		t.Error("observer should be disabled")
	}
}

func TestParseObserverConfigInvalidPort(t *testing.T) {
	_, err := parseObserverConfig(&observerConfigYAML{
		Listen: "127.0.0.1:70000",
	})
	if err == nil {
		t.Error("expected error for invalid port")
	}
}

func TestParseObserverConfigLoopbackDetection(t *testing.T) {
	cfg := defaultObserverConfig()
	if !cfg.isLoopbackBind() {
		t.Error("default bind 127.0.0.1 should be loopback")
	}
	cfg.BindAddr = "::1"
	if !cfg.isLoopbackBind() {
		t.Error("::1 should be loopback")
	}
	cfg.BindAddr = "10.0.0.1"
	if cfg.isLoopbackBind() {
		t.Error("10.0.0.1 should not be loopback")
	}
}

func TestObserverConfigListenAddr(t *testing.T) {
	cfg := observerConfig{BindAddr: "127.0.0.1", Port: 8080}
	if addr := cfg.listenAddr(); addr != "127.0.0.1:8080" {
		t.Errorf("listenAddr() = %q, want 127.0.0.1:8080", addr)
	}
}

// ===== Observer Config YAML Integration Test =====

func TestObserverConfigFromYAML(t *testing.T) {
	yaml := `observer:
  listen: "127.0.0.1:8080"
`
	config := defaultAppConfig()
	if err := parseConfigYAML(yaml, config); err != nil {
		t.Fatalf("parseConfigYAML error: %v", err)
	}
	if !config.Observer.Enabled {
		t.Error("observer should be enabled from YAML")
	}
	if config.Observer.Port != 8080 {
		t.Errorf("port = %d, want 8080", config.Observer.Port)
	}
}

func TestObserverConfigFromEmptyYAMLSection(t *testing.T) {
	yaml := `observer:
`
	config := defaultAppConfig()
	if err := parseConfigYAML(yaml, config); err != nil {
		t.Fatalf("parseConfigYAML error: %v", err)
	}
	if !config.Observer.Enabled {
		t.Error("empty observer section should enable observer")
	}
	if config.Observer.BindAddr != "127.0.0.1" {
		t.Errorf("bind_addr = %q, want 127.0.0.1", config.Observer.BindAddr)
	}
	if config.Observer.Port != 8080 {
		t.Errorf("port = %d, want 8080", config.Observer.Port)
	}
}

func TestObserverConfigKnownFields(t *testing.T) {
	yaml := `observer:
  unknown_field: true
`
	config := defaultAppConfig()
	err := parseConfigYAML(yaml, config)
	if err == nil {
		t.Error("expected error for unknown field")
	}
}

// ===== SSE Hub Tests =====

func TestSSEHubSubscribeBroadcast(t *testing.T) {
	hub := observer.NewHub()
	ch, unsubscribe := hub.Subscribe()
	defer unsubscribe()
	if hub.SubscriberCount() != 1 {
		t.Errorf("subscriber count = %d, want 1", hub.SubscriberCount())
	}
	event := observer.Event{Type: "test", Payload: map[string]any{"key": "value"}}
	hub.Broadcast(event)
	select {
	case received := <-ch:
		if received.Type != "test" {
			t.Errorf("received type = %q, want test", received.Type)
		}
	default:
		t.Error("event not received")
	}
}

func TestSSEHubUnsubscribe(t *testing.T) {
	hub := observer.NewHub()
	_, unsubscribe := hub.Subscribe()
	if hub.SubscriberCount() != 1 {
		t.Errorf("count = %d, want 1", hub.SubscriberCount())
	}
	unsubscribe()
	if hub.SubscriberCount() != 0 {
		t.Errorf("count after unsubscribe = %d, want 0", hub.SubscriberCount())
	}
}

func TestSSEHubBroadcastNoSubscribers(t *testing.T) {
	hub := observer.NewHub()
	hub.Broadcast(observer.Event{Type: "test"}) // should not panic
}

// ===== Observer Server HTTP Tests =====

func newTestObserverServer() *observerServer {
	d := &DaemonService{
		Sync: &SyncRuntime{
			State:  newTestStateFile(),
			Config: &syncConfigFile{PeerID: "test-node", ListenAddr: "127.0.0.1:33434"},
			App:    &Runtime{Config: &appConfig{}},
		},
	}
	cfg := defaultObserverConfig()
	cfg.Enabled = true
	return newObserverServer(d, cfg)
}

func newTestStateFile() *stateFile {
	return &stateFile{
		Network:   nil,
		SyncPeers: make(map[string]syncPeerState),
	}
}

func TestObserverStatusAPI(t *testing.T) {
	srv := newTestObserverServer()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	rr := httptest.NewRecorder()
	srv.handleStatus(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("status code = %d, want %d", rr.Code, http.StatusOK)
	}
	var resp apiResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if !resp.OK {
		t.Error("response OK should be true")
	}
	data, ok := resp.Data.(map[string]any)
	if !ok {
		t.Fatal("data is not a map")
	}
	if data["peer_id"] != "test-node" {
		t.Errorf("peer_id = %v, want test-node", data["peer_id"])
	}
	if data["daemon_online"] != true {
		t.Error("daemon should be online")
	}
}

func TestObserverReadMethodsUseCommittedSnapshotWhileLiveStateLocked(t *testing.T) {
	state, config := buildTestNetworkState(t)
	state.LinkInstances = map[string]linkInstanceState{
		"link-committed": {
			ID:          "link-committed",
			GroupID:     "main",
			PeerZone:    "node-b.catofes.",
			ActualState: "up",
		},
	}
	state.IPsecReconcile = &ipsecReconcileState{DesiredLinks: 1}
	appConfig := defaultAppConfig()
	appConfig.Observer.Enabled = true
	service := newDaemonService(&Runtime{Config: appConfig}, state, config, time.Second)
	srv := newObserverServer(service, appConfig.Observer)
	if srv == nil {
		t.Fatal("observer server is nil")
	}
	committedRev := service.StateStore.Meta().Revision

	state.Lock()
	state.LinkInstances["link-uncommitted"] = linkInstanceState{ID: "link-uncommitted"}
	state.IPsecReconcile.DesiredLinks = 99
	defer state.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	rr := httptest.NewRecorder()
	srv.handleStatus(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d; body=%s", rr.Code, http.StatusOK, rr.Body.String())
	}
	var resp apiResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	data := resp.Data.(map[string]any)
	if data["state_revision"] != float64(committedRev) || data["link_instances"] != float64(1) || data["desired_links"] != float64(1) {
		t.Fatalf("status data = %#v, want committed rev=%d link_instances=1 desired_links=1", data, committedRev)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/links", nil)
	rr = httptest.NewRecorder()
	srv.handleLinks(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("links code = %d, want %d; body=%s", rr.Code, http.StatusOK, rr.Body.String())
	}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode links error: %v", err)
	}
	linksData := resp.Data.(map[string]any)
	if linksData["desired_links"] != float64(1) {
		t.Fatalf("links data = %#v, want desired_links=1 from committed snapshot", linksData)
	}
}

func TestObserverStatusAPIMethodNotAllowed(t *testing.T) {
	srv := newTestObserverServer()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/status", nil)
	rr := httptest.NewRecorder()
	srv.handleStatus(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("status code = %d, want %d", rr.Code, http.StatusMethodNotAllowed)
	}
}

func TestObserverHandlerRoutesPeerDetail(t *testing.T) {
	srv := newTestObserverServer()
	srv.daemon.Sync.State.SyncPeers["peer-a.catofes."] = syncPeerState{
		LastSyncUnix: 123,
		FailureCount: 2,
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/peers/peer-a.catofes.", nil)
	rr := httptest.NewRecorder()
	srv.handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d; body=%s", rr.Code, http.StatusOK, rr.Body.String())
	}
	var resp apiResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if !resp.OK {
		t.Fatalf("response OK should be true: %#v", resp)
	}
	data, ok := resp.Data.(map[string]any)
	if !ok {
		t.Fatalf("data is not a map: %T", resp.Data)
	}
	if data["peer_id"] != "peer-a.catofes." {
		t.Errorf("peer_id = %v, want peer-a.catofes.", data["peer_id"])
	}
	if data["failure_count"] != float64(2) {
		t.Errorf("failure_count = %v, want 2", data["failure_count"])
	}
}

func TestObserverHandlerRejectsUnknownAPIPath(t *testing.T) {
	srv := newTestObserverServer()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/unknown", nil)
	rr := httptest.NewRecorder()
	srv.handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status code = %d, want %d", rr.Code, http.StatusNotFound)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("content type = %q, want application/json", ct)
	}
}

func TestObserverZonesAPIEmpty(t *testing.T) {
	srv := newTestObserverServer()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/zones", nil)
	rr := httptest.NewRecorder()
	srv.handleZones(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("status code = %d, want %d", rr.Code, http.StatusOK)
	}
	var resp apiResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	data, ok := resp.Data.(map[string]any)
	if !ok {
		t.Fatal("data is not a map")
	}
	zones, ok := data["zones"].([]any)
	if !ok {
		t.Fatal("zones is not a list")
	}
	if len(zones) != 0 {
		t.Errorf("zones count = %d, want 0", len(zones))
	}
}

func TestObserverZoneDetailIncludesRecordsAuthorityAndHistory(t *testing.T) {
	srv := newTestObserverServer()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	authority := &zone.ZoneAuthority{
		Zone:      "node-a.catofes.",
		Epoch:     7,
		Threshold: 1,
		Keys: []zone.AuthorizedKey{{
			Key: pub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermWrite},
				KeyPrefix:   "identity",
			}},
		}},
	}
	active := &zone.Record{
		Zone:      "node-a.catofes.",
		Key:       "identity",
		Type:      "policy.string",
		Value:     []byte(`{"name":"node-a"}`),
		Version:   2,
		Timestamp: 20,
	}
	if err := higgscrypto.SignRecord(active, priv); err != nil {
		t.Fatalf("SignRecord(active): %v", err)
	}
	old := &zone.Record{
		Zone:      "node-a.catofes.",
		Key:       "identity",
		Type:      "policy.string",
		Value:     []byte("old"),
		Version:   1,
		Timestamp: 10,
	}
	if err := higgscrypto.SignRecord(old, priv); err != nil {
		t.Fatalf("SignRecord(old): %v", err)
	}
	zs := zone.NewZoneState("node-a.catofes.", authority)
	zs.Records["identity"] = active
	zs.RecordHistory["identity"] = []*zone.Record{old}
	srv.daemon.Sync.State.Network = &zone.NetworkState{Zones: map[zone.ZonePath]*zone.ZoneState{
		"node-a.catofes.": zs,
	}}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/zones/node-a.catofes.", nil)
	rr := httptest.NewRecorder()
	srv.handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d; body=%s", rr.Code, http.StatusOK, rr.Body.String())
	}
	var resp apiResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	data := resp.Data.(map[string]any)
	if data["authority_hash"] == "" {
		t.Fatalf("authority_hash should be present: %#v", data)
	}
	authorityData := data["authority"].(map[string]any)
	if authorityData["epoch"] != float64(7) {
		t.Fatalf("authority epoch = %v, want 7", authorityData["epoch"])
	}
	records := data["records"].([]any)
	if len(records) != 1 {
		t.Fatalf("records len = %d, want 1", len(records))
	}
	record := records[0].(map[string]any)
	if record["value"].(string) != `{"name":"node-a"}` {
		t.Fatalf("record value = %v", record["value"])
	}
	if record["value_json"] == nil || record["record_hash"] == "" || record["signature"] == "" {
		t.Fatalf("record should include parsed JSON, hash and signature: %#v", record)
	}
	if data["history_count"] != float64(1) {
		t.Fatalf("history_count = %v, want 1", data["history_count"])
	}
}

func TestObserverPeersAPIEmpty(t *testing.T) {
	srv := newTestObserverServer()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/peers", nil)
	rr := httptest.NewRecorder()
	srv.handlePeers(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("status code = %d, want %d", rr.Code, http.StatusOK)
	}
	var resp apiResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	data := resp.Data.(map[string]any)
	peers := data["peers"].([]any)
	if len(peers) != 0 {
		t.Errorf("peers count = %d, want 0", len(peers))
	}
}

func TestObserverPeersAPIIncludesEndpointAndDiagnosticsDetails(t *testing.T) {
	srv := newTestObserverServer()
	now := time.Unix(1000, 0)
	srv.daemon.Sync.App.Clock = func() time.Time { return now }
	srv.daemon.Sync.Config.Bootstrap = []syncConfigPeer{{ID: "node-b.catofes.", Addr: "192.0.2.10:33434"}}
	srv.daemon.Sync.State.Network = zone.NewNetworkState()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	authority := &zone.ZoneAuthority{Zone: "node-b.catofes.", Epoch: 1, Threshold: 1, Keys: []zone.AuthorizedKey{{Key: pub}}}
	zs := zone.NewZoneState("node-b.catofes.", authority)
	endpointValue := gossip.EndpointRecordBytes([]gossip.LocalEndpoint{{
		IP:       net.ParseIP("203.0.113.20"),
		Port:     33434,
		Scope:    "global",
		Priority: 100,
		Source:   gossip.SourceAdvertise,
	}}, now)
	endpointRecord := &zone.Record{
		Zone:      "node-b.catofes.",
		Key:       gossip.EndpointRecordKeyUDP,
		Type:      "sync.endpoint",
		Value:     endpointValue,
		Version:   1,
		Timestamp: now.Unix(),
	}
	if err := higgscrypto.SignRecord(endpointRecord, priv); err != nil {
		t.Fatalf("SignRecord(endpoint): %v", err)
	}
	zs.Records[gossip.EndpointRecordKeyUDP] = endpointRecord
	srv.daemon.Sync.State.Network.Zones["node-b.catofes."] = zs
	srv.daemon.Sync.State.SyncPeers["node-b.catofes."] = syncPeerState{
		LastSyncUnix:         900,
		LastRelayUnix:        920,
		LastUpdateSource:     "announce",
		LastRelaySuppression: "relay_fanout_limited",
		DiscoveredAddr:       "203.0.113.20:33434",
		ObservedAddr:         "198.51.100.9:33434",
		ObservedSource:       "verified_packet",
		ObservedGraceAddrs:   []observedGraceAddrState{{Addr: "198.51.100.8:33434", UntilUnix: 1100}},
		DatagramStats:        &datagramStats{ChunkFallbacks: 2},
		ObjectPullStats:      &objectPullStats{Attempts: 3, Successes: 2},
		RejectedDigests:      map[string]rejectedDigestState{"bad": {Zone: "node-b.catofes.", Reason: "verify_failed"}},
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/peers/node-b.catofes.", nil)
	rr := httptest.NewRecorder()
	srv.handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d; body=%s", rr.Code, http.StatusOK, rr.Body.String())
	}
	var resp apiResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	data := resp.Data.(map[string]any)
	if data["configured_addr"] != "192.0.2.10:33434" {
		t.Fatalf("configured_addr = %v", data["configured_addr"])
	}
	if data["last_update_source"] != "announce" || data["last_relay_suppression"] != "relay_fanout_limited" {
		t.Fatalf("peer diagnostics missing: %#v", data)
	}
	endpoints := data["endpoints"].([]any)
	if len(endpoints) < 3 {
		t.Fatalf("endpoints len = %d, want at least 3: %#v", len(endpoints), endpoints)
	}
	var sawSigned, sawObserved bool
	for _, item := range endpoints {
		ep := item.(map[string]any)
		if ep["addr"] == "203.0.113.20:33434" && ep["source"] == "advertise" {
			sawSigned = true
		}
		if ep["addr"] == "198.51.100.9:33434" && ep["source"] == "verified_packet" {
			sawObserved = true
		}
	}
	if !sawSigned || !sawObserved {
		t.Fatalf("missing signed/observed endpoints: %#v", endpoints)
	}
}

func TestObserverPeersAPIExcludesLocalPeerID(t *testing.T) {
	srv := newTestObserverServer()
	now := time.Unix(1000, 0)
	srv.daemon.Sync.App.Clock = func() time.Time { return now }
	srv.daemon.Sync.Config.PeerID = "node-a.catofes."
	srv.daemon.Sync.Config.Bootstrap = []syncConfigPeer{
		{ID: "node-a.catofes.", Addr: "127.0.0.1:33434"},
		{ID: "node-b.catofes.", Addr: "127.0.0.1:33435"},
	}
	srv.daemon.Sync.State.ManagedZone = "node-a.catofes."
	srv.daemon.Sync.State.Network = zone.NewNetworkState()
	addObserverEndpointZone(t, srv.daemon.Sync.State.Network, "node-a.catofes.", "127.0.0.1", 33434, now)
	addObserverEndpointZone(t, srv.daemon.Sync.State.Network, "node-b.catofes.", "127.0.0.1", 33435, now)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/peers", nil)
	rr := httptest.NewRecorder()
	srv.handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d; body=%s", rr.Code, http.StatusOK, rr.Body.String())
	}
	var resp apiResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	data := resp.Data.(map[string]any)
	peers := data["peers"].([]any)
	if len(peers) != 1 {
		t.Fatalf("peers len = %d, want 1: %#v", len(peers), peers)
	}
	peer := peers[0].(map[string]any)
	if peer["peer_id"] != "node-b.catofes." {
		t.Fatalf("peer_id = %v, want node-b.catofes.; peers=%#v", peer["peer_id"], peers)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/peers/node-a.catofes.", nil)
	rr = httptest.NewRecorder()
	srv.handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("self peer status code = %d, want %d; body=%s", rr.Code, http.StatusNotFound, rr.Body.String())
	}
}

func TestObserverPeersAPISortsByZonePath(t *testing.T) {
	srv := newTestObserverServer()
	now := time.Unix(1000, 0)
	srv.daemon.Sync.App.Clock = func() time.Time { return now }
	srv.daemon.Sync.State.ManagedZone = "node-a.catofes."
	srv.daemon.Sync.Config.PeerID = string(srv.daemon.Sync.State.ManagedZone)
	srv.daemon.Sync.State.Network = zone.NewNetworkState()
	addObserverEndpointZone(t, srv.daemon.Sync.State.Network, "zeta.other.", "127.0.0.1", 33439, now)
	addObserverEndpointZone(t, srv.daemon.Sync.State.Network, "node-b.catofes.", "127.0.0.1", 33435, now)
	addObserverEndpointZone(t, srv.daemon.Sync.State.Network, "alpha.catofes.", "127.0.0.1", 33436, now)
	addObserverEndpointZone(t, srv.daemon.Sync.State.Network, "branch.alpha.catofes.", "127.0.0.1", 33437, now)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/peers", nil)
	rr := httptest.NewRecorder()
	srv.handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d; body=%s", rr.Code, http.StatusOK, rr.Body.String())
	}
	var resp apiResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	data := resp.Data.(map[string]any)
	peers := data["peers"].([]any)
	var got []string
	for _, item := range peers {
		got = append(got, item.(map[string]any)["peer_id"].(string))
	}
	want := []string{"alpha.catofes.", "branch.alpha.catofes.", "node-b.catofes.", "zeta.other."}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("peer order = %v, want %v", got, want)
	}
}

func addObserverEndpointZone(t *testing.T, ns *zone.NetworkState, path zone.ZonePath, ip string, port uint16, now time.Time) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(%s): %v", path, err)
	}
	authority := &zone.ZoneAuthority{Zone: path, Epoch: 1, Threshold: 1, Keys: []zone.AuthorizedKey{{Key: pub}}}
	zs := zone.NewZoneState(path, authority)
	value := gossip.EndpointRecordBytes([]gossip.LocalEndpoint{{
		IP:       net.ParseIP(ip),
		Port:     port,
		Scope:    "loopback",
		Priority: 100,
		Source:   gossip.SourceAdvertise,
	}}, now)
	record := &zone.Record{
		Zone:      path,
		Key:       gossip.EndpointRecordKeyUDP,
		Type:      "sync.endpoint",
		Value:     value,
		Version:   1,
		Timestamp: now.Unix(),
	}
	if err := higgscrypto.SignRecord(record, priv); err != nil {
		t.Fatalf("SignRecord(%s): %v", path, err)
	}
	zs.Records[gossip.EndpointRecordKeyUDP] = record
	ns.Zones[path] = zs
}

func TestObserverLinksAPIEmpty(t *testing.T) {
	srv := newTestObserverServer()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/links", nil)
	rr := httptest.NewRecorder()
	srv.handleLinks(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("status code = %d, want %d", rr.Code, http.StatusOK)
	}
	var resp apiResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	data := resp.Data.(map[string]any)
	instances := data["instances"].([]any)
	if len(instances) != 0 {
		t.Errorf("instances count = %d, want 0", len(instances))
	}
}

func TestObserverLinksAPIDetailIncludesDesiredSAAndRouting(t *testing.T) {
	srv := newTestObserverServer()
	srv.daemon.Sync.App.Config = &appConfig{
		IPsec: ipsecConfig{
			LinkGroups: []ipsec.LinkGroupSpec{{
				ID:    "blue",
				NetNS: ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: "hgs-blue"},
			}},
		},
		Routing: routingConfig{
			Instances: []RoutingInstance{{
				Enabled: true,
				NetNS:   "hgs-blue",
			}},
		},
	}
	state := srv.daemon.Sync.State
	state.LinkInstances = map[string]linkInstanceState{
		"link-1": {
			ID:              "link-1",
			GroupID:         "blue",
			PeerZone:        "node-b.catofes.",
			ActualState:     "up",
			InterfaceName:   "hgs0",
			XFRMIfID:        42,
			Endpoint:        "198.51.100.10:4500",
			DesiredSpecHash: "abcdef0123456789",
			ChildSAName:     "child-link-1",
			InitiatorRole:   "primary",
		},
	}
	state.IPsecReconcile = &ipsecReconcileState{
		LastRunUnix:  123,
		DesiredLinks: 1,
		Desired: []desiredLinkState{{
			InstanceID:      "link-1",
			GroupID:         "blue",
			PeerZone:        "node-b.catofes.",
			DesiredSpecHash: "abcdef0123456789",
			InterfaceName:   "hgs0",
			XFRMIfID:        42,
			Endpoint:        "198.51.100.10:4500",
			LocalTunnelAddr: "fd00::1%hgs0",
			PeerTunnelAddr:  "fd00::2%hgs0",
		}},
		ActualSAs: []linkSAState{{
			Name:           "link-1",
			ChildSA:        "child-link-1",
			Established:    true,
			ReqID:          77,
			LocalIdentity:  "node-a.catofes.",
			RemoteIdentity: "node-b.catofes.",
		}},
	}
	state.BirdInstances = map[string]*BirdInstanceState{
		"hgs-blue": {State: "running"},
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/links", nil)
	rr := httptest.NewRecorder()
	srv.handleLinks(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d; body=%s", rr.Code, http.StatusOK, rr.Body.String())
	}
	var resp apiResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	data := resp.Data.(map[string]any)
	instances := data["instances"].([]any)
	if len(instances) != 1 {
		t.Fatalf("instances count = %d, want 1", len(instances))
	}
	link := instances[0].(map[string]any)
	if link["state"] != "up" {
		t.Fatalf("state = %v, want up", link["state"])
	}
	desired := link["desired"].(map[string]any)
	if desired["peer_tunnel_addr"] != "fd00::2%hgs0" {
		t.Fatalf("peer_tunnel_addr = %v, want fd00::2%%hgs0", desired["peer_tunnel_addr"])
	}
	sa := link["actual_sa"].(map[string]any)
	if sa["reqid"].(float64) != 77 || sa["remote_identity"] != "node-b.catofes." {
		t.Fatalf("actual_sa = %#v, want reqid and remote identity", sa)
	}
	routing := link["routing"].(map[string]any)
	if routing["bird_state"] != "running" {
		t.Fatalf("bird_state = %v, want running", routing["bird_state"])
	}
}

func TestObserverHealthAPIIncludesLinkContextWithoutSamples(t *testing.T) {
	srv := newTestObserverServer()
	state := srv.daemon.Sync.State
	state.LinkInstances = map[string]linkInstanceState{
		"link-1": {
			ID:            "link-1",
			GroupID:       "blue",
			PeerZone:      "node-b.catofes.",
			ActualState:   "up",
			InterfaceName: "hgs0",
			Endpoint:      "198.51.100.10:4500",
		},
	}
	state.IPsecReconcile = &ipsecReconcileState{
		Desired: []desiredLinkState{{
			InstanceID:      "link-1",
			GroupID:         "blue",
			PeerZone:        "node-b.catofes.",
			InterfaceName:   "hgs0",
			LocalTunnelAddr: "fd00::1%hgs0",
			PeerTunnelAddr:  "fd00::2%hgs0",
		}},
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	rr := httptest.NewRecorder()
	srv.handleHealth(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d; body=%s", rr.Code, http.StatusOK, rr.Body.String())
	}
	var resp apiResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	data := resp.Data.(map[string]any)
	links := data["links"].([]any)
	if len(links) != 1 {
		t.Fatalf("health links = %d, want 1", len(links))
	}
	item := links[0].(map[string]any)
	if item["peer_zone"] != "node-b.catofes." || item["peer_tunnel_addr"] != "fd00::2%hgs0" {
		t.Fatalf("health context = %#v, want peer and tunnel context", item)
	}
	health := item["health"].(map[string]any)
	if health["state"] != "unknown" {
		t.Fatalf("health state = %v, want unknown", health["state"])
	}
}

func TestObserverHealthSeriesReadsLocalSpool(t *testing.T) {
	srv := newTestObserverServer()
	cfg := defaultHealthConfig()
	cfg.MetricsEnabled = true
	cfg.LocalSpoolPath = t.TempDir()
	cfg.LocalSpoolMaxAge = time.Hour
	srv.daemon.Sync.App.Config.Health = cfg
	now := time.Unix(3000, 0)
	srv.daemon.Sync.App.Clock = func() time.Time { return now }
	if err := srv.daemon.appendHealthSpool(now, []healthLinkJSON{{
		InstanceID: "link-1",
		State:      "healthy",
		ProbeType:  "icmp",
		LastRTTMs:  42,
		LossRatio:  0,
		JitterMs:   3,
	}}); err != nil {
		t.Fatalf("appendHealthSpool: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/health/link-1/series?metric=rtt&range=5m&step=1m", nil)
	rr := httptest.NewRecorder()
	srv.handleHealth(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d; body=%s", rr.Code, http.StatusOK, rr.Body.String())
	}
	var resp apiResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	data := resp.Data.(map[string]any)
	ds := data["datasource"].(map[string]any)
	if ds["configured"] != true || ds["type"] != "local_spool" {
		t.Fatalf("datasource = %#v, want configured local_spool", ds)
	}
	series := data["series"].(map[string]any)
	points := series["points"].([]any)
	if len(points) != 1 {
		t.Fatalf("points = %#v, want 1 point", points)
	}
	point := points[0].(map[string]any)
	if point["value"].(float64) != 42 {
		t.Fatalf("point value = %v, want 42", point["value"])
	}
}

func TestObserverRoutesAPI(t *testing.T) {
	srv := newTestObserverServer()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/routes", nil)
	rr := httptest.NewRecorder()
	srv.handleRoutes(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("status code = %d, want %d", rr.Code, http.StatusOK)
	}
}

func TestObserverBirdAPI(t *testing.T) {
	srv := newTestObserverServer()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/bird", nil)
	rr := httptest.NewRecorder()
	srv.handleBird(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("status code = %d, want %d", rr.Code, http.StatusOK)
	}
}

func TestObserverEventsMethodNotAllowed(t *testing.T) {
	srv := newTestObserverServer()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/events", nil)
	rr := httptest.NewRecorder()
	srv.handleEvents(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("status code = %d, want %d", rr.Code, http.StatusMethodNotAllowed)
	}
}

func TestObserverEventsInitialFrame(t *testing.T) {
	srv := newTestObserverServer()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/api/v1/events", nil)
	rr := httptest.NewRecorder()
	srv.handleEvents(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", rr.Code, http.StatusOK)
	}
	if body := rr.Body.String(); !strings.Contains(body, "event: connected") {
		t.Fatalf("initial connected SSE frame was not written: %q", body)
	}
}

func TestObserverStaticHandler(t *testing.T) {
	srv := newTestObserverServer()
	// Serve index.html
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	srv.handleStatic(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("status code = %d, want %d", rr.Code, http.StatusOK)
	}
	body := rr.Body.String()
	if body == "" {
		t.Error("static file response should not be empty")
	}
}

func TestObserverStaticHandlerSPAFallbackContentType(t *testing.T) {
	srv := newTestObserverServer()
	req := httptest.NewRequest(http.MethodGet, "/overlay/links", nil)
	rr := httptest.NewRecorder()
	srv.handleStatic(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("status code = %d, want %d", rr.Code, http.StatusOK)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Errorf("content type = %q, want text/html; charset=utf-8", ct)
	}
}

func TestObserverStaticHandlerCSS(t *testing.T) {
	srv := newTestObserverServer()
	req := httptest.NewRequest(http.MethodGet, "/style.css", nil)
	rr := httptest.NewRecorder()
	srv.handleStatic(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("status code = %d, want %d", rr.Code, http.StatusOK)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "text/css; charset=utf-8" {
		t.Errorf("content type = %q, want text/css; charset=utf-8", ct)
	}
}

func TestObserverStaticHandlerJS(t *testing.T) {
	srv := newTestObserverServer()
	req := httptest.NewRequest(http.MethodGet, "/app.js", nil)
	rr := httptest.NewRecorder()
	srv.handleStatic(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("status code = %d, want %d", rr.Code, http.StatusOK)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/javascript; charset=utf-8" {
		t.Errorf("content type = %q, want application/javascript; charset=utf-8", ct)
	}
}

func TestObserverStaticHandlerMethodNotAllowed(t *testing.T) {
	srv := newTestObserverServer()
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	rr := httptest.NewRecorder()
	srv.handleStatic(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("status code = %d, want %d", rr.Code, http.StatusMethodNotAllowed)
	}
}

func TestObserverStartObserverServerDisabled(t *testing.T) {
	d := &DaemonService{
		Sync: &SyncRuntime{
			App: &Runtime{Config: &appConfig{Observer: observerConfig{Enabled: false}}},
		},
	}
	stop, err := d.startObserverServer(context.TODO())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	stop()
}

func TestObserverStartObserverServerEnabledServesHTTP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("loopback TCP unavailable: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	d := &DaemonService{
		Sync: &SyncRuntime{
			State:  newTestStateFile(),
			Config: &syncConfigFile{PeerID: "test-node", ListenAddr: "127.0.0.1:33434"},
			App: &Runtime{Config: &appConfig{Observer: observerConfig{
				Enabled:  true,
				BindAddr: "127.0.0.1",
				Port:     port,
			}}},
		},
	}
	stop, err := d.startObserverServer(context.Background())
	if err != nil {
		t.Fatalf("startObserverServer error: %v", err)
	}
	defer stop()
	client := http.Client{Timeout: time.Second}
	url := fmt.Sprintf("http://127.0.0.1:%d/api/v1/status", port)
	var resp *http.Response
	for i := 0; i < 20; i++ {
		resp, err = client.Get(url)
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("GET %s error: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status code = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var apiResp apiResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		t.Fatalf("decode response error: %v", err)
	}
	if !apiResp.OK {
		t.Fatalf("response OK should be true: %#v", apiResp)
	}
	if d.observerHub == nil {
		t.Fatal("observerHub should be wired after start")
	}
}

func TestObserverNotifyObserverNoHub(t *testing.T) {
	d := &DaemonService{}
	// Should not panic when observerHub is nil
	d.notifyObserver("test", nil)
}

// ===== Embedded Web FS Tests =====

func TestWebSubFS(t *testing.T) {
	webFS := webSubFS()
	if webFS == nil {
		t.Fatal("webSubFS should not be nil")
	}
	data, err := fs.ReadFile(webFS, "index.html")
	if err != nil {
		t.Fatalf("read index.html error: %v", err)
	}
	if len(data) == 0 {
		t.Error("index.html should not be empty")
	}
}

func TestWebAppEscapesHTML(t *testing.T) {
	webFS := webSubFS()
	if webFS == nil {
		t.Fatal("webSubFS should not be nil")
	}
	data, err := fs.ReadFile(webFS, "app.js")
	if err != nil {
		t.Fatalf("read app.js error: %v", err)
	}
	body := string(data)
	for _, token := range []string{"&amp;", "&lt;", "&gt;", "&quot;", "&#39;"} {
		if !strings.Contains(body, token) {
			t.Fatalf("app.js esc() missing HTML escape token %q", token)
		}
	}
}

func TestWebAppPreservesFoldState(t *testing.T) {
	webFS := webSubFS()
	if webFS == nil {
		t.Fatal("webSubFS should not be nil")
	}
	data, err := fs.ReadFile(webFS, "app.js")
	if err != nil {
		t.Fatalf("read app.js error: %v", err)
	}
	body := string(data)
	for _, token := range []string{
		"const foldState = new Map()",
		"function rememberFoldState",
		"function restoreFoldState",
		"details[data-fold-key]",
		"data-fold-key",
		"restoreFoldState(content)",
		"restoreFoldState(el)",
	} {
		if !strings.Contains(body, token) {
			t.Fatalf("app.js fold-state support missing token %q", token)
		}
	}
}
