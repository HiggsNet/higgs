package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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
	port := 9090
	cfg, err := parseObserverConfig(&observerConfigYAML{
		BindAddr: "0.0.0.0",
		Port:     &port,
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
	port := 70000
	_, err := parseObserverConfig(&observerConfigYAML{
		Port: &port,
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
  bind_addr: "127.0.0.1"
  port: 8080
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
	hub := newSSEHub()
	ch, unsubscribe := hub.subscribe()
	defer unsubscribe()
	if hub.subscriberCount() != 1 {
		t.Errorf("subscriber count = %d, want 1", hub.subscriberCount())
	}
	event := sseEvent{Type: "test", Payload: map[string]any{"key": "value"}}
	hub.broadcast(event)
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
	hub := newSSEHub()
	_, unsubscribe := hub.subscribe()
	if hub.subscriberCount() != 1 {
		t.Errorf("count = %d, want 1", hub.subscriberCount())
	}
	unsubscribe()
	if hub.subscriberCount() != 0 {
		t.Errorf("count after unsubscribe = %d, want 0", hub.subscriberCount())
	}
}

func TestSSEHubBroadcastNoSubscribers(t *testing.T) {
	hub := newSSEHub()
	hub.broadcast(sseEvent{Type: "test"}) // should not panic
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
	return &observerServer{
		daemon: d,
		config: defaultObserverConfig(),
		hub:    newSSEHub(),
	}
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
	stop, err := d.startObserverServer(nil)
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
