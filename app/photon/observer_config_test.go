package main

import (
	"testing"
)

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
