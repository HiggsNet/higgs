package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseConfigYAML(t *testing.T) {
	pub := make(ed25519.PublicKey, ed25519.PublicKeySize)
	for i := range pub {
		pub[i] = byte(i)
	}
	config := defaultAppConfig()
	input := `
data_dir: /tmp/higgs-a
peer_id: node-a
listen_port: 33434
max_message_bytes: 32768
max_sync_zones: 8
max_sync_records: 512
endpoint_grace: 2m
bootstrap:
  - id: node-b
    addr: 127.0.0.1:33435
trusted_root_public_key: ` + hex.EncodeToString(pub) + `
`
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	normalizeAppConfig(config)
	if config.StatePath != "/tmp/higgs-a/higgs.db" {
		t.Fatalf("StatePath = %q, want /tmp/higgs-a/higgs.db", config.StatePath)
	}
	if config.PeerID != "node-a" || config.ListenAddr != ":33434" {
		t.Fatalf("peer/listen = %q/%q", config.PeerID, config.ListenAddr)
	}
	if len(config.Bootstrap) != 1 || config.Bootstrap[0].ID != "node-b" || config.Bootstrap[0].Addr != "127.0.0.1:33435" {
		t.Fatalf("Bootstrap = %#v", config.Bootstrap)
	}
	if !equalPublicKey(config.TrustedRootPublicKey, pub) {
		t.Fatalf("TrustedRootPublicKey mismatch")
	}
	if config.MaxMessageBytes != 32768 || config.MaxSyncZones != 8 || config.MaxSyncRecords != 512 {
		t.Fatalf("sync limits = %d/%d/%d", config.MaxMessageBytes, config.MaxSyncZones, config.MaxSyncRecords)
	}
	if config.EndpointGrace.String() != "2m0s" {
		t.Fatalf("EndpointGrace = %s, want 2m0s", config.EndpointGrace)
	}
}

func TestRuntimeCachesConfigForStateIO(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	dataDir := filepath.Join(dir, "data")
	statePath := filepath.Join(dataDir, "higgs.db")

	state, _ := buildTestNetworkState(t)
	rootKey, err := rootPublicKey(state.Network)
	if err != nil {
		t.Fatalf("rootPublicKey: %v", err)
	}
	writeRuntimeConfig(t, configPath, dataDir, rootKey, nil)
	t.Setenv("HIGGS_CONFIG", configPath)

	rt, err := NewRuntime()
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	if err := saveStateAt(statePath, state); err != nil {
		t.Fatalf("saveStateAt: %v", err)
	}

	wrongRoot := make(ed25519.PublicKey, ed25519.PublicKeySize)
	for i := range wrongRoot {
		wrongRoot[i] = byte(255 - i)
	}
	writeRuntimeConfig(t, configPath, dataDir, wrongRoot, nil)

	if _, err := rt.LoadState(); err != nil {
		t.Fatalf("cached runtime LoadState should keep original trusted root: %v", err)
	}
	if _, err := loadState(); err == nil {
		t.Fatalf("loadState should observe updated config and reject mismatched root")
	}
}

func TestRuntimeStatePathOverride(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	configDataDir := filepath.Join(dir, "config-data")
	overridePath := filepath.Join(dir, "override", "state.db")
	writeRuntimeConfig(t, configPath, configDataDir, nil, nil)
	t.Setenv("HIGGS_CONFIG", configPath)
	t.Setenv("HIGGS_STATE", overridePath)

	rt, err := NewRuntime()
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	if rt.StatePath != overridePath {
		t.Fatalf("StatePath = %q, want override %q", rt.StatePath, overridePath)
	}
}

func TestRuntimeSyncConfigDerivesLimitsAndDefaults(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	writeRuntimeConfig(t, configPath, filepath.Join(dir, "data"), nil, map[string]string{
		"max_message_bytes": "4096",
		"max_sync_zones":    "8",
		"max_sync_records":  "64",
		"log_level":         "debug",
	})
	t.Setenv("HIGGS_CONFIG", configPath)

	rt, err := NewRuntime()
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	state, _ := buildTestNetworkState(t)
	config, err := rt.SyncConfig(state)
	if err != nil {
		t.Fatalf("SyncConfig: %v", err)
	}
	if config.PeerID != string(state.ManagedZone) {
		t.Fatalf("PeerID = %q, want managed zone default %q", config.PeerID, state.ManagedZone)
	}
	limits := syncLimits(config)
	if limits.MaxBytes != 4096 || limits.MaxZones != 8 || limits.MaxRecords != 64 {
		t.Fatalf("limits = %#v, want 4096/8/64", limits)
	}
	if !debugLogEnabled(config) {
		t.Fatalf("config log_level=debug should enable debug logs")
	}
	t.Setenv("HIGGS_LOG_LEVEL", "info")
	if debugLogEnabled(config) {
		t.Fatalf("HIGGS_LOG_LEVEL should override config log_level")
	}
	t.Setenv("HIGGS_LOG_LEVEL", "debug")
	config.LogLevel = "info"
	if !debugLogEnabled(config) {
		t.Fatalf("HIGGS_LOG_LEVEL=debug should enable debug logs")
	}
}

func TestVerifyConfiguredRootTrustAt(t *testing.T) {
	state, _ := buildTestNetworkState(t)
	rootKey, err := rootPublicKey(state.Network)
	if err != nil {
		t.Fatalf("rootPublicKey: %v", err)
	}
	if err := verifyConfiguredRootTrustAt(state.Network, rootKey); err != nil {
		t.Fatalf("verifyConfiguredRootTrustAt(valid): %v", err)
	}

	wrongRoot := make(ed25519.PublicKey, ed25519.PublicKeySize)
	for i := range wrongRoot {
		wrongRoot[i] = byte(i + 1)
	}
	if err := verifyConfiguredRootTrustAt(state.Network, wrongRoot); err == nil {
		t.Fatalf("verifyConfiguredRootTrustAt should reject mismatched root")
	}
	if err := verifyConfiguredRootTrustAt(state.Network, nil); err != nil {
		t.Fatalf("verifyConfiguredRootTrustAt(nil): %v", err)
	}
}

func writeRuntimeConfig(t *testing.T, path string, dataDir string, rootKey ed25519.PublicKey, extra map[string]string) {
	t.Helper()
	var lines []string
	lines = append(lines, "data_dir: "+dataDir)
	lines = append(lines, "listen_addr: 127.0.0.1:0")
	if len(rootKey) > 0 {
		lines = append(lines, "trusted_root_public_key: "+hex.EncodeToString(rootKey))
	}
	for _, key := range []string{"max_message_bytes", "max_sync_zones", "max_sync_records", "log_level"} {
		if value := extra[key]; value != "" {
			lines = append(lines, key+": "+value)
		}
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(config): %v", err)
	}
}
