package main

import (
	"crypto/ed25519"
	"path/filepath"
	"testing"
)

func TestRuntimeCachesConfigForStateIO(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	dataDir := filepath.Join(dir, "data")
	statePath := filepath.Join(dataDir, "photon.db")

	state, _ := buildTestNetworkState(t)
	rootKey, err := rootPublicKey(state.Network)
	if err != nil {
		t.Fatalf("rootPublicKey: %v", err)
	}
	writeRuntimeConfig(t, configPath, dataDir, rootKey, nil)
	t.Setenv("PHOTON_CONFIG", configPath)

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
	t.Setenv("PHOTON_CONFIG", configPath)
	t.Setenv("PHOTON_STATE", overridePath)

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
		"max_datagram_bytes": "4096",
		"max_sync_zones":     "8",
		"max_sync_records":   "64",
		"log.level":          "debug",
		"log.mode":           "stderr+file",
		"log.file":           filepath.Join(dir, "photon.log"),
	})
	t.Setenv("PHOTON_CONFIG", configPath)

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
		t.Fatalf("config log.level=debug should enable debug logs")
	}
	if config.LogMode != "stderr+file" || config.LogFile != filepath.Join(dir, "photon.log") {
		t.Fatalf("log output config = mode %q file %q, want stderr+file/%s", config.LogMode, config.LogFile, filepath.Join(dir, "photon.log"))
	}
	t.Setenv("PHOTON_LOG_LEVEL", "info")
	if debugLogEnabled(config) {
		t.Fatalf("PHOTON_LOG_LEVEL should override config log.level")
	}
	t.Setenv("PHOTON_LOG_LEVEL", "debug")
	config.LogLevel = "info"
	if !debugLogEnabled(config) {
		t.Fatalf("PHOTON_LOG_LEVEL=debug should enable debug logs")
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
