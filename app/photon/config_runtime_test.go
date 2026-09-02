package main

import (
	"crypto/ed25519"
	"path/filepath"
	"testing"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
)

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
	verified, checkpoint, runtime, _ := buildTestDaemonOwners(t)
	state := composeLinuxStateView(corestate.View{State: verified, Gossip: checkpoint}, runtime)
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
	verified, _, _, _ := buildTestDaemonOwners(t)
	rootKey, err := rootPublicKey(verified.Network)
	if err != nil {
		t.Fatalf("rootPublicKey: %v", err)
	}
	if err := verifyConfiguredRootTrustAt(verified.Network, rootKey); err != nil {
		t.Fatalf("verifyConfiguredRootTrustAt(valid): %v", err)
	}

	wrongRoot := make(ed25519.PublicKey, ed25519.PublicKeySize)
	for i := range wrongRoot {
		wrongRoot[i] = byte(i + 1)
	}
	if err := verifyConfiguredRootTrustAt(verified.Network, wrongRoot); err == nil {
		t.Fatalf("verifyConfiguredRootTrustAt should reject mismatched root")
	}
	if err := verifyConfiguredRootTrustAt(verified.Network, nil); err != nil {
		t.Fatalf("verifyConfiguredRootTrustAt(nil): %v", err)
	}
}
