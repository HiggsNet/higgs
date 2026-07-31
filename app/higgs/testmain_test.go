package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "higgs-app-test-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "MkdirTemp: %v\n", err)
		os.Exit(1)
	}
	if err := installTestConfigDefaults(dir); err != nil {
		fmt.Fprintf(os.Stderr, "install test config defaults: %v\n", err)
		os.RemoveAll(dir)
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

func installTestConfigDefaults(dir string) error {
	dataDir := filepath.Join(dir, "data")
	configPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(configPath, []byte("data_dir: "+dataDir+"\n"), 0o600); err != nil {
		return err
	}
	if err := os.Setenv("HIGGS_CONFIG", configPath); err != nil {
		return err
	}
	os.Unsetenv("HIGGS_STATE")
	os.Unsetenv("HIGGS_CONTROL_SOCKET")
	if err := os.Setenv("HIGGS_CONTROL_SOCKET_SCOPE", "data-dir"); err != nil {
		return err
	}
	return nil
}

func TestPackageTestsUseIsolatedConfigDefaults(t *testing.T) {
	if path := configPath(); path == defaultConfigPath || strings.HasPrefix(path, defaultDataDir) {
		t.Fatalf("test config path = %q, want isolated temporary config", path)
	}

	config, err := loadAppConfig()
	if err != nil {
		t.Fatalf("loadAppConfig: %v", err)
	}
	if strings.HasPrefix(config.StatePath, defaultDataDir) {
		t.Fatalf("test StatePath = %q, want isolated temporary state", config.StatePath)
	}

	statePath, err := configuredStatePath()
	if err != nil {
		t.Fatalf("configuredStatePath: %v", err)
	}
	if statePath != config.StatePath {
		t.Fatalf("configuredStatePath = %q, want config StatePath %q", statePath, config.StatePath)
	}

	controlPath := controlSocketPath(config)
	wantControlPath := filepath.Join(config.DataDir, controlSocketName)
	if controlPath != wantControlPath {
		t.Fatalf("controlSocketPath = %q, want isolated path %q", controlPath, wantControlPath)
	}
}
