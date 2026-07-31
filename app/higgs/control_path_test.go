package main

import (
	"path/filepath"
	"testing"
)

func TestControlSocketPathDataDirScope(t *testing.T) {
	t.Setenv("HIGGS_CONTROL_SOCKET", "")
	t.Setenv("HIGGS_CONTROL_SOCKET_SCOPE", "data-dir")

	dataDir := t.TempDir()
	got := controlSocketPath(&appConfig{DataDir: dataDir})
	want := filepath.Join(dataDir, controlSocketName)
	if got != want {
		t.Fatalf("controlSocketPath() = %q, want %q", got, want)
	}
}

func TestControlSocketPathExplicitOverridePrecedesDataDirScope(t *testing.T) {
	t.Setenv("HIGGS_CONTROL_SOCKET", "/tmp/explicit-higgs.sock")
	t.Setenv("HIGGS_CONTROL_SOCKET_SCOPE", "data-dir")

	got := controlSocketPath(&appConfig{DataDir: t.TempDir()})
	if got != "/tmp/explicit-higgs.sock" {
		t.Fatalf("controlSocketPath() = %q, want explicit override", got)
	}
}
