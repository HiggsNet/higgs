package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Catofes/higgs/pkg/core/zone"
)

func TestJoinFlow(t *testing.T) {
	dir := t.TempDir()
	adminConfig := filepath.Join(dir, "admin.yaml")
	catofesConfig := filepath.Join(dir, "catofes.yaml")
	nodeConfig := filepath.Join(dir, "node.yaml")
	catofesKeyPath := filepath.Join(dir, "catofes.key.json")
	catofesRequestPath := filepath.Join(dir, "catofes.request.json")
	catofesBundlePath := filepath.Join(dir, "catofes.bundle.json")
	keyPath := filepath.Join(dir, "node-b.key.json")
	requestPath := filepath.Join(dir, "node-b.request.json")
	bundlePath := filepath.Join(dir, "node-b.bundle.json")

	writeConfig(t, adminConfig, filepath.Join(dir, "admin"))
	t.Setenv("HIGGS_CONFIG", adminConfig)
	if err := initRootState(); err != nil {
		t.Fatalf("initRootState(admin): %v", err)
	}

	writeConfig(t, catofesConfig, filepath.Join(dir, "catofes"))
	t.Setenv("HIGGS_CONFIG", catofesConfig)
	if err := keygen(catofesKeyPath); err != nil {
		t.Fatalf("keygen(catofes): %v", err)
	}
	if err := createJoinRequest("catofes.", catofesKeyPath, catofesRequestPath); err != nil {
		t.Fatalf("createJoinRequest(catofes): %v", err)
	}
	t.Setenv("HIGGS_CONFIG", adminConfig)
	if err := issueDelegation(catofesRequestPath, catofesBundlePath); err != nil {
		t.Fatalf("issueDelegation(catofes): %v", err)
	}
	t.Setenv("HIGGS_CONFIG", catofesConfig)
	if err := acceptJoinBundle(catofesBundlePath, catofesKeyPath); err != nil {
		t.Fatalf("acceptJoinBundle(catofes): %v", err)
	}

	t.Setenv("HIGGS_CONFIG", nodeConfig)
	writeConfig(t, nodeConfig, filepath.Join(dir, "node-b"))
	if err := keygen(keyPath); err != nil {
		t.Fatalf("keygen: %v", err)
	}
	if err := createJoinRequest("node-b.catofes.", keyPath, requestPath); err != nil {
		t.Fatalf("createJoinRequest: %v", err)
	}
	t.Setenv("HIGGS_CONFIG", catofesConfig)
	if err := issueDelegation(requestPath, bundlePath); err != nil {
		t.Fatalf("issueDelegation: %v", err)
	}

	t.Setenv("HIGGS_CONFIG", nodeConfig)
	if err := acceptJoinBundle(bundlePath, keyPath); err != nil {
		t.Fatalf("acceptJoinBundle: %v", err)
	}
	state, err := loadState()
	if err != nil {
		t.Fatalf("loadState(node-b): %v", err)
	}
	if state.ManagedZone != zone.ZonePath("node-b.catofes.") {
		t.Fatalf("ManagedZone = %s, want node-b.catofes.", state.ManagedZone)
	}
	if len(state.RootPrivateKey) != 0 {
		t.Fatalf("joined node unexpectedly has root private key")
	}
	if err := putRecord("node-b.catofes.", "identity", []byte("node-b"), "node.identity"); err != nil {
		t.Fatalf("putRecord(node-b): %v", err)
	}
	if err := verifyChain("node-b.catofes."); err != nil {
		t.Fatalf("verifyChain(node-b): %v", err)
	}
}

func writeConfig(t *testing.T, path string, dataDir string) {
	t.Helper()
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	content := "data_dir: " + dataDir + "\nlisten_addr: 127.0.0.1:0\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}
