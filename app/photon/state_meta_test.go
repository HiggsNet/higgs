package main

import (
	"path/filepath"
	"testing"

	"github.com/HiggsNet/photon/pkg/core/zone"
)

func TestSaveStateMetaDoesNotRewriteNetwork(t *testing.T) {
	initial, _ := buildTestNetworkState(t)
	path := filepath.Join(t.TempDir(), "photon.db")
	if err := saveStateAt(path, initial); err != nil {
		t.Fatalf("save initial state: %v", err)
	}

	metaOnly := cloneStateFile(initial)
	metaOnly.RoutingReconcile = &routingReconcileState{LastRunUnix: 123, LastError: "routing error"}
	metaOnly.Network.Zones["node-b.catofes."].Authority.Epoch++
	if _, err := saveStateMetaAtWithFileInfo(path, metaOnly); err != nil {
		t.Fatalf("save metadata: %v", err)
	}

	store, err := zone.OpenBoltStore(path, 0o600)
	if err != nil {
		t.Fatalf("open state: %v", err)
	}
	defer store.Close()
	network, err := store.LoadNetwork()
	if err != nil {
		t.Fatalf("load Network: %v", err)
	}
	if got, want := network.Zones["node-b.catofes."].Authority.Epoch, initial.Network.Zones["node-b.catofes."].Authority.Epoch; got != want {
		t.Fatalf("metadata-only save rewrote Network epoch: got %d want %d", got, want)
	}
	var meta stateMeta
	if err := store.LoadMetaJSON(cliMetaKey, &meta); err != nil {
		t.Fatalf("load metadata: %v", err)
	}
	if meta.RoutingReconcile == nil || meta.RoutingReconcile.LastRunUnix != 123 || meta.RoutingReconcile.LastError != "routing error" {
		t.Fatalf("routing metadata = %+v", meta.RoutingReconcile)
	}
}

func TestSaveStateMetaSeedsMissingDatabase(t *testing.T) {
	initial, _ := buildTestNetworkState(t)
	path := filepath.Join(t.TempDir(), "photon.db")
	if _, err := saveStateMetaAtWithFileInfo(path, initial); err != nil {
		t.Fatalf("seed metadata save: %v", err)
	}

	store, err := zone.OpenBoltStore(path, 0o600)
	if err != nil {
		t.Fatalf("open seeded state: %v", err)
	}
	defer store.Close()
	network, err := store.LoadNetwork()
	if err != nil {
		t.Fatalf("load seeded Network: %v", err)
	}
	if len(network.Zones) != len(initial.Network.Zones) {
		t.Fatalf("seeded Network zones = %d, want %d", len(network.Zones), len(initial.Network.Zones))
	}
}
