package main

import (
	"path/filepath"
	"testing"

	"github.com/HiggsNet/photon/pkg/core/zone"
	bolt "go.etcd.io/bbolt"
)

func TestSaveStateCommitsMetaAndNetworkInOneTransaction(t *testing.T) {
	initial, _ := buildTestNetworkState(t)
	path := filepath.Join(t.TempDir(), "photon.db")
	if err := saveStateAt(path, initial); err != nil {
		t.Fatalf("save initial state: %v", err)
	}
	before := stateDBTxID(t, path)

	next := cloneStateFile(initial)
	next.IdentityKeyPath = "/new/identity.key"
	next.Network.Zones["node-b.catofes."].Authority.Epoch++
	if err := saveStateAt(path, next); err != nil {
		t.Fatalf("save updated state: %v", err)
	}
	if got := stateDBTxID(t, path); got != before+1 {
		t.Fatalf("full state save tx id = %d, want one commit after %d", got, before)
	}

	loaded, err := loadStateAtWithConfig(path, nil)
	if err != nil {
		t.Fatalf("load updated state: %v", err)
	}
	if loaded.IdentityKeyPath != next.IdentityKeyPath {
		t.Fatalf("identity path = %q, want %q", loaded.IdentityKeyPath, next.IdentityKeyPath)
	}
	if got, want := loaded.Network.Zones["node-b.catofes."].Authority.Epoch, next.Network.Zones["node-b.catofes."].Authority.Epoch; got != want {
		t.Fatalf("Network epoch = %d, want %d", got, want)
	}
}

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

func stateDBTxID(t *testing.T, path string) int {
	t.Helper()
	db, err := bolt.Open(path, 0o600, &bolt.Options{ReadOnly: true})
	if err != nil {
		t.Fatalf("open state database: %v", err)
	}
	defer db.Close()
	var id int
	if err := db.View(func(tx *bolt.Tx) error {
		id = tx.ID()
		return nil
	}); err != nil {
		t.Fatalf("read state transaction id: %v", err)
	}
	return id
}
