package zone

import (
	"path/filepath"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func TestBoltStoreSaveLoadNetwork(t *testing.T) {
	path := filepath.Join(t.TempDir(), "photon.db")
	store, err := OpenBoltStore(path, 0o600)
	if err != nil {
		t.Fatalf("OpenBoltStore: %v", err)
	}
	defer store.Close()

	ns := NewNetworkState()
	ns.Zones[RootZone] = NewZoneState(RootZone, &ZoneAuthority{
		Zone:      RootZone,
		Epoch:     1,
		Threshold: 1,
	})
	ns.Zones["node1.catofes."] = NewZoneState("node1.catofes.", &ZoneAuthority{
		Zone:      "node1.catofes.",
		Epoch:     1,
		Threshold: 1,
	})
	ns.Zones["node1.catofes."].Records["identity"] = &Record{
		Zone:    "node1.catofes.",
		Key:     "identity",
		Type:    "node.identity",
		Value:   []byte("node1"),
		Version: 1,
	}
	ns.Zones["node1.catofes."].RecordHistory["identity"] = []*Record{{
		Zone:    "node1.catofes.",
		Key:     "identity",
		Type:    "node.identity",
		Value:   []byte("old"),
		Version: 0,
	}}
	ns.Zones[RootZone].Revocations["node1.catofes."] = &DelegationRevocation{
		ChildZone:             "node1.catofes.",
		ParentZone:            RootZone,
		RevokedAuthorityEpoch: 1,
		RevokedAuthorityHash:  []byte{1, 2, 3},
		Reason:                "retired",
		RevokedAt:             123,
		SignedBy:              []byte{4, 5, 6},
		Signature:             []byte{7, 8, 9},
	}
	if err := store.SaveNetwork(ns); err != nil {
		t.Fatalf("SaveNetwork: %v", err)
	}

	got, err := store.LoadNetwork()
	if err != nil {
		t.Fatalf("LoadNetwork: %v", err)
	}
	zs := got.Zones["node1.catofes."]
	if zs == nil {
		t.Fatalf("loaded zone missing")
	}
	if got := string(zs.Records["identity"].Value); got != "node1" {
		t.Fatalf("loaded record value = %q, want node1", got)
	}
	if got := len(zs.RecordHistory["identity"]); got != 1 {
		t.Fatalf("loaded history len = %d, want 1", got)
	}
	revocation := got.Zones[RootZone].Revocations["node1.catofes."]
	if revocation == nil {
		t.Fatalf("loaded revocation missing")
	}
	if revocation.Reason != "retired" || revocation.RevokedAt != 123 {
		t.Fatalf("loaded revocation = %#v, want retired at 123", revocation)
	}
}

func TestBoltStoreCombinedSaveUsesOneTransactionAndSkipsNoop(t *testing.T) {
	path := filepath.Join(t.TempDir(), "photon.db")
	store, err := OpenBoltStore(path, 0o600)
	if err != nil {
		t.Fatalf("OpenBoltStore: %v", err)
	}
	defer store.Close()

	ns := NewNetworkState()
	ns.Zones[RootZone] = NewZoneState(RootZone, &ZoneAuthority{Zone: RootZone, Epoch: 1, Threshold: 1})
	before := boltStoreTxID(t, store)
	if err := store.SaveNetworkAndMetaJSON("daemon", map[string]string{"state": "ready"}, ns); err != nil {
		t.Fatalf("SaveNetworkAndMetaJSON: %v", err)
	}
	after := boltStoreTxID(t, store)
	if after != before+1 {
		t.Fatalf("combined save tx id = %d, want one commit after %d", after, before)
	}
	if err := store.SaveNetworkAndMetaJSON("daemon", map[string]string{"state": "ready"}, ns); err != nil {
		t.Fatalf("SaveNetworkAndMetaJSON(no-op): %v", err)
	}
	if got := boltStoreTxID(t, store); got != after {
		t.Fatalf("no-op save tx id = %d, want unchanged %d", got, after)
	}

	ns.Zones[RootZone].Authority.Epoch = 2
	if err := store.SaveNetworkAndMetaJSON("daemon", map[string]string{"state": "updated"}, ns); err != nil {
		t.Fatalf("SaveNetworkAndMetaJSON(update): %v", err)
	}
	if got := boltStoreTxID(t, store); got != after+1 {
		t.Fatalf("combined update tx id = %d, want %d", got, after+1)
	}
}

func TestBoltStoreCombinedSaveValidationFailureIsAtomic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "photon.db")
	store, err := OpenBoltStore(path, 0o600)
	if err != nil {
		t.Fatalf("OpenBoltStore: %v", err)
	}
	defer store.Close()

	ns := NewNetworkState()
	ns.Zones[RootZone] = NewZoneState(RootZone, &ZoneAuthority{Zone: RootZone, Epoch: 1, Threshold: 1})
	if err := store.SaveNetworkAndMetaJSON("daemon", "ready", ns); err != nil {
		t.Fatalf("seed state: %v", err)
	}
	before := boltStoreTxID(t, store)
	ns.Zones[RootZone].Authority.Epoch = 2
	if err := store.SaveNetworkAndMetaJSON("daemon", make(chan int), ns); err == nil {
		t.Fatal("combined save with unsupported metadata unexpectedly succeeded")
	}
	if got := boltStoreTxID(t, store); got != before {
		t.Fatalf("failed combined save tx id = %d, want unchanged %d", got, before)
	}
	loaded, err := store.LoadNetwork()
	if err != nil {
		t.Fatalf("LoadNetwork: %v", err)
	}
	if got := loaded.Zones[RootZone].Authority.Epoch; got != 1 {
		t.Fatalf("failed combined save persisted Network epoch %d, want 1", got)
	}
	var meta string
	if err := store.LoadMetaJSON("daemon", &meta); err != nil {
		t.Fatalf("LoadMetaJSON: %v", err)
	}
	if meta != "ready" {
		t.Fatalf("failed combined save persisted metadata %q, want ready", meta)
	}
}

func boltStoreTxID(t *testing.T, store *BoltStore) int {
	t.Helper()
	var id int
	if err := store.db.View(func(tx *bolt.Tx) error {
		id = tx.ID()
		return nil
	}); err != nil {
		t.Fatalf("read transaction id: %v", err)
	}
	return id
}

func TestBoltStoreSaveNetworkDoesNotMutateZonePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "photon.db")
	store, err := OpenBoltStore(path, 0o600)
	if err != nil {
		t.Fatalf("OpenBoltStore: %v", err)
	}
	defer store.Close()

	const zonePath ZonePath = "node1.catofes."
	zs := NewZoneState("", &ZoneAuthority{
		Zone:      zonePath,
		Epoch:     1,
		Threshold: 1,
	})
	ns := NewNetworkState()
	ns.Zones[zonePath] = zs

	if err := store.SaveNetwork(ns); err != nil {
		t.Fatalf("SaveNetwork: %v", err)
	}
	if zs.Path != "" {
		t.Fatalf("SaveNetwork mutated zone path: got %q want empty", zs.Path)
	}

	loaded, err := store.LoadNetwork()
	if err != nil {
		t.Fatalf("LoadNetwork: %v", err)
	}
	if got := loaded.Zones[zonePath]; got == nil || got.Path != zonePath {
		t.Fatalf("loaded zone = %#v, want path %q", got, zonePath)
	}
}

func TestBoltStoreLoadTrimsLegacyRecordHistory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "photon.db")
	store, err := OpenBoltStore(path, 0o600)
	if err != nil {
		t.Fatalf("OpenBoltStore: %v", err)
	}
	defer store.Close()

	ns := NewNetworkState()
	zs := NewZoneState("node1.catofes.", &ZoneAuthority{
		Zone:      "node1.catofes.",
		Epoch:     1,
		Threshold: 1,
	})
	historyLen := MaxRecordHistoryPerKey + 5
	history := make([]*Record, 0, historyLen)
	for version := 1; version <= historyLen; version++ {
		history = append(history, &Record{
			Zone:    "node1.catofes.",
			Key:     "identity",
			Version: uint64(version),
		})
	}
	zs.RecordHistory["identity"] = history
	ns.Zones[zs.Path] = zs
	if err := store.SaveNetwork(ns); err != nil {
		t.Fatalf("SaveNetwork: %v", err)
	}

	got, err := store.LoadNetwork()
	if err != nil {
		t.Fatalf("LoadNetwork: %v", err)
	}
	loaded := got.Zones[zs.Path].RecordHistory["identity"]
	if len(loaded) != MaxRecordHistoryPerKey {
		t.Fatalf("loaded history len = %d, want %d", len(loaded), MaxRecordHistoryPerKey)
	}
	wantOldest := uint64(historyLen - MaxRecordHistoryPerKey + 1)
	if loaded[0].Version != wantOldest {
		t.Fatalf("oldest loaded version = %d, want %d", loaded[0].Version, wantOldest)
	}
}

func TestBoltStoreLoadRestoresLatestActiveRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "photon.db")
	store, err := OpenBoltStore(path, 0o600)
	if err != nil {
		t.Fatalf("OpenBoltStore: %v", err)
	}
	defer store.Close()

	ns := NewNetworkState()
	ns.ConfigureRecordValidation(
		func(record *Record, authority *ZoneAuthority, now time.Time) error { return nil },
		func(record *Record) []byte { return []byte{byte(record.Version)} },
	)
	ns.Zones["node1.catofes."] = NewZoneState("node1.catofes.", &ZoneAuthority{
		Zone:      "node1.catofes.",
		Epoch:     1,
		Threshold: 1,
	})
	for version := uint64(1); version <= MaxRecordHistoryPerKey+2; version++ {
		record := &Record{
			Zone:    "node1.catofes.",
			Key:     "identity",
			Type:    "node.identity",
			Value:   []byte{byte(version)},
			Version: version,
		}
		if err := ns.PutAt(record, time.Unix(123, 0)); err != nil {
			t.Fatalf("PutAt(v%d): %v", version, err)
		}
	}
	if err := store.SaveNetwork(ns); err != nil {
		t.Fatalf("SaveNetwork: %v", err)
	}

	got, err := store.LoadNetwork()
	if err != nil {
		t.Fatalf("LoadNetwork: %v", err)
	}
	zs := got.Zones["node1.catofes."]
	if zs == nil {
		t.Fatalf("loaded zone missing")
	}
	active := zs.Records["identity"]
	if active == nil || active.Version != MaxRecordHistoryPerKey+2 {
		t.Fatalf("loaded active record = %#v, want latest version %d", active, MaxRecordHistoryPerKey+2)
	}
	if got := len(zs.RecordHistory["identity"]); got != MaxRecordHistoryPerKey {
		t.Fatalf("loaded history len = %d, want %d", got, MaxRecordHistoryPerKey)
	}
	if got := zs.RecordHistory["identity"][0].Version; got != 2 {
		t.Fatalf("oldest loaded history version = %d, want 2", got)
	}
}

func TestBoltStoreSaveNetworkDeletesRemovedZoneBuckets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "photon.db")
	store, err := OpenBoltStore(path, 0o600)
	if err != nil {
		t.Fatalf("OpenBoltStore: %v", err)
	}
	defer store.Close()

	ns := NewNetworkState()
	ns.Zones[RootZone] = NewZoneState(RootZone, &ZoneAuthority{
		Zone:      RootZone,
		Epoch:     1,
		Threshold: 1,
	})
	ns.Zones["node1.catofes."] = NewZoneState("node1.catofes.", &ZoneAuthority{
		Zone:      "node1.catofes.",
		Epoch:     1,
		Threshold: 1,
	})
	if err := store.SaveNetwork(ns); err != nil {
		t.Fatalf("SaveNetwork(initial): %v", err)
	}

	delete(ns.Zones, "node1.catofes.")
	if err := store.SaveNetwork(ns); err != nil {
		t.Fatalf("SaveNetwork(delete): %v", err)
	}

	got, err := store.LoadNetwork()
	if err != nil {
		t.Fatalf("LoadNetwork: %v", err)
	}
	if got.Zones["node1.catofes."] != nil {
		t.Fatalf("removed zone bucket was loaded again")
	}
	if got.Zones[RootZone] == nil {
		t.Fatalf("root zone was unexpectedly removed")
	}
}
