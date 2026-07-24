package zone

import (
	"path/filepath"
	"testing"
	"time"
)

func TestBoltStoreSaveLoadNetwork(t *testing.T) {
	path := filepath.Join(t.TempDir(), "higgs.db")
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

func TestBoltStoreLoadTrimsLegacyRecordHistory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "higgs.db")
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
	path := filepath.Join(t.TempDir(), "higgs.db")
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
	path := filepath.Join(t.TempDir(), "higgs.db")
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
