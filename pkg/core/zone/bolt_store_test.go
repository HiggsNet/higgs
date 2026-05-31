package zone

import (
	"path/filepath"
	"testing"
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
}
