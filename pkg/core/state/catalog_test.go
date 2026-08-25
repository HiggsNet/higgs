package state

import (
	"bytes"
	"testing"

	"github.com/HiggsNet/photon/pkg/core/zone"
)

func TestCatalogSummaryForDigestsMatchesCatalogRoot(t *testing.T) {
	entries := []ZoneDigest{
		{Zone: "a.catofes.", RootHash: bytes.Repeat([]byte{1}, 32)},
		{Zone: "b.catofes.", RootHash: bytes.Repeat([]byte{2}, 32)},
	}
	summary := CatalogSummaryForDigests(entries)
	if summary.ZoneCount != len(entries) || !bytes.Equal(summary.CatalogRoot, CatalogRoot(entries)) {
		t.Fatalf("summary = %#v, want zone_count=%d root=%x", summary, len(entries), CatalogRoot(entries))
	}
}

func TestCatalogDiffReturnsOnlyValidChangedRemoteEntries(t *testing.T) {
	local := []ZoneDigest{{Zone: "a.catofes.", RootHash: []byte("same")}}
	remote := []ZoneDigest{
		{Zone: "a.catofes.", RootHash: []byte("same")},
		{Zone: "b.catofes.", RootHash: []byte("different")},
		{Zone: "invalid", RootHash: []byte("ignored")},
	}
	diff := CatalogDiff(local, remote)
	if len(diff) != 1 || diff[0].Zone != "b.catofes." {
		t.Fatalf("CatalogDiff = %#v, want changed valid remote zone", diff)
	}
}

func TestZoneDigestsAreStable(t *testing.T) {
	ns := zone.NewNetworkState()
	ns.Zones["catofes."] = zone.NewZoneState("catofes.", &zone.ZoneAuthority{
		Zone:      "catofes.",
		Epoch:     1,
		Threshold: 1,
	})
	ns.Zones["catofes."].Records["identity"] = &zone.Record{
		Zone:      "catofes.",
		Key:       "identity",
		Type:      "node.identity",
		Value:     []byte("node"),
		ValueHash: []byte{1},
		Version:   1,
		Timestamp: 123,
	}
	first := ZoneDigests(ns)
	second := ZoneDigests(ns)
	if len(first) != 1 || len(second) != 1 {
		t.Fatalf("ZoneDigests lengths = %d/%d, want 1/1", len(first), len(second))
	}
	if !bytes.Equal(first[0].RootHash, second[0].RootHash) {
		t.Fatal("ZoneDigests root hash changed for same state")
	}
}
