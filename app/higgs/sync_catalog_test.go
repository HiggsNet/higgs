package main

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/Catofes/higgs/pkg/core/gossip"
	"github.com/Catofes/higgs/pkg/core/zone"
	higgscrypto "github.com/Catofes/higgs/pkg/crypto"
)

func TestFilterRemoteCatalogPageSkipsManagedZone(t *testing.T) {
	state, _ := buildTestNetworkState(t)
	state.ManagedZone = "node-b.catofes."
	page := &gossip.CatalogPage{Entries: []gossip.ZoneDigest{
		{Zone: state.ManagedZone, RootHash: []byte("remote-own-root")},
		{Zone: "catofes.", RootHash: []byte("remote-parent-root")},
	}}

	filtered := filterRemoteCatalogPage(state, "zone-catofes-admin", page, time.Unix(1000, 0))
	if len(filtered.Entries) != 1 || filtered.Entries[0].Zone != "catofes." {
		t.Fatalf("filtered entries = %+v, want only catofes.", filtered.Entries)
	}
	if len(page.Entries) != 2 {
		t.Fatalf("original page was mutated: %+v", page.Entries)
	}
}

func TestApplySyncSnapshotRecordsRejectedDigest(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(2000, 0)
	badRecord := &zone.Record{Zone: "node-b.catofes.", Key: "bad", Type: "policy.string", Value: []byte("original"), Version: 1, Timestamp: now.Unix()}
	if err := higgscrypto.SignRecord(badRecord, state.ZonePrivateKey); err != nil {
		t.Fatalf("SignRecord: %v", err)
	}
	badRecord.Value = []byte("tampered")
	snapshot := &gossip.ZoneSnapshot{Zone: "node-b.catofes.", Authority: state.Network.Zones["node-b.catofes."].Authority, Records: map[string]*zone.Record{"bad": badRecord}}
	rt := &Runtime{StatePath: filepath.Join(t.TempDir(), "higgs.db"), Clock: func() time.Time { return now }}
	service := newDaemonService(rt, state, config, defaultDaemonInterval)
	if _, _, err := service.applySyncSnapshotAction("node-b.catofes.", ApplySnapshotAction{PeerID: "node-b.catofes.", Snapshot: snapshot}, gossip.DefaultSyncLimits(), now); err == nil {
		t.Fatal("applySyncSnapshotAction accepted an invalid snapshot")
	}
	committed, _ := service.StateStore.Snapshot()
	if !isRejectedDigestActive(committed, "node-b.catofes.", snapshot.Zone, digestForSnapshot(snapshot).RootHash, now.Add(time.Minute)) {
		t.Fatal("invalid snapshot did not record a rejected digest")
	}
}
