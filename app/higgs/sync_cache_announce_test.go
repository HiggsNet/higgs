package main

import (
	"context"
	"github.com/Catofes/higgs/pkg/core/gossip"
	"github.com/Catofes/higgs/pkg/core/zone"
	higgscrypto "github.com/Catofes/higgs/pkg/crypto"
	"path/filepath"
	"testing"
	"time"
)

func TestRejectedDigestCacheSkipsSameRootWithinTTL(t *testing.T) {
	state, _ := buildTestNetworkState(t)
	now := time.Unix(1000, 0)
	digest := gossip.ZoneDigest{Zone: "node-b.catofes.", RootHash: []byte("bad-root")}

	recordRejectedDigest(state, "node-b.catofes.", digest, "verify_failed", now)

	if got := fetchListForPeer(state, "node-b.catofes.", []gossip.ZoneDigest{digest}, now.Add(time.Minute)); len(got) != 0 {
		t.Fatalf("fetchListForPeer() = %v, want skipped rejected digest", got)
	}
}

func TestFetchListForPeerSkipsManagedZone(t *testing.T) {
	state, _ := buildTestNetworkState(t)
	state.ManagedZone = "node-b.catofes."
	now := time.Unix(1000, 0)
	digest := gossip.ZoneDigest{Zone: state.ManagedZone, RootHash: []byte("remote-root")}

	if got := fetchListForPeer(state, "zone-catofes-admin", []gossip.ZoneDigest{digest}, now); len(got) != 0 {
		t.Fatalf("fetchListForPeer(managed zone) = %v, want skipped", got)
	}
}

func TestRejectedDigestCacheAllowsRootChangeAndExpiry(t *testing.T) {
	state, _ := buildTestNetworkState(t)
	now := time.Unix(1000, 0)
	oldDigest := gossip.ZoneDigest{Zone: "node-b.catofes.", RootHash: []byte("bad-root")}
	newDigest := gossip.ZoneDigest{Zone: "node-b.catofes.", RootHash: []byte("new-root")}

	recordRejectedDigest(state, "node-b.catofes.", oldDigest, "verify_failed", now)

	if got := fetchListForPeer(state, "node-b.catofes.", []gossip.ZoneDigest{newDigest}, now.Add(time.Minute)); len(got) != 1 {
		t.Fatalf("fetchListForPeer(new root) = %v, want retry", got)
	}
	if got := fetchListForPeer(state, "node-b.catofes.", []gossip.ZoneDigest{oldDigest}, now.Add(rejectedDigestTTL+time.Second)); len(got) != 1 {
		t.Fatalf("fetchListForPeer(expired) = %v, want retry", got)
	}
}

func TestHandleAnnounceSkipsManagedZoneSnapshotAndRecord(t *testing.T) {
	state, config := buildTestNetworkState(t)
	state.ManagedZone = "node-b.catofes."
	now := time.Unix(2000, 0)
	record, err := buildSignedRecordAt(state, state.ManagedZone, "remote-own-record", []byte("remote"), "policy.string", now)
	if err != nil {
		t.Fatalf("buildSignedRecordAt: %v", err)
	}
	snapshot, err := gossip.Snapshot(state.Network, state.ManagedZone)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	snapshot.Records["remote-own-record"] = record

	rt := &Runtime{StatePath: filepath.Join(t.TempDir(), "higgs.db"), Clock: func() time.Time { return now }}
	service := newDaemonService(rt, state, config, defaultDaemonInterval)
	session := NewSyncSession("zone-catofes-admin")
	state.Lock()
	unlock := state.Unlock
	service.executeSyncActions(context.Background(), session, []SyncAction{
		ApplySnapshotAction{PeerID: "zone-catofes-admin", Snapshot: snapshot},
	})
	unlock()
	if got := state.Network.Zones[state.ManagedZone].Records["remote-own-record"]; got != nil {
		t.Fatalf("managed zone record was applied from remote announce: %+v", got)
	}
}

func TestFilterRemoteCatalogPageSkipsManagedZone(t *testing.T) {
	state, _ := buildTestNetworkState(t)
	state.ManagedZone = "node-b.catofes."
	page := &gossip.CatalogPage{Entries: []gossip.ZoneDigest{
		{Zone: state.ManagedZone, RootHash: []byte("remote-own-root")},
		{Zone: "catofes.", RootHash: []byte("remote-parent-root")},
	}}

	filtered := filterRemoteCatalogPage(state, "zone-catofes-admin", page, time.Unix(1000, 0))
	if filtered == page {
		t.Fatal("filterRemoteCatalogPage returned original page, want filtered copy")
	}
	if len(filtered.Entries) != 1 || filtered.Entries[0].Zone != "catofes." {
		t.Fatalf("filtered entries = %+v, want only catofes.", filtered.Entries)
	}
	if len(page.Entries) != 2 {
		t.Fatalf("original page was mutated: %+v", page.Entries)
	}
}

func TestHandleAnnounceRecordsRejectedDigestOnVerifyFailure(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(2000, 0)
	badRecord := &zone.Record{
		Zone:      "node-b.catofes.",
		Key:       "bad",
		Type:      "policy.string",
		Value:     []byte("original"),
		Version:   1,
		Timestamp: now.Unix(),
	}
	if err := higgscrypto.SignRecord(badRecord, state.ZonePrivateKey); err != nil {
		t.Fatalf("SignRecord: %v", err)
	}
	badRecord.Value = []byte("tampered")
	snapshot := &gossip.ZoneSnapshot{
		Zone:      "node-b.catofes.",
		Authority: state.Network.Zones["node-b.catofes."].Authority,
		Records:   map[string]*zone.Record{"bad": badRecord},
	}
	digest := digestForSnapshot(snapshot)
	rt := &Runtime{StatePath: filepath.Join(t.TempDir(), "higgs.db"), Clock: func() time.Time { return now }}
	service := newDaemonService(rt, state, config, defaultDaemonInterval)
	session := NewSyncSession("node-b.catofes.")
	state.Lock()
	unlock := state.Unlock
	service.executeSyncActions(context.Background(), session, []SyncAction{
		ApplySnapshotAction{PeerID: "node-b.catofes.", Snapshot: snapshot},
	})
	unlock()
	snapshotState, _ := service.StateStore.Snapshot()
	if !isRejectedDigestActive(snapshotState, "node-b.catofes.", "node-b.catofes.", digest.RootHash, now.Add(time.Minute)) {
		t.Fatalf("rejected digest was not recorded")
	}
}

func TestRejectedRecordCacheSkipsSameObjectWithinTTL(t *testing.T) {
	state, _ := buildTestNetworkState(t)
	now := time.Unix(3000, 0)
	record := &zone.Record{
		Zone:      "node-b.catofes.",
		Key:       "bad-record",
		Type:      "policy.string",
		Value:     []byte("original"),
		Version:   1,
		Timestamp: now.Unix(),
	}
	if err := higgscrypto.SignRecord(record, state.ZonePrivateKey); err != nil {
		t.Fatalf("SignRecord: %v", err)
	}
	record.Value = []byte("tampered")
	snapshot := &gossip.RecordSnapshot{Zone: "node-b.catofes.", Record: record}

	recordRejectedRecord(state, "node-b.catofes.", snapshot, "verify_failed", now)

	if !isRejectedRecordActive(state, "node-b.catofes.", snapshot, "", now.Add(time.Minute)) {
		t.Fatalf("rejected record was not active")
	}
	if isRejectedRecordActive(state, "node-b.catofes.", snapshot, "", now.Add(rejectedDigestTTL+time.Second)) {
		t.Fatalf("rejected record stayed active after TTL")
	}
	changed := *record
	changed.Value = []byte("different tamper")
	if isRejectedRecordActive(state, "node-b.catofes.", &gossip.RecordSnapshot{Zone: "node-b.catofes.", Record: &changed}, "", now.Add(time.Minute)) {
		t.Fatalf("changed record hash should be retried")
	}
}
