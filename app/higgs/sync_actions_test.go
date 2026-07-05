package main

import (
	"context"
	"crypto/sha256"
	"github.com/Catofes/higgs/pkg/core/gossip"
	"github.com/Catofes/higgs/pkg/core/zone"
	"path/filepath"
	"testing"
	"time"
)

func TestHandleSyncEventCommitsPeerDiagnosticsToStateStore(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(2100, 0)
	rt := &Runtime{
		StatePath: filepath.Join(t.TempDir(), "higgs.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	service := newDaemonService(rt, state, config, defaultDaemonInterval)
	peerID := "node-b.catofes."
	service.syncSessions[peerID] = NewSyncSession(peerID)

	service.handleSyncEvent(context.Background(), &CatalogSummaryReceivedEvent{
		PeerID: peerID,
		Summary: &gossip.CatalogSummary{
			CatalogRoot: []byte{0x21, 0x22},
			ZoneCount:   2,
			NextCursor:  "next-page",
		},
	})

	snapshot, _ := service.StateStore.Snapshot()
	peerState := snapshot.SyncPeers[peerID]
	stats := peerState.DatagramStats
	if stats == nil {
		t.Fatal("datagram stats missing from committed snapshot")
	}
	if stats.LastCatalogRootHex != "2122" || stats.LastCatalogZoneCount != 2 || stats.LastCatalogCursor != "next-page" {
		t.Fatalf("catalog stats = %+v, want committed summary", stats)
	}
	if peerState.ActivePullState != string(SyncSessionCatalogDiffing) || peerState.ActivePullLastEvent != "catalog_summary" {
		t.Fatalf("active pull = state %q event %q, want committed catalog diffing summary", peerState.ActivePullState, peerState.ActivePullLastEvent)
	}
}

func TestExecuteSyncActionsAppliesSnapshotThroughStateStore(t *testing.T) {
	base, config := buildTestNetworkState(t)
	state := cloneStateFile(base)
	source := cloneStateFile(base)
	now := time.Unix(2200, 0)
	record, err := buildSignedRecordAt(source, "node-b.catofes.", "remote-record", []byte("remote"), "policy.string", now)
	if err != nil {
		t.Fatalf("buildSignedRecordAt: %v", err)
	}
	source.Network.Zones["node-b.catofes."].Records[record.Key] = record
	snapshot, err := gossip.Snapshot(source.Network, "node-b.catofes.")
	if err != nil {
		t.Fatalf("Snapshot(node-b): %v", err)
	}

	rt := &Runtime{StatePath: filepath.Join(t.TempDir(), "higgs.db"), Clock: func() time.Time { return now }}
	service := newDaemonService(rt, state, config, defaultDaemonInterval)
	session := NewSyncSession("node-b.catofes.")
	unlock := service.lockState()
	changed := service.executeSyncActions(context.Background(), session, []SyncAction{
		ApplySnapshotAction{PeerID: "node-b.catofes.", Snapshot: snapshot},
	})
	unlock()
	if !changed {
		t.Fatal("executeSyncActions changed = false, want true")
	}

	committed, _ := service.StateStore.Snapshot()
	if got := committed.Network.Zones["node-b.catofes."].Records["remote-record"]; got == nil {
		t.Fatal("committed snapshot missing applied record")
	}
	current := service.currentState()
	if got := current.Network.Zones["node-b.catofes."].Records["remote-record"]; got == nil {
		t.Fatal("current state missing applied record")
	}
}

func TestHandleObjectChunkAppliesZoneSnapshot(t *testing.T) {
	prepareStatePersistence(t)
	udpChunkAssemblies = newChunkAssemblyStore()
	sourceState, _ := buildTestNetworkState(t)
	snapshot, err := gossip.Snapshot(sourceState.Network, "catofes.")
	if err != nil {
		t.Fatalf("Snapshot(catofes): %v", err)
	}
	data, err := gossip.EncodeZoneSnapshotObject(snapshot)
	if err != nil {
		t.Fatalf("EncodeZoneSnapshotObject: %v", err)
	}
	objectHash := sha256.Sum256(data)
	rootHash := gossip.ZoneRoot(sourceState.Network.Zones["catofes."])
	targetState := sourceState
	config := &syncConfigFile{PeerID: "node-a.catofes.", ListenAddr: "127.0.0.1:0"}
	delete(targetState.Network.Zones, zone.ZonePath("catofes."))
	delete(targetState.Network.Zones, zone.ZonePath("node-b.catofes."))
	if err := saveState(targetState); err != nil {
		t.Fatalf("saveState(target): %v", err)
	}
	rt, err := NewRuntime()
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	rt.Clock = func() time.Time { return time.Unix(123, 0) }
	sr := newSyncRuntime(targetState, config, nil, rt)

	chunkSize := len(data) / 2
	if chunkSize == 0 {
		t.Fatalf("encoded snapshot unexpectedly empty")
	}
	chunks := []*gossip.ObjectChunk{
		{
			Object:     gossip.ObjectPullZone,
			Zone:       "catofes.",
			RootHash:   rootHash,
			ObjectHash: objectHash[:],
			Index:      0,
			Total:      2,
			Data:       data[:chunkSize],
		},
		{
			Object:     gossip.ObjectPullZone,
			Zone:       "catofes.",
			RootHash:   rootHash,
			ObjectHash: objectHash[:],
			Index:      1,
			Total:      2,
			Data:       data[chunkSize:],
		},
	}
	for _, chunk := range []*gossip.ObjectChunk{chunks[1], chunks[0]} {
		err := sr.handleObjectChunk(&gossip.Message{
			Type:        gossip.MessageObjectChunk,
			PeerID:      "node-b.catofes.",
			ObjectChunk: chunk,
		}, gossip.DefaultSyncLimits())
		if err != nil {
			t.Fatalf("handleObjectChunk: %v", err)
		}
	}
	if targetState.Network.Zones["catofes."] == nil {
		t.Fatalf("catofes. zone was not applied from chunks")
	}
	stats := targetState.SyncPeers["node-b.catofes."].DatagramStats
	if stats == nil || stats.ChunkFallbacks == 0 {
		t.Fatalf("chunk fallback stats were not recorded: %#v", stats)
	}
}

func TestSnapshotRecordMessagesPrioritizesActiveRecord(t *testing.T) {
	snapshot := &gossip.ZoneSnapshot{
		Zone: "node-b.catofes.",
		Records: map[string]*zone.Record{
			"identity": {
				Zone:    "node-b.catofes.",
				Key:     "identity",
				Version: 2,
				Value:   []byte("node-b-restarted"),
			},
		},
		RecordHistory: map[string][]*zone.Record{
			"identity": {
				{
					Zone:    "node-b.catofes.",
					Key:     "identity",
					Version: 1,
					Value:   []byte("node-b"),
				},
			},
		},
	}

	records := snapshotRecordMessages(snapshot)
	if len(records) != 2 {
		t.Fatalf("records = %d, want 2", len(records))
	}
	if records[0].Record == nil || records[0].Record.Version != 2 || string(records[0].Record.Value) != "node-b-restarted" {
		t.Fatalf("first record = %#v, want active v2", records[0].Record)
	}
	if records[1].Record == nil || records[1].Record.Version != 1 || string(records[1].Record.Value) != "node-b" {
		t.Fatalf("second record = %#v, want history v1", records[1].Record)
	}
}
