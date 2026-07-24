package main

import (
	"context"
	"crypto/sha256"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/Catofes/higgs/internal/observability"
	"github.com/Catofes/higgs/pkg/core/gossip"
	"github.com/Catofes/higgs/pkg/core/zone"
)

func TestHandleSyncEventStoresPeerDiagnosticsOutsideCommittedState(t *testing.T) {
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
	observed, ok := service.PeerObservability.Snapshot(peerID, now)
	if !ok {
		t.Fatal("peer observability snapshot missing")
	}
	stats := observed.DatagramStats
	if stats == nil {
		t.Fatal("datagram stats missing from observability snapshot")
	}
	if stats.LastCatalogRootHex != "2122" || stats.LastCatalogZoneCount != 2 || stats.LastCatalogCursor != "next-page" {
		t.Fatalf("catalog stats = %+v, want committed summary", stats)
	}
	if peerState.ActivePullState != string(SyncSessionCatalogDiffing) || peerState.ActivePullLastEvent != "catalog_summary" {
		t.Fatalf("active pull = state %q event %q, want committed catalog diffing summary", peerState.ActivePullState, peerState.ActivePullLastEvent)
	}
	if peerState.DatagramStats != nil {
		t.Fatalf("datagram stats leaked into committed state: %+v", peerState.DatagramStats)
	}
}

func TestHandleSyncEventDoesNotWaitForLiveStateLock(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(2120, 0)
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

	state.Lock()
	unlock := state.Unlock
	done := make(chan struct{})
	go func() {
		service.handleSyncEvent(context.Background(), &CatalogSummaryReceivedEvent{
			PeerID: peerID,
			Summary: &gossip.CatalogSummary{
				CatalogRoot: []byte{0x31, 0x32},
				ZoneCount:   3,
			},
		})
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		unlock()
		t.Fatal("handleSyncEvent blocked behind live state lock")
	}
	unlock()

	snapshot, _ := service.StateStore.Snapshot()
	peerState := snapshot.SyncPeers[peerID]
	observed, ok := service.PeerObservability.Snapshot(peerID, now)
	if !ok || observed.DatagramStats == nil || observed.DatagramStats.LastCatalogRootHex != "3132" {
		t.Fatalf("catalog stats = %+v, want observability summary", observed.DatagramStats)
	}
	if peerState.ActivePullState != string(SyncSessionCatalogDiffing) {
		t.Fatalf("active pull state = %q, want catalog diffing", peerState.ActivePullState)
	}
}

func TestReadOnlyResponderUsesCommittedSnapshotWhileLiveStateLocked(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(2130, 0)
	rt := &Runtime{
		StatePath: filepath.Join(t.TempDir(), "higgs.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	service := newDaemonService(rt, state, config, defaultDaemonInterval)
	peerID := "node-b.catofes."

	state.Lock()
	unlock := state.Unlock
	done := make(chan error, 1)
	go func() {
		done <- service.respondFetchCatalogPage(peerID, "")
	}()

	select {
	case err := <-done:
		if err != nil {
			unlock()
			t.Fatalf("respondFetchCatalogPage: %v", err)
		}
	case <-time.After(time.Second):
		unlock()
		t.Fatal("read-only responder blocked behind live state lock")
	}
	unlock()

	snapshot, _ := service.StateStore.Snapshot()
	peerState := snapshot.SyncPeers[peerID]
	if peerState.ReadOnlyResponder == 0 {
		t.Fatalf("read-only responder count = %d, want committed read-only responder stats", peerState.ReadOnlyResponder)
	}
	observed, ok := service.PeerObservability.Snapshot(peerID, now)
	if !ok || observed.DatagramStats == nil || (observed.DatagramStats.LastCatalogCursor == "" && observed.DatagramStats.LastCatalogPageEntries == 0) {
		t.Fatalf("catalog page stats = %+v, want observability catalog page", observed.DatagramStats)
	}
}

func TestChunkResponderCommitsDatagramDiagnostics(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(2140, 0)
	rt := &Runtime{
		StatePath: filepath.Join(t.TempDir(), "higgs.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	transport, err := gossip.Listen(gossip.Config{
		PeerID:          config.PeerID,
		ListenAddr:      "127.0.0.1:0",
		MaxMessageBytes: gossip.DefaultDatagramBudget,
	})
	if err != nil {
		skipRestrictedSocket(t, err)
		t.Fatalf("Listen: %v", err)
	}
	defer transport.Close()
	peerID := "node-b.catofes."
	transport.SetPeerAddrs(peerID, []*net.UDPAddr{transport.LocalAddr()})
	service := newDaemonService(rt, state, config, defaultDaemonInterval)
	service.Sync.Transport = transport

	state.Lock()
	unlock := state.Unlock
	done := make(chan error, 1)
	go func() {
		done <- service.respondFetchZoneChunks(peerID, "node-b.catofes.")
	}()

	select {
	case err := <-done:
		if err != nil {
			unlock()
			t.Fatalf("respondFetchZoneChunks: %v", err)
		}
	case <-time.After(time.Second):
		unlock()
		t.Fatal("chunk responder blocked behind live state lock")
	}
	unlock()

	observed, ok := service.PeerObservability.Snapshot(peerID, now)
	if !ok {
		t.Fatal("peer observability snapshot missing")
	}
	stats := observed.DatagramStats
	if stats == nil || stats.ChunkFallbacks == 0 {
		t.Fatalf("datagram stats = %+v, want observability chunk fallback counter", stats)
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
	state.Lock()
	unlock := state.Unlock
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
	sr.Observability = observability.NewPeerObservabilityStore(8, time.Hour)

	chunkSize := len(data) / 2
	if chunkSize == 0 {
		t.Fatalf("encoded snapshot unexpectedly empty")
	}
	chunks := []*gossip.ObjectChunk{
		{
			TransferID: []byte("0123456789abcdef"),
			Object:     gossip.ObjectPullZone,
			Zone:       "catofes.",
			RootHash:   rootHash,
			ObjectHash: objectHash[:],
			Index:      0,
			Total:      2,
			Data:       data[:chunkSize],
		},
		{
			TransferID: []byte("0123456789abcdef"),
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
	observed, ok := sr.Observability.Snapshot("node-b.catofes.", rt.Now())
	if !ok {
		t.Fatal("peer observability snapshot missing")
	}
	stats := observed.DatagramStats
	if stats == nil || stats.ChunkFallbacks == 0 {
		t.Fatalf("chunk fallback stats were not recorded: %#v", stats)
	}
}

func TestDaemonHandleObjectChunkCommitsThroughStateStore(t *testing.T) {
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

	targetState := cloneStateFile(sourceState)
	delete(targetState.Network.Zones, zone.ZonePath("catofes."))
	delete(targetState.Network.Zones, zone.ZonePath("node-b.catofes."))
	now := time.Unix(2230, 0)
	rt := &Runtime{
		StatePath: filepath.Join(t.TempDir(), "higgs.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rt.SaveState(targetState); err != nil {
		t.Fatalf("SaveState(target): %v", err)
	}
	config := &syncConfigFile{PeerID: "node-a.catofes.", ListenAddr: "127.0.0.1:0"}
	service := newDaemonService(rt, targetState, config, defaultDaemonInterval)
	beforeRev := service.StateStore.Meta().Revision

	chunkSize := len(data) / 2
	if chunkSize == 0 {
		t.Fatal("encoded snapshot unexpectedly empty")
	}
	chunks := []*gossip.ObjectChunk{
		{
			TransferID: []byte("daemon-chunks-01"),
			Object:     gossip.ObjectPullZone,
			Zone:       "catofes.",
			RootHash:   rootHash,
			ObjectHash: objectHash[:],
			Index:      0,
			Total:      2,
			Data:       data[:chunkSize],
		},
		{
			TransferID: []byte("daemon-chunks-01"),
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
		if err := service.handleObjectChunk(&gossip.Message{
			Type:        gossip.MessageObjectChunk,
			PeerID:      "node-b.catofes.",
			ObjectChunk: chunk,
		}, gossip.DefaultSyncLimits()); err != nil {
			t.Fatalf("handleObjectChunk: %v", err)
		}
	}

	if targetState.Network.Zones["catofes."] != nil {
		t.Fatal("daemon object chunk mutated the old live state")
	}
	committed, rev := service.StateStore.Snapshot()
	if rev != beforeRev+1 {
		t.Fatalf("state revision = %d, want exactly one object apply after %d", rev, beforeRev)
	}
	if committed.Network.Zones["catofes."] == nil {
		t.Fatal("committed state missing chunk-applied zone")
	}
	if current := service.currentState(); current == targetState || current.Network.Zones["catofes."] == nil {
		t.Fatal("current state was not installed from committed snapshot")
	}
	reloaded, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if reloaded.Network.Zones["catofes."] == nil {
		t.Fatal("persisted state missing chunk-applied zone")
	}
	observed, ok := service.PeerObservability.Snapshot("node-b.catofes.", now)
	if !ok || observed.DatagramStats == nil || observed.DatagramStats.ChunkFallbacks != 1 {
		t.Fatalf("chunk fallback observability = %+v, want one apply", observed.DatagramStats)
	}
}

func TestDaemonHandleObjectChunkRejectUsesPeerCOW(t *testing.T) {
	udpChunkAssemblies = newChunkAssemblyStore()
	state, config := buildTestNetworkState(t)
	now := time.Unix(2240, 0)
	rt := &Runtime{
		StatePath: filepath.Join(t.TempDir(), "higgs.db"),
		Clock:     func() time.Time { return now },
	}
	service := newDaemonService(rt, state, config, defaultDaemonInterval)
	peerID := "node-b.catofes."
	beforeRev := service.StateStore.Meta().Revision
	rootHash := gossip.ZoneRoot(state.Network.Zones["catofes."])

	err := service.handleObjectChunk(&gossip.Message{
		Type:   gossip.MessageObjectChunk,
		PeerID: peerID,
		ObjectChunk: &gossip.ObjectChunk{
			TransferID: []byte("daemon-reject-01"),
			Object:     gossip.ObjectPullZone,
			Zone:       "catofes.",
			RootHash:   rootHash,
			ObjectHash: make([]byte, sha256.Size),
			Index:      0,
			Total:      1,
			Data:       []byte("invalid object"),
		},
	}, gossip.DefaultSyncLimits())
	if err == nil {
		t.Fatal("handleObjectChunk accepted invalid object hash")
	}

	if len(state.SyncPeers[peerID].RejectedDigests) != 0 {
		t.Fatal("chunk rejection mutated the old live peer state")
	}
	committed, rev := service.StateStore.Snapshot()
	if rev != beforeRev+1 {
		t.Fatalf("state revision = %d, want one peer COW commit after %d", rev, beforeRev)
	}
	rejected, ok := committed.SyncPeers[peerID].RejectedDigests[rejectedDigestKey("catofes.")]
	if !ok || rejected.Reason == "" || rejected.RootHashHex == "" {
		t.Fatalf("committed rejected digest = %+v, present=%v", rejected, ok)
	}
	if current := service.currentState(); len(current.SyncPeers[peerID].RejectedDigests) != 1 {
		t.Fatalf("current rejected digests = %+v, want installed committed peer", current.SyncPeers[peerID].RejectedDigests)
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
