package main

import (
	"context"
	"crypto/sha256"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

func TestHandleSyncEventStoresPeerDiagnosticsOutsideCommittedState(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(2100, 0)
	rt := &Runtime{
		StatePath: filepath.Join(t.TempDir(), "photon.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	service := newDaemonService(rt, state, config, defaultDaemonInterval)
	peerID := "node-b.catofes."
	service.hostRuntime.Gossip.SetSession(peerID, gossip.NewSyncSession(peerID))

	if changed := service.handleSyncEvent(context.Background(), &gossip.CatalogSummaryReceivedEvent{
		PeerID: peerID,
		Summary: &gossip.CatalogSummary{
			CatalogRoot: []byte{0x21, 0x22},
			ZoneCount:   2,
			NextCursor:  "next-page",
		},
	}); changed {
		t.Fatal("metadata-only catalog event reported a Network change")
	}

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
	if peerState.ActivePullState != string(gossip.SyncSessionCatalogDiffing) || peerState.ActivePullLastEvent != "catalog_summary" {
		t.Fatalf("active pull = state %q event %q, want committed catalog diffing summary", peerState.ActivePullState, peerState.ActivePullLastEvent)
	}
	if peerState.DatagramStats != nil {
		t.Fatalf("datagram stats leaked into committed state: %+v", peerState.DatagramStats)
	}
}

func TestHandleSyncEventDoesNotWaitForConstructorInputLock(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(2120, 0)
	rt := &Runtime{
		StatePath: filepath.Join(t.TempDir(), "photon.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	service := newDaemonService(rt, state, config, defaultDaemonInterval)
	peerID := "node-b.catofes."
	service.hostRuntime.Gossip.SetSession(peerID, gossip.NewSyncSession(peerID))

	state.Lock()
	unlock := state.Unlock
	done := make(chan struct{})
	go func() {
		service.handleSyncEvent(context.Background(), &gossip.CatalogSummaryReceivedEvent{
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
		t.Fatal("handleSyncEvent blocked behind detached constructor-input lock")
	}
	unlock()

	snapshot, _ := service.StateStore.Snapshot()
	peerState := snapshot.SyncPeers[peerID]
	observed, ok := service.PeerObservability.Snapshot(peerID, now)
	if !ok || observed.DatagramStats == nil || observed.DatagramStats.LastCatalogRootHex != "3132" {
		t.Fatalf("catalog stats = %+v, want observability summary", observed.DatagramStats)
	}
	if peerState.ActivePullState != string(gossip.SyncSessionCatalogDiffing) {
		t.Fatalf("active pull state = %q, want catalog diffing", peerState.ActivePullState)
	}
}

func TestRecordSyncPeerStateUsesSoleCommittedAuthority(t *testing.T) {
	state, config := buildTestNetworkState(t)
	service := newDaemonService(&Runtime{}, state, config, defaultDaemonInterval)
	peerID := "node-b.catofes."
	beforeRevision := service.StateStore.Meta().Revision

	service.recordSyncPeerState(peerID, "test_local_cow", func(next *stateFile) {
		peer := next.SyncPeers[peerID]
		peer.LastSyncUnix = 42
		next.SyncPeers[peerID] = peer
	})

	// The constructor input is detached from the store and must remain
	// unchanged; there is no second runtime state to install or synchronize.
	if state.SyncPeers[peerID].LastSyncUnix != 0 {
		t.Fatalf("constructor input peer changed to %+v", state.SyncPeers[peerID])
	}
	committed, revision := service.StateStore.Snapshot()
	if revision != beforeRevision+1 {
		t.Fatalf("revision = %d, want %d", revision, beforeRevision+1)
	}
	if committed.SyncPeers[peerID].LastSyncUnix != 42 {
		t.Fatalf("committed peer = %+v, want LastSyncUnix 42", committed.SyncPeers[peerID])
	}
}

func TestReadOnlyResponderUsesCommittedSnapshotWhileConstructorInputLocked(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(2130, 0)
	rt := &Runtime{
		StatePath: filepath.Join(t.TempDir(), "photon.db"),
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
		t.Fatal("read-only responder blocked behind detached constructor-input lock")
	}
	unlock()

	state.Lock()
	unlock = state.Unlock
	go func() {
		done <- service.respondFetchZone(peerID, "node-b.catofes.")
	}()
	select {
	case err := <-done:
		if err != nil {
			unlock()
			t.Fatalf("respondFetchZone: %v", err)
		}
	case <-time.After(time.Second):
		unlock()
		t.Fatal("fetch-zone responder blocked behind detached constructor-input lock")
	}
	unlock()

	snapshot, _ := service.StateStore.Snapshot()
	peerState := snapshot.SyncPeers[peerID]
	if peerState.ReadOnlyResponder != 0 {
		t.Fatalf("read-only responder count = %d, want no StateStore write", peerState.ReadOnlyResponder)
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
		StatePath: filepath.Join(t.TempDir(), "photon.db"),
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
		t.Fatal("chunk responder blocked behind detached constructor-input lock")
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
	snapshot, err := corestate.Snapshot(source.Network, "node-b.catofes.")
	if err != nil {
		t.Fatalf("Snapshot(node-b): %v", err)
	}

	rt := &Runtime{StatePath: filepath.Join(t.TempDir(), "photon.db"), Clock: func() time.Time { return now }}
	service := newDaemonService(rt, state, config, defaultDaemonInterval)
	session := gossip.NewSyncSession("node-b.catofes.")
	state.Lock()
	unlock := state.Unlock
	changed := service.executeSyncActions(context.Background(), session, []gossip.SyncAction{
		gossip.ApplySnapshotAction{PeerID: "node-b.catofes.", Snapshot: snapshot},
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

func TestExecuteSyncActionsBatchesSnapshotSavepointsIntoOneRevision(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(2210, 0)
	validParent, err := corestate.Snapshot(state.Network, "catofes.")
	if err != nil {
		t.Fatalf("Snapshot(catofes): %v", err)
	}
	invalidParent, err := corestate.Snapshot(state.Network, "catofes.")
	if err != nil {
		t.Fatalf("Snapshot(invalid catofes): %v", err)
	}
	invalidParent.Authority.Keys[0].Key[0] ^= 0xff
	validChild, err := corestate.Snapshot(state.Network, "node-b.catofes.")
	if err != nil {
		t.Fatalf("Snapshot(node-b): %v", err)
	}

	rt := &Runtime{StatePath: filepath.Join(t.TempDir(), "photon.db"), Clock: func() time.Time { return now }}
	service := newDaemonService(rt, state, config, defaultDaemonInterval)
	session := gossip.NewSyncSession("node-b.catofes.")
	beforeRevision := service.StateStore.Meta().Revision
	var beforeRoot, beforeParent, beforeChild *zone.ZoneState
	readCommittedForTest(service.StateStore, func(committed *stateFile) {
		beforeRoot = committed.Network.Zones[zone.RootZone]
		beforeParent = committed.Network.Zones["catofes."]
		beforeChild = committed.Network.Zones["node-b.catofes."]
	})

	changed := service.executeSyncActions(context.Background(), session, []gossip.SyncAction{
		gossip.ApplySnapshotAction{PeerID: session.PeerID, Snapshot: validParent},
		gossip.ApplySnapshotAction{PeerID: session.PeerID, Snapshot: invalidParent},
		gossip.ApplySnapshotAction{PeerID: session.PeerID, Snapshot: validChild},
	})
	if !changed {
		t.Fatal("executeSyncActions changed = false, want partial success")
	}

	if revision := service.StateStore.Meta().Revision; revision != beforeRevision+1 {
		t.Fatalf("revision = %d, want one batch publication after %d", revision, beforeRevision)
	}
	readCommittedForTest(service.StateStore, func(committed *stateFile) {
		if committed.Network.Zones[zone.RootZone] != beforeRoot {
			t.Fatal("unmodified root zone was not shared by batch commit")
		}
		if committed.Network.Zones["catofes."] == beforeParent {
			t.Fatal("successful parent savepoint was not detached")
		}
		if committed.Network.Zones["node-b.catofes."] == beforeChild {
			t.Fatal("later successful child savepoint did not run")
		}
		rejected, ok := committed.SyncPeers[session.PeerID].RejectedDigests[rejectedDigestKey("catofes.")]
		if !ok || rejected.Reason == "" {
			t.Fatalf("invalid middle savepoint rejection = %+v, present=%t", rejected, ok)
		}
	})

	reloaded, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if reloaded.Network.Zones["catofes."] == nil || reloaded.Network.Zones["node-b.catofes."] == nil {
		t.Fatal("persisted batch is missing a successful snapshot")
	}
}

func TestDaemonHandleObjectChunkCommitsThroughStateStore(t *testing.T) {
	udpChunkAssemblies = gossip.NewChunkAssemblyStore()
	sourceState, _ := buildTestNetworkState(t)
	snapshot, err := corestate.Snapshot(sourceState.Network, "catofes.")
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
		StatePath: filepath.Join(t.TempDir(), "photon.db"),
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
		}, corestate.DefaultSyncLimits()); err != nil {
			t.Fatalf("handleObjectChunk: %v", err)
		}
	}

	if targetState.Network.Zones["catofes."] != nil {
		t.Fatal("daemon object chunk mutated the detached constructor input")
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
	udpChunkAssemblies = gossip.NewChunkAssemblyStore()
	state, config := buildTestNetworkState(t)
	now := time.Unix(2240, 0)
	rt := &Runtime{
		StatePath: filepath.Join(t.TempDir(), "photon.db"),
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
	}, corestate.DefaultSyncLimits())
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
