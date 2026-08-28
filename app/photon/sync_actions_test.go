package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
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
	service := newTestDaemonService(rt, state, config, defaultDaemonInterval)
	peerID := "node-b.catofes."
	service.hostRuntime.Gossip.SetSession(peerID, gossip.NewSyncSession(peerID))

	if changed := service.handleSyncEvent(context.Background(), &gossip.CatalogSummaryReceivedEvent{
		PeerID: peerID,
		Summary: &corestate.CatalogSummary{
			CatalogRoot: []byte{0x21, 0x22},
			ZoneCount:   2,
			NextCursor:  "next-page",
		},
	}); changed {
		t.Fatal("metadata-only catalog event reported a Network change")
	}

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
	if observed.ActivePullState != string(gossip.SyncSessionCatalogDiffing) || observed.ActivePullLastEvent != "catalog_summary" {
		t.Fatalf("active pull = state %q event %q, want observable catalog diffing summary", observed.ActivePullState, observed.ActivePullLastEvent)
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
	service := newTestDaemonService(rt, state, config, defaultDaemonInterval)
	peerID := "node-b.catofes."
	service.hostRuntime.Gossip.SetSession(peerID, gossip.NewSyncSession(peerID))

	state.Lock()
	unlock := state.Unlock
	done := make(chan struct{})
	go func() {
		service.handleSyncEvent(context.Background(), &gossip.CatalogSummaryReceivedEvent{
			PeerID: peerID,
			Summary: &corestate.CatalogSummary{
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

	observed, ok := service.PeerObservability.Snapshot(peerID, now)
	if !ok || observed.DatagramStats == nil || observed.DatagramStats.LastCatalogRootHex != "3132" {
		t.Fatalf("catalog stats = %+v, want observability summary", observed.DatagramStats)
	}
	if observed.ActivePullState != string(gossip.SyncSessionCatalogDiffing) {
		t.Fatalf("active pull state = %q, want catalog diffing", observed.ActivePullState)
	}
}

func TestRecordSyncPeerStateUsesSoleCommittedAuthority(t *testing.T) {
	state, config := buildTestNetworkState(t)
	service := newTestDaemonService(&Runtime{}, state, config, defaultDaemonInterval)
	peerID := "node-b.catofes."
	beforeRevision := service.StateStore.Meta().Revision

	service.recordSyncPeerState(peerID, "test_local_cow", func(peer *corestate.PeerCheckpoint) {
		peer.LastSyncUnix = 42
	})

	// The constructor input is detached from the store and must remain
	// unchanged; there is no second runtime state to install or synchronize.
	if state.SyncPeers[peerID].LastSyncUnix != 0 {
		t.Fatalf("constructor input peer changed to %+v", state.SyncPeers[peerID])
	}
	committed, revision := service.StateStore.Snapshot()
	if revision != beforeRevision {
		t.Fatalf("verified revision = %d, want unchanged %d", revision, beforeRevision)
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
	service := newTestDaemonService(rt, state, config, defaultDaemonInterval)
	peerID := "node-b.catofes."

	state.Lock()
	unlock := state.Unlock
	done := make(chan error, 1)
	go func() {
		message := &gossip.Message{
			Type:             gossip.MessageFetchCatalogPage,
			PeerID:           peerID,
			FetchCatalogPage: &gossip.FetchCatalogPage{},
		}
		controller := &daemonGossipActionController{
			daemon: service,
			now:    now,
			limits: syncLimits(config),
		}
		done <- service.hostRuntime.ExecuteGossipInbound(
			context.Background(),
			service.hostRuntime.Gossip.PlanInbound(&gossip.Packet{Message: message}),
			controller,
		)
	}()

	select {
	case err := <-done:
		if err != nil {
			unlock()
			t.Fatalf("ExecuteGossipInbound: %v", err)
		}
	case <-time.After(time.Second):
		unlock()
		t.Fatal("read-only responder blocked behind detached constructor-input lock")
	}
	unlock()

	state.Lock()
	unlock = state.Unlock
	go func() {
		done <- service.respondFetchZoneTo(peerID, "node-b.catofes.", nil)
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

	observed, ok := service.PeerObservability.Snapshot(peerID, now)
	if !ok || observed.ReadOnlyResponder != 1 || observed.DatagramStats == nil || (observed.DatagramStats.LastCatalogCursor == "" && observed.DatagramStats.LastCatalogPageEntries == 0) {
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
	service := newTestDaemonService(rt, state, config, defaultDaemonInterval)
	service.Sync.Transport = transport

	state.Lock()
	unlock := state.Unlock
	done := make(chan error, 1)
	go func() {
		done <- service.respondFetchZoneChunksTo(peerID, "node-b.catofes.", nil)
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
	service := newTestDaemonService(rt, state, config, defaultDaemonInterval)
	session := gossip.NewSyncSession("node-b.catofes.")
	state.Lock()
	unlock := state.Unlock
	changed := service.executeSyncActions(context.Background(), session, []gossip.SyncAction{
		gossip.ApplySnapshotAction{PeerID: "node-b.catofes.", Snapshot: snapshot, ExpectedRoot: corestate.ZoneRoot(source.Network.Zones["node-b.catofes."])},
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

func TestExecuteSyncActionsNoopSnapshotCommitsMetadataOnly(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(2205, 0)
	snapshot, err := corestate.Snapshot(state.Network, "node-b.catofes.")
	if err != nil {
		t.Fatalf("Snapshot(node-b): %v", err)
	}
	recordRejectedDigest(state, "node-b.catofes.", digestForSnapshot(snapshot), "previous transient rejection", now.Add(-time.Minute))

	rt := &Runtime{StatePath: filepath.Join(t.TempDir(), "photon.db"), Clock: func() time.Time { return now }}
	service := newTestDaemonService(rt, state, config, defaultDaemonInterval)
	session := NewSyncSession("node-b.catofes.")
	beforeRevision := service.StateStore.Meta().Revision
	beforeRoot := append([]byte(nil), corestate.ZoneRoot(state.Network.Zones["node-b.catofes."])...)

	changed := service.executeSyncActions(context.Background(), session, []SyncAction{
		ApplySnapshotAction{PeerID: session.PeerID, Snapshot: snapshot},
	})
	if changed {
		t.Fatal("executeSyncActions changed = true for identical snapshot")
	}
	if revision := service.StateStore.Meta().Revision; revision != beforeRevision {
		t.Fatalf("verified revision = %d, want unchanged %d", revision, beforeRevision)
	}
	committed, _ := service.StateStore.Snapshot()
	if afterRoot := corestate.ZoneRoot(committed.Network.Zones["node-b.catofes."]); !bytes.Equal(afterRoot, beforeRoot) {
		t.Fatalf("no-op snapshot changed zone root: before=%x after=%x", beforeRoot, afterRoot)
	}

	notifications := 0
	service.Hooks.OnStateChanged = func(*stateFile) { notifications++ }
	session.State = SyncSessionCompleted
	service.hostRuntime.Gossip.SetSession(session.PeerID, session)
	service.completeSyncSessionAfterPeerState(session, changed)
	if notifications != 0 {
		t.Fatalf("no-op snapshot emitted %d state-change notifications", notifications)
	}
}

func TestExecuteSyncActionsPureNoopDoesNotCommit(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(2206, 0)
	snapshot, err := corestate.Snapshot(state.Network, "node-b.catofes.")
	if err != nil {
		t.Fatalf("Snapshot(node-b): %v", err)
	}

	service := newTestDaemonService(&Runtime{Clock: func() time.Time { return now }}, state, config, defaultDaemonInterval)
	session := NewSyncSession("node-b.catofes.")
	beforeRevision := service.StateStore.Meta().Revision
	if changed := service.executeSyncActions(context.Background(), session, []SyncAction{
		ApplySnapshotAction{PeerID: session.PeerID, Snapshot: snapshot},
	}); changed {
		t.Fatal("pure no-op snapshot reported NetworkChanged")
	}
	if revision := service.StateStore.Meta().Revision; revision != beforeRevision {
		t.Fatalf("pure no-op revision = %d, want unchanged %d", revision, beforeRevision)
	}
}

func TestExecuteSyncActionsRejectsSnapshotOutsideAdvertisedRoot(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(2207, 0)
	snapshot, err := corestate.Snapshot(state.Network, "node-b.catofes.")
	if err != nil {
		t.Fatalf("Snapshot(node-b): %v", err)
	}

	service := newTestDaemonService(&Runtime{Clock: func() time.Time { return now }}, state, config, defaultDaemonInterval)
	session := NewSyncSession("node-b.catofes.")
	beforeRoot := append([]byte(nil), corestate.ZoneRoot(state.Network.Zones[snapshot.Zone])...)
	changed := service.executeSyncActions(context.Background(), session, []SyncAction{ApplySnapshotAction{
		PeerID:       session.PeerID,
		Snapshot:     snapshot,
		ExpectedRoot: []byte("different-advertised-root"),
		ReportResult: true,
	}})
	if changed {
		t.Fatal("root-mismatched snapshot changed Network")
	}
	committed, _ := service.StateStore.Snapshot()
	if afterRoot := corestate.ZoneRoot(committed.Network.Zones[snapshot.Zone]); !bytes.Equal(afterRoot, beforeRoot) {
		t.Fatalf("root-mismatched snapshot changed zone: before=%x after=%x", beforeRoot, afterRoot)
	}
	if !isRejectedDigestActive(committed, session.PeerID, snapshot.Zone, []byte("different-advertised-root"), now.Add(time.Minute)) {
		t.Fatal("root-mismatched snapshot did not record rejected digest")
	}
	select {
	case hostEvent := <-service.hostRuntime.Events():
		event, _ := service.hostRuntime.GossipEventFor(hostEvent)
		applied, ok := event.(*SnapshotAppliedEvent)
		if !ok || applied.Err == nil {
			t.Fatalf("apply completion = %#v, want SnapshotAppliedEvent error", event)
		}
	default:
		t.Fatal("root-mismatched snapshot did not report apply completion")
	}
}

func TestExecuteSyncActionsAcceptsAdvertisedSnapshotWhenMergeKeepsNewerLocalState(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(2208, 0)
	staleSnapshot, err := corestate.Snapshot(state.Network, "node-b.catofes.")
	if err != nil {
		t.Fatalf("Snapshot(stale node-b): %v", err)
	}
	localRecord, err := buildSignedRecordAt(state, "node-b.catofes.", "local-newer", []byte("keep"), "policy.string", now)
	if err != nil {
		t.Fatalf("buildSignedRecordAt(local-newer): %v", err)
	}
	if err := state.Network.PutAt(localRecord, now); err != nil {
		t.Fatalf("PutAt(local-newer): %v", err)
	}
	beforeRoot := append([]byte(nil), corestate.ZoneRoot(state.Network.Zones[staleSnapshot.Zone])...)
	expectedRoot := digestForSnapshot(staleSnapshot).RootHash

	service := newTestDaemonService(&Runtime{Clock: func() time.Time { return now }}, state, config, defaultDaemonInterval)
	session := NewSyncSession("node-b.catofes.")
	changed := service.executeSyncActions(context.Background(), session, []SyncAction{ApplySnapshotAction{
		PeerID:       session.PeerID,
		Snapshot:     staleSnapshot,
		ExpectedRoot: expectedRoot,
		ReportResult: true,
	}})
	if changed {
		t.Fatal("stale snapshot changed Network")
	}
	committed, _ := service.StateStore.Snapshot()
	if afterRoot := corestate.ZoneRoot(committed.Network.Zones[staleSnapshot.Zone]); !bytes.Equal(afterRoot, beforeRoot) {
		t.Fatalf("non-converging snapshot changed local root: before=%x after=%x", beforeRoot, afterRoot)
	}
	if committed.Network.Zones[staleSnapshot.Zone].Records[localRecord.Key] == nil {
		t.Fatal("stale snapshot removed newer local record")
	}
	if isRejectedDigestActive(committed, session.PeerID, staleSnapshot.Zone, expectedRoot, now.Add(time.Minute)) {
		t.Fatal("valid advertised snapshot was rejected because the merge retained newer local state")
	}
	select {
	case hostEvent := <-service.hostRuntime.Events():
		event, _ := service.hostRuntime.GossipEventFor(hostEvent)
		applied, ok := event.(*SnapshotAppliedEvent)
		if !ok || applied.Err != nil {
			t.Fatalf("apply completion = %#v, want successful merge acknowledgement", event)
		}
	default:
		t.Fatal("stale snapshot did not report apply completion")
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
	childSource := cloneStateFile(state)
	childRecord, err := buildSignedRecordAt(childSource, "node-b.catofes.", "batch-record", []byte("remote"), "policy.string", now)
	if err != nil {
		t.Fatalf("buildSignedRecordAt(node-b): %v", err)
	}
	childSource.Network.Zones["node-b.catofes."].Records[childRecord.Key] = childRecord
	validChild, err := corestate.Snapshot(childSource.Network, "node-b.catofes.")
	if err != nil {
		t.Fatalf("Snapshot(node-b): %v", err)
	}

	rt := &Runtime{StatePath: filepath.Join(t.TempDir(), "photon.db"), Clock: func() time.Time { return now }}
	service := newTestDaemonService(rt, state, config, defaultDaemonInterval)
	session := gossip.NewSyncSession("node-b.catofes.")
	beforeRevision := service.StateStore.Meta().Revision
	beforeRootEpoch := state.Network.Zones[zone.RootZone].Authority.Epoch

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
		if root := committed.Network.Zones[zone.RootZone]; root == nil || root.Authority.Epoch != beforeRootEpoch {
			t.Fatal("batch commit changed the unmodified root zone")
		}
		if committed.Network.Zones["catofes."] == nil {
			t.Fatal("successful parent savepoint was not applied")
		}
		if child := committed.Network.Zones["node-b.catofes."]; child == nil || child.Records["batch-record"] == nil {
			t.Fatal("later successful child savepoint did not run")
		}
		rejected, ok := committed.SyncPeers[session.PeerID].RejectedDigests["catofes."]
		if !ok || rejected.Reason == "" {
			t.Fatalf("invalid middle savepoint rejection = %+v, present=%t", rejected, ok)
		}
	})

}

func TestDaemonHandleObjectChunkCommitsThroughStateStore(t *testing.T) {
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
	rootHash := corestate.ZoneRoot(sourceState.Network.Zones["catofes."])

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
	service := newTestDaemonService(rt, targetState, config, defaultDaemonInterval)
	peerID := "node-b.catofes."
	session := NewSyncSession(peerID)
	_, _ = session.OnEvent(&SyncTimerEvent{PeerID: peerID}, now)
	_, _ = session.OnEvent(&PongReceivedEvent{PeerID: peerID, Pong: &gossip.Pong{}, MissingZones: []zone.ZonePath{"catofes."}}, now)
	_, _ = session.OnEvent(&ObjectPullResultEvent{PeerID: peerID, Zone: "catofes.", Err: errors.New("tcp unavailable")}, now)
	service.hostRuntime.Gossip.SetSession(peerID, session)
	notifications := 0
	service.Hooks.OnStateChanged = func(*stateFile) { notifications++ }
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
		if err := service.handleObjectChunkFrom(&gossip.Message{
			Type:        gossip.MessageObjectChunk,
			PeerID:      peerID,
			ObjectChunk: chunk,
		}, nil, corestate.DefaultSyncLimits()); err != nil {
			t.Fatalf("handleObjectChunk: %v", err)
		}
	}
drainEvents:
	for range 4 {
		if service.hostRuntime.Gossip.Session(peerID) == nil && service.hostRuntime.PendingEventCount() == 0 {
			break
		}
		select {
		case hostEvent := <-service.hostRuntime.Events():
			if event, ok := service.hostRuntime.GossipEventFor(hostEvent); ok {
				service.handleSyncEvent(context.Background(), event)
			}
		default:
			break drainEvents
		}
	}

	if targetState.Network.Zones["catofes."] != nil {
		t.Fatal("daemon object chunk mutated the detached constructor input")
	}
	committed, rev := service.StateStore.Snapshot()
	if rev <= beforeRev {
		t.Fatalf("state revision = %d, want object apply after %d", rev, beforeRev)
	}
	if committed.Network.Zones["catofes."] == nil {
		t.Fatal("committed state missing chunk-applied zone")
	}
	if current := service.currentState(); current == targetState || current.Network.Zones["catofes."] == nil {
		t.Fatal("current state was not installed from committed snapshot")
	}
	if active := service.hostRuntime.Gossip.Session(peerID); active != nil {
		t.Fatalf("chunk sync session remained active after apply acknowledgement: state=%s pending=%d inflight=%d", active.State, active.PendingCount(), active.InflightCount())
	}
	if notifications != 1 {
		t.Fatalf("chunk apply notifications = %d, want one after acknowledged completion", notifications)
	}
	observed, ok := service.PeerObservability.Snapshot(peerID, now)
	if !ok || observed.DatagramStats == nil || observed.DatagramStats.ChunkFallbacks != 1 {
		t.Fatalf("chunk fallback observability = %+v, want one apply", observed.DatagramStats)
	}
}

func TestDaemonHandleObjectChunkRejectUsesPeerCOW(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(2240, 0)
	rt := &Runtime{
		StatePath: filepath.Join(t.TempDir(), "photon.db"),
		Clock:     func() time.Time { return now },
	}
	service := newTestDaemonService(rt, state, config, defaultDaemonInterval)
	peerID := "node-b.catofes."
	beforeRev := service.StateStore.Meta().Revision
	rootHash := corestate.ZoneRoot(state.Network.Zones["catofes."])
	if len(rootHash) == 0 {
		rootHash = []byte("catofes-root")
	}
	if !zone.ZonePath("catofes.").Valid() {
		t.Fatal("catofes fixture zone is invalid")
	}

	message := &gossip.Message{
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
	}
	err := service.handleObjectChunkFrom(message, nil, corestate.DefaultSyncLimits())
	if err == nil {
		t.Fatal("handleObjectChunk accepted invalid object hash")
	}
	if len(message.ObjectChunk.RootHash) == 0 {
		t.Fatalf("chunk root hash was lost: %v", err)
	}

	if len(state.SyncPeers[peerID].RejectedDigests) != 0 {
		t.Fatal("chunk rejection mutated the old live peer state")
	}
	committed, rev := service.StateStore.Snapshot()
	if rev != beforeRev {
		t.Fatalf("verified revision = %d, want rejected checkpoint to keep %d", rev, beforeRev)
	}
	rejected, ok := committed.SyncPeers[peerID].RejectedDigests["catofes."]
	if !ok || rejected.Reason == "" || rejected.RootHashHex == "" {
		t.Fatalf("committed rejected digest = %+v, present=%v, all=%+v, common=%+v", rejected, ok, committed.SyncPeers[peerID].RejectedDigests, service.StateStore.common.ReadView().Gossip.Peers)
	}
	if current := service.currentState(); len(current.SyncPeers[peerID].RejectedDigests) != 1 {
		t.Fatalf("current rejected digests = %+v, want installed committed peer", current.SyncPeers[peerID].RejectedDigests)
	}
}
