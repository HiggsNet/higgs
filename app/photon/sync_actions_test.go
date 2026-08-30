package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

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

	committed, _ := snapshotTestDaemonState(service.StateStore)
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
	rt := &Runtime{StatePath: filepath.Join(t.TempDir(), "photon.db"), Clock: func() time.Time { return now }}
	service := newTestDaemonService(rt, state, config, defaultDaemonInterval)
	if _, err := service.StateStore.common.UpdatePeerCheckpoint(context.Background(), "node-b.catofes.", corestate.PeerCheckpointPatch{
		Reject: map[zone.ZonePath]corestate.RejectedObject{snapshot.Zone: {
			RootHash:    corestate.ZoneRoot(corestate.ZoneStateFromSnapshot(snapshot)),
			Reason:      "previous transient rejection",
			UpdatedUnix: now.Add(-time.Minute).Unix(),
			UntilUnix:   now.Add(time.Minute).Unix(),
		}},
	}); err != nil {
		t.Fatalf("UpdatePeerCheckpoint(rejected snapshot): %v", err)
	}
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
	committed, _ := snapshotTestDaemonState(service.StateStore)
	if afterRoot := corestate.ZoneRoot(committed.Network.Zones["node-b.catofes."]); !bytes.Equal(afterRoot, beforeRoot) {
		t.Fatalf("no-op snapshot changed zone root: before=%x after=%x", beforeRoot, afterRoot)
	}

	notifications := 0
	service.Hooks.OnStateChanged = func() { notifications++ }
	session.State = SyncSessionCompleted
	service.hostRuntime.Gossip.SetSession(session.PeerID, session)
	service.handleSyncEvent(context.Background(), &gossip.SyncTimerEvent{PeerID: session.PeerID})
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
	committed, _ := snapshotTestDaemonState(service.StateStore)
	if afterRoot := corestate.ZoneRoot(committed.Network.Zones[snapshot.Zone]); !bytes.Equal(afterRoot, beforeRoot) {
		t.Fatalf("root-mismatched snapshot changed zone: before=%x after=%x", beforeRoot, afterRoot)
	}
	rejected := service.StateStore.common.ReadView().Gossip.Peers[session.PeerID].RejectedObjects[snapshot.Zone]
	if !bytes.Equal(rejected.RootHash, []byte("different-advertised-root")) || rejected.UntilUnix <= now.Unix() {
		t.Fatal("root-mismatched snapshot did not record rejected digest")
	}
	select {
	case hostEvent := <-service.hostRuntime.Events():
		event, _ := service.hostRuntime.GossipSessionEventFor(hostEvent)
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
	expectedRoot := corestate.ZoneRoot(corestate.ZoneStateFromSnapshot(staleSnapshot))

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
	committed, _ := snapshotTestDaemonState(service.StateStore)
	if afterRoot := corestate.ZoneRoot(committed.Network.Zones[staleSnapshot.Zone]); !bytes.Equal(afterRoot, beforeRoot) {
		t.Fatalf("non-converging snapshot changed local root: before=%x after=%x", beforeRoot, afterRoot)
	}
	if committed.Network.Zones[staleSnapshot.Zone].Records[localRecord.Key] == nil {
		t.Fatal("stale snapshot removed newer local record")
	}
	if _, rejected := service.StateStore.common.ReadView().Gossip.Peers[session.PeerID].RejectedObjects[staleSnapshot.Zone]; rejected {
		t.Fatal("valid advertised snapshot was rejected because the merge retained newer local state")
	}
	select {
	case hostEvent := <-service.hostRuntime.Events():
		event, _ := service.hostRuntime.GossipSessionEventFor(hostEvent)
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
	service.Hooks.OnStateChanged = func() { notifications++ }
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
		if err := service.processPacketEvent(&gossip.Packet{Message: &gossip.Message{
			Type:        gossip.MessageObjectChunk,
			PeerID:      peerID,
			ObjectChunk: chunk,
		}}, context.Background()); err != nil {
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
			_, _ = service.handleHostRuntimeGossipEvent(context.Background(), hostEvent)
		default:
			break drainEvents
		}
	}

	if targetState.Network.Zones["catofes."] != nil {
		t.Fatal("daemon object chunk mutated the detached constructor input")
	}
	committed, rev := snapshotTestDaemonState(service.StateStore)
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
	observed, ok := service.hostRuntime.Observability.Snapshot(peerID, now)
	if !ok || observed.DatagramStats == nil || observed.DatagramStats.ChunkFallbacks != 1 {
		t.Fatalf("chunk fallback observability = %+v, want one apply", observed.DatagramStats)
	}
}
