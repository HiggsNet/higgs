package main

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestMetadataCheckpointCoalescesPeerRuntimeWrites(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(5000, 0)
	rt := &Runtime{Config: defaultAppConfig(), StatePath: filepath.Join(t.TempDir(), "photon.db"), Clock: func() time.Time { return now }}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState(initial): %v", err)
	}
	service := newDaemonService(rt, state, config, time.Minute)

	for i, peerID := range []string{"peer-a", "peer-b"} {
		if _, err := service.StateStore.UpdateSyncPeer(peerID, func(peer *syncPeerState) error {
			peer.LastSyncUnix = int64(5001 + i)
			return nil
		}); err != nil {
			t.Fatalf("UpdateSyncPeer(%s): %v", peerID, err)
		}
		service.markMetadataCheckpointDirty()
	}
	if err := service.flushMetadataCheckpoint(false); err != nil {
		t.Fatalf("early flush: %v", err)
	}
	loaded, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState(before due): %v", err)
	}
	if loaded.SyncPeers["peer-a"].LastSyncUnix != 0 || loaded.SyncPeers["peer-b"].LastSyncUnix != 0 {
		t.Fatalf("peer runtime reached disk before checkpoint: %+v", loaded.SyncPeers)
	}

	now = now.Add(defaultMetadataCheckpointMaxDelay)
	if err := service.flushMetadataCheckpoint(false); err != nil {
		t.Fatalf("due flush: %v", err)
	}
	loaded, err = rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState(after due): %v", err)
	}
	if loaded.SyncPeers["peer-a"].LastSyncUnix != 5001 || loaded.SyncPeers["peer-b"].LastSyncUnix != 5002 {
		t.Fatalf("checkpoint did not persist both peers: %+v", loaded.SyncPeers)
	}
	if due := service.metadataCheckpointDue(); !due.IsZero() {
		t.Fatalf("checkpoint due after success = %s", due)
	}
}

func TestMetadataCheckpointRetriesAndShutdownForcesFlush(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(5100, 0)
	service := newDaemonService(&Runtime{Config: defaultAppConfig(), Clock: func() time.Time { return now }}, state, config, time.Minute)
	calls := 0
	service.metadataCheckpointSave = func() error {
		calls++
		if calls == 1 {
			return errors.New("disk busy")
		}
		return nil
	}
	if _, err := service.StateStore.UpdateSyncPeer("peer-a", func(peer *syncPeerState) error {
		peer.LastSyncUnix = 5101
		return nil
	}); err != nil {
		t.Fatalf("UpdateSyncPeer: %v", err)
	}
	service.markMetadataCheckpointDirty()
	now = now.Add(defaultMetadataCheckpointMaxDelay)
	if err := service.flushMetadataCheckpoint(false); err == nil {
		t.Fatal("first checkpoint unexpectedly succeeded")
	}
	if calls != 1 || service.metadataCheckpointDue().IsZero() {
		t.Fatalf("failed checkpoint calls/due = %d/%s", calls, service.metadataCheckpointDue())
	}

	service.flushMetadataCheckpointOnShutdown()
	if calls != 2 {
		t.Fatalf("shutdown flush calls = %d, want 2", calls)
	}
	if due := service.metadataCheckpointDue(); !due.IsZero() {
		t.Fatalf("checkpoint still dirty after shutdown success: %s", due)
	}
}

func TestMetadataCheckpointDeadlineDoesNotSlide(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(5150, 0)
	service := newDaemonService(&Runtime{Config: defaultAppConfig(), Clock: func() time.Time { return now }}, state, config, time.Minute)

	service.markMetadataCheckpointDirty()
	firstDue := service.metadataCheckpointDue()
	now = now.Add(30 * time.Second)
	if _, err := service.StateStore.UpdateSyncPeer("peer-a", func(peer *syncPeerState) error {
		peer.LastSyncUnix = now.Unix()
		return nil
	}); err != nil {
		t.Fatalf("UpdateSyncPeer: %v", err)
	}
	service.markMetadataCheckpointDirty()
	if got := service.metadataCheckpointDue(); !got.Equal(firstDue) {
		t.Fatalf("checkpoint due slid from %s to %s", firstDue, got)
	}
}

func TestMetadataCheckpointKeepsUpdateCreatedDuringSaveDirty(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(5170, 0)
	service := newDaemonService(&Runtime{Config: defaultAppConfig(), Clock: func() time.Time { return now }}, state, config, time.Minute)
	service.markMetadataCheckpointDirty()
	service.metadataCheckpointSave = func() error {
		if _, err := service.StateStore.UpdateSyncPeer("peer-a", func(peer *syncPeerState) error {
			peer.LastSyncUnix = 5171
			return nil
		}); err != nil {
			return err
		}
		service.markMetadataCheckpointDirty()
		return nil
	}

	now = now.Add(defaultMetadataCheckpointMaxDelay)
	if err := service.flushMetadataCheckpoint(false); err != nil {
		t.Fatalf("flushMetadataCheckpoint: %v", err)
	}
	if due := service.metadataCheckpointDue(); due.IsZero() {
		t.Fatal("update created during save was incorrectly marked persisted")
	}
}

func TestImmediateStateSaveAbsorbsPendingMetadataCheckpoint(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(5180, 0)
	rt := &Runtime{Config: defaultAppConfig(), StatePath: filepath.Join(t.TempDir(), "photon.db"), Clock: func() time.Time { return now }}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState(initial): %v", err)
	}
	service := newDaemonService(rt, state, config, time.Minute)
	if _, err := service.StateStore.UpdateSyncPeer("peer-a", func(peer *syncPeerState) error {
		peer.LastSyncUnix = 5181
		return nil
	}); err != nil {
		t.Fatalf("UpdateSyncPeer: %v", err)
	}
	service.markMetadataCheckpointDirty()

	if err := service.saveCommittedState(); err != nil {
		t.Fatalf("saveCommittedState: %v", err)
	}
	if due := service.metadataCheckpointDue(); !due.IsZero() {
		t.Fatalf("full save left a redundant checkpoint due at %s", due)
	}
	loaded, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if loaded.SyncPeers["peer-a"].LastSyncUnix != 5181 {
		t.Fatal("full save did not include pending peer metadata")
	}
}

func TestMetadataCheckpointRebasesPeerRuntimeAcrossExternalNetworkReload(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(5200, 0)
	rt := &Runtime{Config: defaultAppConfig(), StatePath: filepath.Join(t.TempDir(), "photon.db"), Clock: func() time.Time { return now }}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState(initial): %v", err)
	}
	service := newDaemonService(rt, state, config, time.Minute)
	if _, err := service.StateStore.UpdateSyncPeer("peer-a", func(peer *syncPeerState) error {
		peer.LastSyncUnix = 5201
		return nil
	}); err != nil {
		t.Fatalf("UpdateSyncPeer: %v", err)
	}
	service.markMetadataCheckpointDirty()

	external := cloneStateFile(state)
	external.Network.Zones["node-b.catofes."].Authority.Epoch++
	if err := rt.SaveState(external); err != nil {
		t.Fatalf("SaveState(external): %v", err)
	}
	if !service.rebasePendingPeerMetadata(external) {
		t.Fatal("dirty peer metadata was not rebased")
	}
	if external.SyncPeers["peer-a"].LastSyncUnix != 5201 {
		t.Fatalf("rebased LastSyncUnix = %d", external.SyncPeers["peer-a"].LastSyncUnix)
	}
	revision := service.StateStore.ReplaceCommitted(external)
	service.advanceMetadataCheckpointRevision(revision)
	service.flushMetadataCheckpointOnShutdown()

	loaded, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if loaded.Network.Zones["node-b.catofes."].Authority.Epoch != external.Network.Zones["node-b.catofes."].Authority.Epoch {
		t.Fatal("external Network change was lost")
	}
	if loaded.SyncPeers["peer-a"].LastSyncUnix != 5201 {
		t.Fatal("pending peer runtime was lost across external reload")
	}
}
