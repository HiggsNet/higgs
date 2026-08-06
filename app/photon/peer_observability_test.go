package main

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"
)

func TestPersistentSyncPeersDropsDiagnosticsWithoutMutatingInput(t *testing.T) {
	peers := map[string]syncPeerState{
		"peer-a.catofes.": {
			LastSyncUnix:    42,
			DatagramStats:   &datagramStats{ChunkFallbacks: 2},
			ObjectPullStats: &objectPullStats{Attempts: 3},
		},
	}

	persistent := persistentSyncPeers(peers)
	if persistent["peer-a.catofes."].DatagramStats != nil || persistent["peer-a.catofes."].ObjectPullStats != nil {
		t.Fatalf("persistent peer retained diagnostics: %#v", persistent["peer-a.catofes."])
	}
	if persistent["peer-a.catofes."].LastSyncUnix != 42 {
		t.Fatalf("persistent peer lost control state: %#v", persistent["peer-a.catofes."])
	}
	if peers["peer-a.catofes."].DatagramStats == nil || peers["peer-a.catofes."].ObjectPullStats == nil {
		t.Fatalf("persistent projection mutated input: %#v", peers["peer-a.catofes."])
	}
}

func TestLegacyPeerDiagnosticsRemainReadable(t *testing.T) {
	var meta stateMeta
	err := json.Unmarshal([]byte(`{
		"sync_peers": {
			"peer-a.catofes.": {
				"datagram_stats": {"chunk_fallbacks": 2},
				"object_pull_stats": {"attempts": 3}
			}
		}
	}`), &meta)
	if err != nil {
		t.Fatalf("Unmarshal legacy state: %v", err)
	}
	peer := meta.SyncPeers["peer-a.catofes."]
	if peer.DatagramStats == nil || peer.DatagramStats.ChunkFallbacks != 2 {
		t.Fatalf("legacy datagram stats = %#v", peer.DatagramStats)
	}
	if peer.ObjectPullStats == nil || peer.ObjectPullStats.Attempts != 3 {
		t.Fatalf("legacy object pull stats = %#v", peer.ObjectPullStats)
	}
}

func TestSaveStateDoesNotRewriteLegacyPeerDiagnostics(t *testing.T) {
	state, _ := buildTestNetworkState(t)
	normalizeSyncPeers(state)
	state.SyncPeers["peer-a.catofes."] = syncPeerState{
		LastSyncUnix:    42,
		DatagramStats:   &datagramStats{ChunkFallbacks: 2},
		ObjectPullStats: &objectPullStats{Attempts: 3},
	}
	rt := &Runtime{Config: defaultAppConfig(), StatePath: filepath.Join(t.TempDir(), "photon.db")}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	loaded, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	peer := loaded.SyncPeers["peer-a.catofes."]
	if peer.LastSyncUnix != 42 {
		t.Fatalf("control state was not persisted: %#v", peer)
	}
	if peer.DatagramStats != nil || peer.ObjectPullStats != nil {
		t.Fatalf("diagnostics were rewritten to state DB: %#v", peer)
	}
}

func TestDaemonObservabilityResetsLegacyDiagnosticsOnRestart(t *testing.T) {
	state, config := buildTestNetworkState(t)
	normalizeSyncPeers(state)
	state.SyncPeers["peer-a.catofes."] = syncPeerState{
		LastSyncUnix:    42,
		DatagramStats:   &datagramStats{ChunkFallbacks: 2},
		ObjectPullStats: &objectPullStats{Attempts: 3},
	}
	service := newDaemonService(&Runtime{Clock: func() time.Time { return time.Unix(100, 0) }}, state, config, time.Second)

	merged := service.mergePeerObservability(state.SyncPeers["peer-a.catofes."], service.peerObservabilitySnapshots()["peer-a.catofes."])
	if merged.LastSyncUnix != 42 {
		t.Fatalf("control state did not survive restart projection: %#v", merged)
	}
	if merged.DatagramStats != nil || merged.ObjectPullStats != nil {
		t.Fatalf("legacy diagnostics survived daemon restart: %#v", merged)
	}
}
