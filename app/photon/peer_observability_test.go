package main

import (
	"encoding/json"
	"path/filepath"
	"reflect"
	"testing"
)

func TestLegacyPeerDiagnosticsAreIgnored(t *testing.T) {
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
	if !reflect.DeepEqual(peer, syncPeerState{}) {
		t.Fatalf("legacy diagnostics leaked into runtime state: %#v", peer)
	}
}

func TestSaveStateCannotPersistPeerDiagnostics(t *testing.T) {
	state, _ := buildTestNetworkState(t)
	normalizeSyncPeers(state)
	state.SyncPeers["peer-a.catofes."] = syncPeerState{LastSyncUnix: 42}
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
	data, err := json.Marshal(stateMetaFromState(state))
	if err != nil {
		t.Fatalf("Marshal state metadata: %v", err)
	}
	if string(data) == "" || json.Valid(data) == false {
		t.Fatalf("invalid state metadata: %q", data)
	}
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal state metadata: %v", err)
	}
	peers := decoded["sync_peers"].(map[string]any)
	encodedPeer := peers["peer-a.catofes."].(map[string]any)
	if _, ok := encodedPeer["datagram_stats"]; ok {
		t.Fatalf("datagram diagnostics were persisted: %#v", encodedPeer)
	}
	if _, ok := encodedPeer["object_pull_stats"]; ok {
		t.Fatalf("object-pull diagnostics were persisted: %#v", encodedPeer)
	}
}
