package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Catofes/higgs/pkg/core/gossip"
)

func TestSyncRuntimeReloadStateIfChangedSkipsUnchangedStateFile(t *testing.T) {
	state, _ := buildTestNetworkState(t)
	next := cloneStateFile(state)
	next.Network.Zones["node-b.catofes."].Authority.Epoch++

	path := filepath.Join(t.TempDir(), "higgs.db")
	if err := os.WriteFile(path, []byte("first"), 0o600); err != nil {
		t.Fatalf("write state marker: %v", err)
	}
	sr := &SyncRuntime{App: &Runtime{StatePath: path}, State: state}
	loads := 0
	load := func() (*stateFile, error) {
		loads++
		if loads == 1 {
			return state, nil
		}
		return next, nil
	}
	previous := gossip.ZoneDigests(state.Network)

	if latest, changed, err := sr.reloadStateIfChangedWith(previous, load); err != nil || changed || latest != state {
		t.Fatalf("first reload = (%p, %t, %v), want current state without change", latest, changed, err)
	}
	if latest, changed, err := sr.reloadStateIfChangedWith(previous, load); err != nil || changed || latest != state {
		t.Fatalf("unchanged reload = (%p, %t, %v), want cached current state", latest, changed, err)
	}
	if loads != 1 {
		t.Fatalf("loads after unchanged file = %d, want 1", loads)
	}

	// Rename gives the new database a distinct inode even if its contents have
	// the same size and timestamp resolution is coarse.
	replacement := path + ".new"
	if err := os.WriteFile(replacement, []byte("second"), 0o600); err != nil {
		t.Fatalf("write replacement marker: %v", err)
	}
	if err := os.Rename(replacement, path); err != nil {
		t.Fatalf("rename replacement marker: %v", err)
	}
	if latest, changed, err := sr.reloadStateIfChangedWith(previous, load); err != nil || !changed || latest != next {
		t.Fatalf("renamed reload = (%p, %t, %v), want changed next state", latest, changed, err)
	}
	if loads != 2 {
		t.Fatalf("loads after rename = %d, want 2", loads)
	}
}

func TestSyncRuntimeReloadStateIfChangedDoesNotCacheRacingFile(t *testing.T) {
	state, _ := buildTestNetworkState(t)
	path := filepath.Join(t.TempDir(), "higgs.db")
	if err := os.WriteFile(path, []byte("first"), 0o600); err != nil {
		t.Fatalf("write state marker: %v", err)
	}
	sr := &SyncRuntime{App: &Runtime{StatePath: path}, State: state}
	loads := 0
	load := func() (*stateFile, error) {
		loads++
		if loads == 1 {
			if err := os.WriteFile(path, []byte("changed during load"), 0o600); err != nil {
				t.Fatalf("change state marker: %v", err)
			}
		}
		return state, nil
	}
	previous := gossip.ZoneDigests(state.Network)

	if _, changed, err := sr.reloadStateIfChangedWith(previous, load); err != nil || changed {
		t.Fatalf("racing reload changed=%t err=%v", changed, err)
	}
	if _, changed, err := sr.reloadStateIfChangedWith(previous, load); err != nil || changed {
		t.Fatalf("follow-up reload changed=%t err=%v", changed, err)
	}
	if loads != 2 {
		t.Fatalf("loads after racing file = %d, want 2", loads)
	}
}
