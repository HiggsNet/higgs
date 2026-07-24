package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

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

func TestSyncRuntimeReloadStateIfChangedSkipsStableSelfWrite(t *testing.T) {
	state, _ := buildTestNetworkState(t)
	path := filepath.Join(t.TempDir(), "higgs.db")
	rt := &Runtime{Config: defaultAppConfig(), StatePath: path}
	sr := &SyncRuntime{App: rt, State: state}

	if err := sr.saveState(); err != nil {
		t.Fatalf("self save: %v", err)
	}
	if sr.reloadStateStamp.info == nil || sr.reloadStateStamp.path != path {
		t.Fatalf("self save marker = %+v, want stable marker for %s", sr.reloadStateStamp, path)
	}

	loads := 0
	load := func() (*stateFile, error) {
		loads++
		return rt.LoadState()
	}
	previous := gossip.ZoneDigests(state.Network)
	latest, changed, err := sr.reloadStateIfChangedWith(previous, load)
	if err != nil || changed || latest != state {
		t.Fatalf("reload after self write = (%p, %t, %v), want current state", latest, changed, err)
	}
	if loads != 0 {
		t.Fatalf("loads after stable self write = %d, want 0", loads)
	}

	external := cloneStateFile(state)
	external.Network.Zones["node-b.catofes."].Authority.Epoch++
	// Keep this test robust on filesystems with coarse timestamp updates.
	time.Sleep(time.Millisecond)
	if err := rt.SaveState(external); err != nil {
		t.Fatalf("external save: %v", err)
	}
	latest, changed, err = sr.reloadStateIfChangedWith(previous, load)
	if err != nil || !changed || latest == state {
		t.Fatalf("reload after external write = (%p, %t, %v), want loaded change", latest, changed, err)
	}
	if loads != 1 {
		t.Fatalf("loads after external write = %d, want 1", loads)
	}
}

func TestSyncRuntimeFailedSelfWriteClearsReloadMarker(t *testing.T) {
	state, _ := buildTestNetworkState(t)
	dir := t.TempDir()
	sr := &SyncRuntime{
		App:   &Runtime{Config: defaultAppConfig(), StatePath: dir},
		State: state,
		reloadStateStamp: stateFileStamp{
			path: "old",
			info: fakeFileInfo{name: "old"},
		},
	}
	if err := sr.saveState(); err == nil {
		t.Fatal("self save to directory unexpectedly succeeded")
	}
	if sr.reloadStateStamp.info != nil || sr.reloadStateStamp.path != "" {
		t.Fatalf("failed self save kept reload marker: %+v", sr.reloadStateStamp)
	}
}

type fakeFileInfo struct {
	name string
}

func (f fakeFileInfo) Name() string     { return f.name }
func (fakeFileInfo) Size() int64        { return 0 }
func (fakeFileInfo) Mode() os.FileMode  { return 0 }
func (fakeFileInfo) ModTime() time.Time { return time.Time{} }
func (fakeFileInfo) IsDir() bool        { return false }
func (fakeFileInfo) Sys() any           { return nil }
