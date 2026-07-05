package main

import (
	"testing"
	"time"
)

func TestDaemonStateStoreSnapshotReturnsCommittedClone(t *testing.T) {
	store := NewDaemonStateStore(&stateFile{
		ManagedZone: "node-a.catofes.",
		Network:     cloneTestNetworkState(),
		SyncPeers:   cloneTestSyncPeers(),
	})

	snapshot, rev := store.Snapshot()
	if rev == 0 {
		t.Fatal("revision should be initialized")
	}
	snapshot.ManagedZone = "mutated.catofes."
	snapshot.Network.Zones["node-a.catofes."].Records["endpoint"].Value[0] = 'X'

	again, againRev := store.Snapshot()
	if againRev != rev {
		t.Fatalf("revision changed after snapshot mutation: got %d want %d", againRev, rev)
	}
	if again.ManagedZone != "node-a.catofes." {
		t.Fatalf("snapshot mutation leaked into store: %s", again.ManagedZone)
	}
	if string(again.Network.Zones["node-a.catofes."].Records["endpoint"].Value) != "endpoint-a" {
		t.Fatalf("nested snapshot mutation leaked into store: %q", string(again.Network.Zones["node-a.catofes."].Records["endpoint"].Value))
	}
}

func TestDaemonStateStoreUpdateAndCommitIfRevision(t *testing.T) {
	store := NewDaemonStateStore(&stateFile{ManagedZone: "node-a.catofes.", Network: cloneTestNetworkState()})
	_, baseRev := store.Snapshot()

	nextRev, err := store.Update(func(state *stateFile) error {
		state.ManagedZone = "node-b.catofes."
		return nil
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if nextRev <= baseRev {
		t.Fatalf("revision did not advance: base=%d next=%d", baseRev, nextRev)
	}

	currentRev, committed, err := store.CommitIfRevision(baseRev, func(state *stateFile) error {
		state.ManagedZone = "stale.catofes."
		return nil
	})
	if err != nil {
		t.Fatalf("CommitIfRevision stale: %v", err)
	}
	if committed {
		t.Fatal("stale CommitIfRevision committed")
	}
	if currentRev != nextRev {
		t.Fatalf("stale commit returned rev %d, want %d", currentRev, nextRev)
	}
	snapshot, _ := store.Snapshot()
	if snapshot.ManagedZone != "node-b.catofes." {
		t.Fatalf("stale commit changed state: %s", snapshot.ManagedZone)
	}
}

func TestDaemonStateStoreBeginUpdateWorkspaceDoesNotBlockSnapshots(t *testing.T) {
	store := NewDaemonStateStore(&stateFile{ManagedZone: "node-a.catofes.", Network: cloneTestNetworkState()})
	update, err := store.BeginUpdate()
	if err != nil {
		t.Fatalf("BeginUpdate: %v", err)
	}
	update.Workspace().ManagedZone = "workspace.catofes."

	done := make(chan struct{})
	go func() {
		snapshot, _ := store.Snapshot()
		if snapshot.ManagedZone != "node-a.catofes." {
			t.Errorf("snapshot saw uncommitted workspace: %s", snapshot.ManagedZone)
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Snapshot blocked behind an uncommitted workspace")
	}

	_, committed, err := update.Commit()
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if !committed {
		t.Fatal("workspace commit unexpectedly stale")
	}
	snapshot, _ := store.Snapshot()
	if snapshot.ManagedZone != "workspace.catofes." {
		t.Fatalf("workspace commit not visible: %s", snapshot.ManagedZone)
	}
}
