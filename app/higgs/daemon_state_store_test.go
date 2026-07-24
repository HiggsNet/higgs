package main

import (
	"errors"
	"testing"
	"time"

	"github.com/Catofes/higgs/pkg/core/gossip"
	"github.com/Catofes/higgs/pkg/core/zone"
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

func TestDaemonStateStoreZoneDigestsReturnsDetachedProjection(t *testing.T) {
	state := &stateFile{ManagedZone: "node-a.catofes.", Network: cloneTestNetworkState()}
	store := NewDaemonStateStore(state)
	want := gossip.ZoneDigests(state.Network)

	got := store.ZoneDigests()
	if !sameZoneDigests(got, want) {
		t.Fatalf("ZoneDigests = %#v, want %#v", got, want)
	}
	got[0].RootHash[0] ^= 0xff
	if again := store.ZoneDigests(); !sameZoneDigests(again, want) {
		t.Fatalf("digest mutation leaked into committed state: got %#v, want %#v", again, want)
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

func TestDaemonStateStoreUpdateSyncPeerSharesNetworkAndIsolatesPeer(t *testing.T) {
	initial := &stateFile{
		ManagedZone: "node-a.catofes.",
		Network:     cloneTestNetworkState(),
		SyncPeers: map[string]syncPeerState{
			"peer-a": {
				ObservedGraceAddrs: []observedGraceAddrState{{Addr: "198.51.100.1:33434"}},
				RejectedDigests: map[string]rejectedDigestState{
					"old": {Reason: "old"},
				},
			},
			"peer-b": {
				ObservedGraceAddrs: []observedGraceAddrState{{Addr: "198.51.100.2:33434"}},
			},
		},
	}
	store := NewDaemonStateStore(initial)
	var beforeNetwork *zone.NetworkState
	var beforePeerBGrace *observedGraceAddrState
	store.ReadCommitted(func(state *stateFile) {
		beforeNetwork = state.Network
		peerB := state.SyncPeers["peer-b"]
		beforePeerBGrace = &peerB.ObservedGraceAddrs[0]
	})

	var retained *syncPeerState
	beforeRev := store.Meta().Revision
	afterRev, err := store.UpdateSyncPeer("peer-a", func(peer *syncPeerState) error {
		retained = peer
		peer.LastSyncUnix = 123
		peer.ObservedGraceAddrs[0].Addr = "203.0.113.1:33434"
		peer.RejectedDigests["old"] = rejectedDigestState{Reason: "changed"}
		return nil
	})
	if err != nil {
		t.Fatalf("UpdateSyncPeer: %v", err)
	}
	if afterRev != beforeRev+1 {
		t.Fatalf("revision = %d, want %d", afterRev, beforeRev+1)
	}

	store.ReadCommitted(func(state *stateFile) {
		if state.Network != beforeNetwork {
			t.Fatal("UpdateSyncPeer copied Network instead of sharing it")
		}
		peerB := state.SyncPeers["peer-b"]
		if &peerB.ObservedGraceAddrs[0] != beforePeerBGrace {
			t.Fatal("UpdateSyncPeer copied an unrelated peer's nested state")
		}
	})

	retained.LastSyncUnix = 999
	retained.ObservedGraceAddrs[0].Addr = "retained-mutation"
	retained.RejectedDigests["old"] = rejectedDigestState{Reason: "retained-mutation"}
	snapshot, _ := store.Snapshot()
	peer := snapshot.SyncPeers["peer-a"]
	if peer.LastSyncUnix != 123 ||
		peer.ObservedGraceAddrs[0].Addr != "203.0.113.1:33434" ||
		peer.RejectedDigests["old"].Reason != "changed" {
		t.Fatalf("retained callback state mutated committed peer: %+v", peer)
	}
}

func TestDaemonStateStoreUpdateSyncPeerRetriesAreBounded(t *testing.T) {
	store := NewDaemonStateStore(&stateFile{
		Network:   cloneTestNetworkState(),
		SyncPeers: map[string]syncPeerState{"peer-a": {}},
	})
	attempts := 0
	_, err := store.UpdateSyncPeer("peer-a", func(peer *syncPeerState) error {
		attempts++
		_, updateErr := store.Update(func(state *stateFile) error {
			state.IdentityKeyPath = "advance-revision"
			return nil
		})
		return updateErr
	})
	if !errors.Is(err, errDaemonStateRevisionStale) {
		t.Fatalf("UpdateSyncPeer error = %v, want stale revision", err)
	}
	if attempts != maxSyncPeerUpdateAttempts {
		t.Fatalf("attempts = %d, want bounded %d", attempts, maxSyncPeerUpdateAttempts)
	}
}

func TestDaemonStateStoreSyncPeerRetryRebuildsImmutableView(t *testing.T) {
	store := NewDaemonStateStore(&stateFile{
		ManagedZone: "node-a.catofes.",
		Network:     cloneTestNetworkState(),
		SyncPeers:   map[string]syncPeerState{"peer-a": {}},
	})
	attempts := 0
	_, err := store.updateSyncPeerWithView("peer-a", func(view syncPeerMutationView, peer *syncPeerState) error {
		attempts++
		if attempts == 1 {
			if _, err := store.Update(func(state *stateFile) error {
				state.ManagedZone = "node-b.catofes."
				return nil
			}); err != nil {
				return err
			}
		}
		peer.LastUpdateSource = string(view.ManagedZone)
		return nil
	})
	if err != nil {
		t.Fatalf("updateSyncPeerWithView: %v", err)
	}
	if attempts != 2 {
		t.Fatalf("attempts = %d, want one stale retry", attempts)
	}
	snapshot, _ := store.Snapshot()
	if got := snapshot.SyncPeers["peer-a"].LastUpdateSource; got != "node-b.catofes." {
		t.Fatalf("LastUpdateSource = %q, want latest retry view", got)
	}
}

func BenchmarkDaemonStateStorePeerUpdate(b *testing.B) {
	newLargeState := func() *stateFile {
		state := &stateFile{
			Network:   cloneTestNetworkState(),
			SyncPeers: map[string]syncPeerState{"peer-a": {}},
		}
		state.Network.Zones["node-a.catofes."].Records["large"] = &zone.Record{
			Zone:  "node-a.catofes.",
			Key:   "large",
			Value: make([]byte, 1<<20),
		}
		return state
	}
	b.Run("full_update", func(b *testing.B) {
		store := NewDaemonStateStore(newLargeState())
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := store.Update(func(state *stateFile) error {
				peer := state.SyncPeers["peer-a"]
				peer.LastSyncUnix++
				state.SyncPeers["peer-a"] = peer
				return nil
			}); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("local_cow", func(b *testing.B) {
		store := NewDaemonStateStore(newLargeState())
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := store.UpdateSyncPeer("peer-a", func(peer *syncPeerState) error {
				peer.LastSyncUnix++
				return nil
			}); err != nil {
				b.Fatal(err)
			}
		}
	})
}
