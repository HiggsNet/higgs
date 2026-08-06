package main

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

var benchmarkStateSnapshot *stateFile
var benchmarkStatusProjection daemonStatusProjection
var benchmarkPersistenceLease committedStateLease

func readCommittedForTest(store *DaemonStateStore, fn func(*stateFile)) {
	if store == nil || fn == nil {
		return
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	fn(store.committed)
}

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

func TestDaemonStateStoreRoutingSnapshotSharesNetworkAndDetachesOwnedState(t *testing.T) {
	initial := &stateFile{
		ManagedZone: "node-a.catofes.",
		Network:     cloneTestNetworkState(),
		BirdInstances: map[string]*BirdInstanceState{
			"mesh": {NetNSName: "mesh", Overlays: []string{"main"}},
		},
		RoutingReconcile: &routingReconcileState{LastRunUnix: 10},
	}
	store := NewDaemonStateStore(initial)

	var committedNetwork *zone.NetworkState
	readCommittedForTest(store, func(state *stateFile) {
		committedNetwork = state.Network
	})
	snapshot, rev := store.routingSnapshot()
	if snapshot.Network != committedNetwork {
		t.Fatal("routing snapshot copied Network instead of sharing it")
	}
	snapshot.BirdInstances["mesh"].Overlays[0] = "changed"
	snapshot.RoutingReconcile.LastRunUnix = 20

	readCommittedForTest(store, func(state *stateFile) {
		if got := state.BirdInstances["mesh"].Overlays[0]; got != "main" {
			t.Fatalf("routing snapshot BirdInstances mutation leaked: %q", got)
		}
		if got := state.RoutingReconcile.LastRunUnix; got != 10 {
			t.Fatalf("routing snapshot reconcile mutation leaked: %d", got)
		}
	})

	nextRev, committed := store.commitRoutingIfRevision(rev, snapshot.BirdInstances, snapshot.RoutingReconcile)
	if !committed || nextRev != rev+1 {
		t.Fatalf("routing commit = (%d, %t), want (%d, true)", nextRev, committed, rev+1)
	}
	readCommittedForTest(store, func(state *stateFile) {
		if state.Network != committedNetwork {
			t.Fatal("routing commit copied Network instead of sharing it")
		}
		if got := state.BirdInstances["mesh"].Overlays[0]; got != "changed" {
			t.Fatalf("routing commit overlay = %q, want changed", got)
		}
	})

	snapshot.BirdInstances["mesh"].Overlays[0] = "retained-mutation"
	readCommittedForTest(store, func(state *stateFile) {
		if got := state.BirdInstances["mesh"].Overlays[0]; got != "changed" {
			t.Fatalf("post-commit input mutation leaked: %q", got)
		}
	})
}

func TestDaemonStateStoreIPsecTypedCOWOwnershipAndStale(t *testing.T) {
	initial := &stateFile{
		ManagedZone:       "node-a.catofes.",
		Network:           cloneTestNetworkState(),
		IPsecTransportKey: &ipsecTransportKeyState{PrivateKey: []byte("private")},
		IPsecPortRecord:   &ipsecPortRecordState{Range: &ipsec.PortRange{From: 4500, To: 4510}},
		LinkInstances:     map[string]linkInstanceState{"link-a": {ID: "link-a", Owner: linkOwnerState{Token: "owner-a"}}},
		IPsecReconcile:    &ipsecReconcileState{Desired: []desiredLinkState{{InstanceID: "link-a"}}},
		RoutingReconcile:  &routingReconcileState{LastError: "routing"},
	}
	store := NewDaemonStateStore(initial)

	var committedNetwork *zone.NetworkState
	var committedRouting *routingReconcileState
	readCommittedForTest(store, func(state *stateFile) {
		committedNetwork = state.Network
		committedRouting = state.RoutingReconcile
	})
	snapshot, rev := store.ipsecSnapshot()
	if snapshot.Network != committedNetwork || snapshot.RoutingReconcile != committedRouting {
		t.Fatal("IPsec snapshot copied or replaced an unowned field")
	}
	snapshot.IPsecTransportKey.PrivateKey[0] = 'P'
	snapshot.IPsecPortRecord.Range.From = 4600
	snapshot.LinkInstances["link-a"] = linkInstanceState{ID: "changed"}
	snapshot.IPsecReconcile.Desired[0].InstanceID = "changed"
	readCommittedForTest(store, func(state *stateFile) {
		if string(state.IPsecTransportKey.PrivateKey) != "private" ||
			state.IPsecPortRecord.Range.From != 4500 ||
			state.LinkInstances["link-a"].ID != "link-a" ||
			state.IPsecReconcile.Desired[0].InstanceID != "link-a" {
			t.Fatalf("IPsec workspace mutation leaked into committed state: %#v", state)
		}
	})

	nextRev, committed := store.commitIPsecIfRevision(rev, snapshot.IPsecTransportKey, snapshot.IPsecPortRecord, snapshot.LinkInstances, snapshot.IPsecReconcile)
	if !committed || nextRev != rev+1 {
		t.Fatalf("IPsec typed commit = (%d, %t), want (%d, true)", nextRev, committed, rev+1)
	}
	snapshot.IPsecReconcile.Desired[0].InstanceID = "retained"
	readCommittedForTest(store, func(state *stateFile) {
		if state.Network != committedNetwork || state.RoutingReconcile != committedRouting {
			t.Fatal("IPsec commit replaced an unowned field")
		}
		if state.IPsecReconcile.Desired[0].InstanceID != "changed" {
			t.Fatalf("retained IPsec input mutated committed state: %#v", state.IPsecReconcile)
		}
	})

	stale, staleRev := store.ipsecSnapshot()
	if _, err := store.Update(func(state *stateFile) error {
		state.IdentityKeyPath = "newer"
		return nil
	}); err != nil {
		t.Fatalf("advance revision: %v", err)
	}
	if current, ok := store.commitIPsecIfRevision(staleRev, stale.IPsecTransportKey, stale.IPsecPortRecord, map[string]linkInstanceState{"stale": {ID: "stale"}}, stale.IPsecReconcile); ok || current != staleRev+1 {
		t.Fatalf("stale IPsec commit = (%d, %t), want (%d, false)", current, ok, staleRev+1)
	}
	readCommittedForTest(store, func(state *stateFile) {
		if _, ok := state.LinkInstances["stale"]; ok {
			t.Fatal("stale IPsec result overwrote committed state")
		}
	})
}

func TestDaemonStateStoreFirewallTypedCOWOwnershipAndStale(t *testing.T) {
	initial := &stateFile{
		Network: cloneTestNetworkState(),
		EndpointACLs: map[string]endpointACL{
			"api": {Name: "api", Selectors: []string{"zone:catofes."}},
		},
		FirewallReconcile: &firewallReconcileState{Instances: map[string]*firewallInstanceReconcileStateEntry{
			"host": {PolicyHash: "old"},
		}},
		IPsecReconcile: &ipsecReconcileState{LastError: "ipsec"},
	}
	store := NewDaemonStateStore(initial)
	var committedNetwork *zone.NetworkState
	var committedIPsec *ipsecReconcileState
	readCommittedForTest(store, func(state *stateFile) {
		committedNetwork = state.Network
		committedIPsec = state.IPsecReconcile
	})

	snapshot, rev := store.firewallSnapshot()
	if snapshot.Network != committedNetwork || snapshot.IPsecReconcile != committedIPsec {
		t.Fatal("firewall snapshot copied or replaced an unowned field")
	}
	acl := snapshot.EndpointACLs["api"]
	acl.Selectors[0] = "zone:changed."
	snapshot.EndpointACLs["api"] = acl
	snapshot.FirewallReconcile.Instances["host"].PolicyHash = "changed"
	readCommittedForTest(store, func(state *stateFile) {
		if state.EndpointACLs["api"].Selectors[0] != "zone:catofes." ||
			state.FirewallReconcile.Instances["host"].PolicyHash != "old" {
			t.Fatal("firewall workspace mutation leaked into committed state")
		}
	})

	nextRev, committed := store.commitFirewallIfRevision(rev, snapshot.EndpointACLs, snapshot.FirewallReconcile)
	if !committed || nextRev != rev+1 {
		t.Fatalf("firewall typed commit = (%d, %t), want (%d, true)", nextRev, committed, rev+1)
	}
	snapshot.FirewallReconcile.Instances["host"].PolicyHash = "retained"
	readCommittedForTest(store, func(state *stateFile) {
		if state.Network != committedNetwork || state.IPsecReconcile != committedIPsec {
			t.Fatal("firewall commit replaced an unowned field")
		}
		if state.FirewallReconcile.Instances["host"].PolicyHash != "changed" {
			t.Fatal("retained firewall input mutated committed state")
		}
	})

	stale, staleRev := store.firewallSnapshot()
	if _, err := store.Update(func(state *stateFile) error {
		state.IdentityKeyPath = "newer"
		return nil
	}); err != nil {
		t.Fatalf("advance revision: %v", err)
	}
	stale.FirewallReconcile.LastError = "stale"
	if current, ok := store.commitFirewallIfRevision(staleRev, stale.EndpointACLs, stale.FirewallReconcile); ok || current != staleRev+1 {
		t.Fatalf("stale firewall commit = (%d, %t), want (%d, false)", current, ok, staleRev+1)
	}
	readCommittedForTest(store, func(state *stateFile) {
		if state.FirewallReconcile.LastError == "stale" {
			t.Fatal("stale firewall result overwrote committed state")
		}
	})
}

func TestDaemonStateStoreNetworkTypedCOWOwnershipRetainAndStale(t *testing.T) {
	initial := &stateFile{
		Network:          cloneTestNetworkState(),
		IPsecReconcile:   &ipsecReconcileState{LastError: "ipsec"},
		EndpointACLs:     map[string]endpointACL{"api": {Name: "api"}},
		RoutingReconcile: &routingReconcileState{LastError: "routing"},
	}
	store := NewDaemonStateStore(initial)
	var committedIPsec *ipsecReconcileState
	var committedRouting *routingReconcileState
	readCommittedForTest(store, func(state *stateFile) {
		committedIPsec = state.IPsecReconcile
		committedRouting = state.RoutingReconcile
	})

	snapshot, rev := store.networkSnapshot()
	if snapshot.IPsecReconcile != committedIPsec || snapshot.RoutingReconcile != committedRouting {
		t.Fatal("Network snapshot copied or replaced an unowned field")
	}
	snapshot.Network.Zones["node-a.catofes."].Records["endpoint"].Value[0] = 'N'
	readCommittedForTest(store, func(state *stateFile) {
		if string(state.Network.Zones["node-a.catofes."].Records["endpoint"].Value) != "endpoint-a" {
			t.Fatal("Network workspace mutation leaked into committed state")
		}
	})
	nextRev, committed := store.commitNetworkIfRevision(rev, snapshot.Network)
	if !committed || nextRev != rev+1 {
		t.Fatalf("Network typed commit = (%d, %t), want (%d, true)", nextRev, committed, rev+1)
	}
	snapshot.Network.Zones["node-a.catofes."].Records["endpoint"].Value[0] = 'R'
	readCommittedForTest(store, func(state *stateFile) {
		if state.IPsecReconcile != committedIPsec || state.RoutingReconcile != committedRouting {
			t.Fatal("Network commit replaced an unowned field")
		}
		if got := state.Network.Zones["node-a.catofes."].Records["endpoint"].Value[0]; got != 'N' {
			t.Fatalf("retained Network input mutated committed state: %q", got)
		}
	})

	stale, staleRev := store.networkSnapshot()
	if _, err := store.Update(func(state *stateFile) error {
		state.IdentityKeyPath = "newer"
		return nil
	}); err != nil {
		t.Fatalf("advance revision: %v", err)
	}
	stale.Network.GlobalRoot = []byte("stale")
	if current, ok := store.commitNetworkIfRevision(staleRev, stale.Network); ok || current != staleRev+1 {
		t.Fatalf("stale Network commit = (%d, %t), want (%d, false)", current, ok, staleRev+1)
	}
	readCommittedForTest(store, func(state *stateFile) {
		if string(state.Network.GlobalRoot) == "stale" {
			t.Fatal("stale Network result overwrote committed state")
		}
	})
}

func BenchmarkDaemonStateStoreSnapshotStrategies(b *testing.B) {
	network := cloneTestNetworkState()
	zs := network.Zones["node-a.catofes."]
	for i := range 1000 {
		key := fmt.Sprintf("record-%04d", i)
		zs.Records[key] = &zone.Record{
			Zone:      "node-a.catofes.",
			Key:       key,
			Type:      "benchmark",
			Value:     make([]byte, 128),
			ValueHash: make([]byte, 32),
			Signature: make([]byte, 64),
			Version:   1,
		}
	}
	store := NewDaemonStateStore(&stateFile{
		ManagedZone: "node-a.catofes.",
		Network:     network,
		BirdInstances: map[string]*BirdInstanceState{
			"mesh": {NetNSName: "mesh", Overlays: []string{"main"}},
		},
		RoutingReconcile: &routingReconcileState{LastRunUnix: 10},
	})

	b.Run("full-handwritten-snapshot", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			benchmarkStateSnapshot, _ = store.Snapshot()
		}
	})
	b.Run("routing-cow-snapshot", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			benchmarkStateSnapshot, _ = store.routingSnapshot()
		}
	})
	b.Run("status-projection", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			benchmarkStatusProjection = store.statusProjection()
		}
	})
	b.Run("persistence-lease", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			benchmarkPersistenceLease = store.persistenceLease()
		}
	})
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
	readCommittedForTest(store, func(state *stateFile) {
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

	readCommittedForTest(store, func(state *stateFile) {
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

func TestDaemonStateStoreUpdateSyncPeersWithViewRetriesAndIsolatesUpdates(t *testing.T) {
	store := NewDaemonStateStore(&stateFile{
		ManagedZone: "node-a.catofes.",
		Network:     cloneTestNetworkState(),
		SyncPeers: map[string]syncPeerState{
			"peer-a": {
				ObservedGraceAddrs: []observedGraceAddrState{{Addr: "198.51.100.1:33434"}},
			},
			"peer-b": {
				ObservedGraceAddrs: []observedGraceAddrState{{Addr: "198.51.100.2:33434"}},
			},
		},
	})
	attempts := 0
	var retained []observedGraceAddrState
	var plannedNetwork *zone.NetworkState
	var plannedPeerBGrace *observedGraceAddrState
	_, changed, err := store.updateSyncPeersWithView(func(view syncPeerMutationView) (map[string]syncPeerState, error) {
		attempts++
		if attempts == 1 {
			if _, err := store.Update(func(state *stateFile) error {
				state.IdentityKeyPath = "advance-revision"
				return nil
			}); err != nil {
				return nil, err
			}
		}
		plannedNetwork = view.Network
		peerB := view.SyncPeers["peer-b"]
		plannedPeerBGrace = &peerB.ObservedGraceAddrs[0]
		peer := cloneSyncPeerState(view.SyncPeers["peer-a"])
		peer.LastSyncUnix = int64(attempts)
		retained = peer.ObservedGraceAddrs
		return map[string]syncPeerState{"peer-a": peer}, nil
	})
	if err != nil {
		t.Fatalf("updateSyncPeersWithView: %v", err)
	}
	if !changed {
		t.Fatal("updateSyncPeersWithView reported no change")
	}
	if attempts != 2 {
		t.Fatalf("attempts = %d, want one stale retry", attempts)
	}

	readCommittedForTest(store, func(state *stateFile) {
		if state.Network != plannedNetwork {
			t.Fatal("batch peer update copied Network instead of sharing it")
		}
		peerB := state.SyncPeers["peer-b"]
		if &peerB.ObservedGraceAddrs[0] != plannedPeerBGrace {
			t.Fatal("batch peer update copied an unrelated peer's nested state")
		}
	})
	retained[0].Addr = "retained-mutation"
	snapshot, _ := store.Snapshot()
	peer := snapshot.SyncPeers["peer-a"]
	if peer.LastSyncUnix != 2 || peer.ObservedGraceAddrs[0].Addr != "198.51.100.1:33434" {
		t.Fatalf("retained batch result mutated committed peer: %+v", peer)
	}
}

func TestDaemonStateStoreUpdateSyncPeersWithViewNoopKeepsRevision(t *testing.T) {
	store := NewDaemonStateStore(&stateFile{
		Network:   cloneTestNetworkState(),
		SyncPeers: map[string]syncPeerState{"peer-a": {}},
	})
	before := store.Meta().Revision
	attempts := 0
	rev, changed, err := store.updateSyncPeersWithView(func(syncPeerMutationView) (map[string]syncPeerState, error) {
		attempts++
		if attempts == 1 {
			if _, err := store.Update(func(state *stateFile) error {
				state.IdentityKeyPath = "advance-revision"
				return nil
			}); err != nil {
				return nil, err
			}
		}
		return nil, nil
	})
	if err != nil {
		t.Fatalf("updateSyncPeersWithView: %v", err)
	}
	if changed {
		t.Fatal("no-op batch reported a change")
	}
	if attempts != 2 {
		t.Fatalf("no-op attempts = %d, want retry against latest revision", attempts)
	}
	if rev != before+1 || store.Meta().Revision != before+1 {
		t.Fatalf("no-op batch returned stale revision: returned=%d before=%d after=%d", rev, before, store.Meta().Revision)
	}
}

func newLargeDaemonState() *stateFile {
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

func BenchmarkDaemonStateStorePeerUpdate(b *testing.B) {
	b.Run("full_update", func(b *testing.B) {
		store := NewDaemonStateStore(newLargeDaemonState())
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
		store := NewDaemonStateStore(newLargeDaemonState())
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

func BenchmarkDaemonRecordSyncPeerState(b *testing.B) {
	service := newDaemonService(
		&Runtime{},
		newLargeDaemonState(),
		&syncConfigFile{PeerID: "node-a.catofes."},
		defaultDaemonInterval,
	)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		service.recordSyncPeerState("peer-a", "benchmark", func(state *stateFile) {
			peer := state.SyncPeers["peer-a"]
			peer.LastSyncUnix++
			state.SyncPeers["peer-a"] = peer
		})
	}
}
