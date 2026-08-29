package main

import (
	"context"
	"net/netip"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
	"github.com/HiggsNet/photon/pkg/core/observability"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/firewall"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

// TestCollectAllRevokedZonesEmpty verifies that no revoked zones are returned
// when all zones have active delegations.
func TestCollectAllRevokedZonesEmpty(t *testing.T) {
	state, _ := buildTestNetworkState(t)
	now := time.Unix(4140, 0)
	revoked := CollectAllRevokedZones(state, now)
	if len(revoked) != 0 {
		t.Fatalf("expected no revoked zones, got %d: %v", len(revoked), revoked)
	}
}

// TestCollectAllRevokedZonesWithRevocation verifies that revoked zones are
// correctly identified from active state.
func TestCollectAllRevokedZonesWithRevocation(t *testing.T) {
	state, _ := buildTestNetworkState(t)
	now := time.Unix(4140, 0)

	// Revoke node-b.catofes.
	parent := state.Network.Zones["catofes."]
	delegation := parent.Delegations["node-b.catofes."]
	parent.Revocations["node-b.catofes."] = &zone.DelegationRevocation{
		ChildZone:             "node-b.catofes.",
		ParentZone:            "catofes.",
		RevokedAuthorityEpoch: delegation.AuthorityEpoch,
		RevokedAuthorityHash:  delegation.AuthorityHash,
		RevokedAt:             now.Add(-time.Second).Unix(),
	}

	revoked := CollectAllRevokedZones(state, now)
	if !revoked["node-b.catofes."] {
		t.Fatalf("expected node-b.catofes. to be revoked, got %v", revoked)
	}
	if len(revoked) != 1 {
		t.Fatalf("expected exactly 1 revoked zone, got %d: %v", len(revoked), revoked)
	}
}

// TestComputeRevocationImpactBasic verifies that inspect.RevocationImpact correctly
// identifies affected link instances, sync peers, and the source zone.
func TestComputeRevocationImpactBasic(t *testing.T) {
	state, _ := buildTestNetworkState(t)
	now := time.Unix(4140, 0)

	// Set up a link instance to node-b.catofes.
	state.LinkInstances = map[string]linkInstanceState{
		"link-to-node-b": {
			ID:          "link-to-node-b",
			PeerZone:    "node-b.catofes.",
			GroupID:     "main",
			ActualState: "up",
		},
	}
	// Set up a SyncPeer for node-b.
	state.SyncPeers = map[string]syncPeerState{
		"node-b.catofes.": {
			DiscoveredAddr: "192.0.2.1:33434",
			ObservedAddr:   "192.0.2.1:33434",
		},
	}

	// Revoke node-b.catofes.
	parent := state.Network.Zones["catofes."]
	delegation := parent.Delegations["node-b.catofes."]
	parent.Revocations["node-b.catofes."] = &zone.DelegationRevocation{
		ChildZone:             "node-b.catofes.",
		ParentZone:            "catofes.",
		RevokedAuthorityEpoch: delegation.AuthorityEpoch,
		RevokedAuthorityHash:  delegation.AuthorityHash,
		RevokedAt:             now.Add(-time.Second).Unix(),
	}

	impact := ComputeRevocationImpact(state.Network, state.LinkInstances, state.SyncPeers, "node-b.catofes.", now)
	if impact.RevokedZone != "node-b.catofes." {
		t.Fatalf("revoked zone = %s, want node-b.catofes.", impact.RevokedZone)
	}
	if impact.SourceZone != "catofes." {
		t.Fatalf("source zone = %s, want catofes.", impact.SourceZone)
	}
	if len(impact.AffectedLinkInstances) != 1 || impact.AffectedLinkInstances[0] != "link-to-node-b" {
		t.Fatalf("affected link instances = %v, want [link-to-node-b]", impact.AffectedLinkInstances)
	}
	if len(impact.AffectedSyncPeers) != 1 || impact.AffectedSyncPeers[0] != "node-b.catofes." {
		t.Fatalf("affected sync peers = %v, want [node-b.catofes.]", impact.AffectedSyncPeers)
	}
	// All layer statuses should be pending.
	for _, layer := range []string{inspect.RevocationLayerIPsec, inspect.RevocationLayerRouting, inspect.RevocationLayerFirewall, inspect.RevocationLayerGossip} {
		if status := impact.Layers[layer]; status == nil || status.Status != inspect.RevocationStatusPending {
			t.Fatalf("layer %s status = %+v, want pending", layer, status)
		}
	}
}

// TestComputeRevocationImpactSubtree verifies that descendant zones are
// correctly identified as part of the revoked subtree.
func TestComputeRevocationImpactSubtree(t *testing.T) {
	state, _ := buildTestNetworkState(t)
	now := time.Unix(4140, 0)

	// Add a grandchild zone under node-b.catofes.
	// buildTestNetworkState already has root -> catofes. -> node-b.catofes.
	// We need to add a sub-zone like leaf.node-b.catofes.
	leafZone := zone.ZonePath("leaf.node-b.catofes.")
	state.Network.Zones[leafZone] = &zone.ZoneState{
		Path:          leafZone,
		Authority:     state.Network.Zones["node-b.catofes."].Authority,
		Delegations:   make(map[zone.ZonePath]*zone.Delegation),
		Revocations:   make(map[zone.ZonePath]*zone.DelegationRevocation),
		Records:       make(map[string]*zone.Record),
		RecordHistory: make(map[string][]*zone.Record),
	}
	// Also set up link instance and sync peer for the leaf.
	state.LinkInstances = map[string]linkInstanceState{
		"link-to-leaf": {
			ID:          "link-to-leaf",
			PeerZone:    leafZone,
			GroupID:     "main",
			ActualState: "up",
		},
	}
	state.SyncPeers = map[string]syncPeerState{
		string(leafZone): {
			DiscoveredAddr: "192.0.2.2:33434",
		},
	}

	// Revoke node-b.catofes. (parent zone).
	parent := state.Network.Zones["catofes."]
	delegation := parent.Delegations["node-b.catofes."]
	parent.Revocations["node-b.catofes."] = &zone.DelegationRevocation{
		ChildZone:             "node-b.catofes.",
		ParentZone:            "catofes.",
		RevokedAuthorityEpoch: delegation.AuthorityEpoch,
		RevokedAuthorityHash:  delegation.AuthorityHash,
		RevokedAt:             now.Add(-time.Second).Unix(),
	}

	impact := ComputeRevocationImpact(state.Network, state.LinkInstances, state.SyncPeers, "node-b.catofes.", now)
	// The leaf should be in the subtree.
	found := slices.Contains(impact.RevokedSubtree, leafZone)
	if !found {
		t.Fatalf("leaf zone %s not found in subtree %v", leafZone, impact.RevokedSubtree)
	}
	// The leaf's link instance should be affected.
	if len(impact.AffectedLinkInstances) != 1 || impact.AffectedLinkInstances[0] != "link-to-leaf" {
		t.Fatalf("affected link instances = %v, want [link-to-leaf]", impact.AffectedLinkInstances)
	}
	// The leaf's sync peer should be affected.
	if len(impact.AffectedSyncPeers) != 1 || impact.AffectedSyncPeers[0] != string(leafZone) {
		t.Fatalf("affected sync peers = %v, want [%s]", impact.AffectedSyncPeers, leafZone)
	}
}

// TestComputeRevocationImpactNilState verifies that nil state produces an
// empty impact.
func TestComputeRevocationImpactNilState(t *testing.T) {
	impact := ComputeRevocationImpact(nil, nil, nil, "node-b.catofes.", time.Now())
	if impact.RevokedZone != "node-b.catofes." {
		t.Fatalf("revoked zone = %s, want node-b.catofes.", impact.RevokedZone)
	}
	if len(impact.RevokedSubtree) != 0 || len(impact.AffectedLinkInstances) != 0 || len(impact.AffectedSyncPeers) != 0 {
		t.Fatalf("expected empty impact for nil state, got %+v", impact)
	}
}

// TestCleanupRevokedPeerCache verifies that runtime-relevant fields are cleared
// for revoked peers while keeping the entry for diagnostics.
func TestCleanupRevokedPeerCache(t *testing.T) {
	state, _ := buildTestNetworkState(t)
	now := time.Unix(4140, 0)

	// Set up sync peer with addresses and observed paths.
	state.SyncPeers = map[string]syncPeerState{
		"node-b.catofes.": {
			DiscoveredAddr:       "192.0.2.1:33434",
			DiscoveredAtUnix:     now.Add(-1 * time.Hour).Unix(),
			ObservedAddr:         "192.0.2.1:33434",
			ObservedLastSeenUnix: now.Unix(),
			ObservedUntilUnix:    now.Add(5 * time.Minute).Unix(),
			ObservedGraceAddrs: []observedGraceAddrState{
				{Addr: "192.0.2.2:33434", UntilUnix: now.Add(10 * time.Minute).Unix()},
			},
			BackoffUntilUnix: now.Add(30 * time.Second).Unix(),
			FailureCount:     3,
			LastError:        "timeout",
		},
		"node-a.catofes.": {
			DiscoveredAddr: "192.0.2.10:33434",
		},
	}

	revoked := map[zone.ZonePath]bool{"node-b.catofes.": true}
	CleanupRevokedPeerCache(state, revoked)

	// node-b should have cleared fields.
	peerB := state.SyncPeers["node-b.catofes."]
	if peerB.DiscoveredAddr != "" {
		t.Fatalf("discovered addr not cleared: %s", peerB.DiscoveredAddr)
	}
	if peerB.ObservedAddr != "" {
		t.Fatalf("observed addr not cleared: %s", peerB.ObservedAddr)
	}
	if peerB.ObservedLastSeenUnix != 0 {
		t.Fatalf("observed last seen not cleared: %d", peerB.ObservedLastSeenUnix)
	}
	if peerB.ObservedGraceAddrs != nil {
		t.Fatalf("observed grace addrs not cleared: %+v", peerB.ObservedGraceAddrs)
	}
	if peerB.BackoffUntilUnix != 0 {
		t.Fatalf("backoff not cleared: %d", peerB.BackoffUntilUnix)
	}
	if peerB.FailureCount != 0 {
		t.Fatalf("failure count not cleared: %d", peerB.FailureCount)
	}
	if peerB.LastError != "zone revoked" {
		t.Fatalf("last error = %q, want 'zone revoked'", peerB.LastError)
	}

	// node-a should be untouched.
	peerA := state.SyncPeers["node-a.catofes."]
	if peerA.DiscoveredAddr != "192.0.2.10:33434" {
		t.Fatalf("non-revoked peer discovered addr changed: %s", peerA.DiscoveredAddr)
	}
}

// TestCleanupRevokedPeerCacheEmpty verifies no panic on empty/nil input.
func TestCleanupRevokedPeerCacheEmpty(t *testing.T) {
	CleanupRevokedPeerCache(nil, nil)
	state := &stateFile{SyncPeers: map[string]syncPeerState{}}
	CleanupRevokedPeerCache(state, nil)
}

// TestUpdateRevocationLayerStatus verifies layer status updates.
func TestUpdateRevocationLayerStatus(t *testing.T) {
	impact := inspect.RevocationImpact{
		Layers: make(map[string]*inspect.RevocationLayerStatus),
	}
	// Initialize all layers as pending, similar to ComputeRevocationImpact.
	for _, layer := range []string{inspect.RevocationLayerIPsec, inspect.RevocationLayerRouting, inspect.RevocationLayerFirewall, inspect.RevocationLayerGossip} {
		impact.Layers[layer] = &inspect.RevocationLayerStatus{Status: inspect.RevocationStatusPending}
	}
	now := time.Unix(4140, 0)
	UpdateRevocationLayerStatus(&impact, inspect.RevocationLayerFirewall, inspect.RevocationStatusRemoved, "deleted 3 rules", "", now)
	status := impact.Layers[inspect.RevocationLayerFirewall]
	if status == nil || status.Status != inspect.RevocationStatusRemoved || status.Reason != "deleted 3 rules" || status.UnixTime != now.Unix() {
		t.Fatalf("layer status = %+v, want removed/deleted 3 rules", status)
	}

	UpdateRevocationLayerStatus(&impact, inspect.RevocationLayerIPsec, inspect.RevocationStatusError, "", "timeout", now)
	if !impact.HasPendingCleanup() {
		// routing and gossip should still be pending
		t.Fatalf("expected pending cleanup, but routing/gossip are not pending")
	}
	UpdateRevocationLayerStatus(&impact, inspect.RevocationLayerRouting, inspect.RevocationStatusRemoved, "", "", now)
	UpdateRevocationLayerStatus(&impact, inspect.RevocationLayerGossip, inspect.RevocationStatusRemoved, "", "", now)
	if impact.HasPendingCleanup() {
		t.Fatalf("expected no pending cleanup after all layers resolved")
	}
}

// TestDaemonFlushRevocationCleanup verifies that the daemon's
// flushRevocationCleanup correctly clears peer cache after revocation.
func TestDaemonFlushRevocationCleanup(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(4140, 0)

	// Set up sync peer with observed path.
	state.SyncPeers = map[string]syncPeerState{
		"node-b.catofes.": {
			DiscoveredAddr:       "192.0.2.1:33434",
			ObservedAddr:         "192.0.2.1:33434",
			ObservedLastSeenUnix: now.Unix(),
			ObservedUntilUnix:    now.Add(5 * time.Minute).Unix(),
		},
	}

	// Revoke node-b.catofes.
	parent := state.Network.Zones["catofes."]
	delegation := parent.Delegations["node-b.catofes."]
	parent.Revocations["node-b.catofes."] = &zone.DelegationRevocation{
		ChildZone:             "node-b.catofes.",
		ParentZone:            "catofes.",
		RevokedAuthorityEpoch: delegation.AuthorityEpoch,
		RevokedAuthorityHash:  delegation.AuthorityHash,
		RevokedAt:             now.Add(-time.Second).Unix(),
	}

	appConfig := defaultAppConfig()
	rt := &Runtime{
		Config:    appConfig,
		StatePath: filepath.Join(t.TempDir(), "photon.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	service := newTestDaemonService(rt, state, config, time.Second)

	// Flush revocation cleanup.
	service.flushRevocationCleanup()

	// Verify peer cache is cleared.
	peer := service.currentState().SyncPeers["node-b.catofes."]
	if peer.DiscoveredAddr != "" || peer.ObservedAddr != "" {
		t.Fatalf("peer cache not cleared: discovered=%s observed=%s", peer.DiscoveredAddr, peer.ObservedAddr)
	}
	if peer.LastError != "zone revoked" {
		t.Fatalf("last error = %q, want 'zone revoked'", peer.LastError)
	}
}

func TestDaemonFlushRevocationCleanupWithoutRevocationsDoesNotCommit(t *testing.T) {
	state, config := buildTestNetworkState(t)
	rt := &Runtime{
		Config:    defaultAppConfig(),
		StatePath: filepath.Join(t.TempDir(), "photon.db"),
	}
	service := newTestDaemonService(rt, state, config, time.Second)
	before := service.StateStore.Meta().Revision

	service.flushRevocationCleanup()

	if after := service.StateStore.Meta().Revision; after != before {
		t.Fatalf("state revision after no-op cleanup = %d, want %d", after, before)
	}
}

func TestDaemonFlushRevocationCleanupAlreadyCleanDoesNotCommit(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(4140, 0)
	state.SyncPeers = map[string]syncPeerState{
		"node-b.catofes.": {LastError: "zone revoked"},
	}
	parent := state.Network.Zones["catofes."]
	delegation := parent.Delegations["node-b.catofes."]
	parent.Revocations["node-b.catofes."] = &zone.DelegationRevocation{
		ChildZone:             "node-b.catofes.",
		ParentZone:            "catofes.",
		RevokedAuthorityEpoch: delegation.AuthorityEpoch,
		RevokedAuthorityHash:  delegation.AuthorityHash,
		RevokedAt:             now.Add(-time.Second).Unix(),
	}
	rt := &Runtime{Config: defaultAppConfig(), Clock: func() time.Time { return now }}
	service := newTestDaemonService(rt, state, config, time.Second)
	service.hostRuntime.Observability.Update("node-b.catofes.", now, func(peer *observability.PeerDiagnostics) {
		peer.DatagramStats = &observability.PeerDatagramStats{ChunkFallbacks: 1}
	})
	before := service.StateStore.Meta().Revision

	service.flushRevocationCleanup()

	if after := service.StateStore.Meta().Revision; after != before {
		t.Fatalf("state revision after already-clean cleanup = %d, want %d", after, before)
	}
	if _, ok := service.hostRuntime.Observability.Snapshot("node-b.catofes.", now); ok {
		t.Fatal("already-clean fast path retained revoked peer observability")
	}
}

func BenchmarkDaemonFlushRevocationCleanupAlreadyClean(b *testing.B) {
	state, config := buildTestNetworkState(b)
	now := time.Unix(4140, 0)
	state.SyncPeers = map[string]syncPeerState{
		"node-b.catofes.": {LastError: "zone revoked"},
	}
	parent := state.Network.Zones["catofes."]
	delegation := parent.Delegations["node-b.catofes."]
	parent.Revocations["node-b.catofes."] = &zone.DelegationRevocation{
		ChildZone:             "node-b.catofes.",
		ParentZone:            "catofes.",
		RevokedAuthorityEpoch: delegation.AuthorityEpoch,
		RevokedAuthorityHash:  delegation.AuthorityHash,
		RevokedAt:             now.Add(-time.Second).Unix(),
	}
	service := newTestDaemonService(&Runtime{Config: defaultAppConfig(), Clock: func() time.Time { return now }}, state, config, time.Second)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		service.flushRevocationCleanup()
	}
}

func TestDaemonFlushRevocationCleanupUsesStateStoreWhileConstructorInputLocked(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(4140, 0)
	state.SyncPeers = map[string]syncPeerState{
		"node-b.catofes.": {DiscoveredAddr: "192.0.2.1:33434"},
	}
	parent := state.Network.Zones["catofes."]
	delegation := parent.Delegations["node-b.catofes."]
	parent.Revocations["node-b.catofes."] = &zone.DelegationRevocation{
		ChildZone:             "node-b.catofes.",
		ParentZone:            "catofes.",
		RevokedAuthorityEpoch: delegation.AuthorityEpoch,
		RevokedAuthorityHash:  delegation.AuthorityHash,
		RevokedAt:             now.Add(-time.Second).Unix(),
	}

	rt := &Runtime{
		Config:    defaultAppConfig(),
		StatePath: filepath.Join(t.TempDir(), "photon.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	service := newTestDaemonService(rt, state, config, time.Second)
	service.hostRuntime.Observability.Update("node-b.catofes.", now, func(peer *observability.PeerDiagnostics) {
		peer.DatagramStats = &observability.PeerDatagramStats{ChunkFallbacks: 1}
	})

	state.Lock()
	done := make(chan struct{})
	go func() {
		service.flushRevocationCleanup()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		state.Unlock()
		t.Fatalf("flushRevocationCleanup blocked behind detached constructor-input lock")
	}
	state.Unlock()

	snapshot, _ := service.StateStore.Snapshot()
	if got := snapshot.SyncPeers["node-b.catofes."].DiscoveredAddr; got != "" {
		t.Fatalf("committed discovered addr = %q, want cleared", got)
	}
	if _, ok := service.hostRuntime.Observability.Snapshot("node-b.catofes.", now); ok {
		t.Fatal("revoked peer diagnostics were not deleted")
	}
}

// TestAllRevocationImpact verifies the combined impact for multiple revoked zones.
func TestAllRevocationImpact(t *testing.T) {
	state, _ := buildTestNetworkState(t)
	now := time.Unix(4140, 0)

	// Revoke node-b.catofes.
	parent := state.Network.Zones["catofes."]
	delegation := parent.Delegations["node-b.catofes."]
	parent.Revocations["node-b.catofes."] = &zone.DelegationRevocation{
		ChildZone:             "node-b.catofes.",
		ParentZone:            "catofes.",
		RevokedAuthorityEpoch: delegation.AuthorityEpoch,
		RevokedAuthorityHash:  delegation.AuthorityHash,
		RevokedAt:             now.Add(-time.Second).Unix(),
	}

	impacts := AllRevocationImpact(state.Network, state.LinkInstances, state.SyncPeers, nil, now)
	if len(impacts) != 1 {
		t.Fatalf("expected 1 impact, got %d", len(impacts))
	}
	if impacts[0].RevokedZone != "node-b.catofes." {
		t.Fatalf("impact revoked zone = %s, want node-b.catofes.", impacts[0].RevokedZone)
	}
}

// TestAllRevocationImpactEmpty verifies empty output when no zones are revoked.
func TestAllRevocationImpactEmpty(t *testing.T) {
	state, _ := buildTestNetworkState(t)
	now := time.Unix(4140, 0)

	impacts := AllRevocationImpact(state.Network, state.LinkInstances, state.SyncPeers, nil, now)
	if impacts != nil {
		t.Fatalf("expected nil impacts, got %d", len(impacts))
	}
}

// TestDaemonRevocationCleanupPeerCache verifies that the daemon's
// notifyStateChanged path clears peer cache after revocation, and that the
// deny-first ordering runs cleanup before IPsec/routing/firewall flush.
func TestDaemonRevocationCleanupPeerCache(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(4140, 0)
	addTestIPsecRecords(t, state.Network.Zones["node-b.catofes."], "node-b.catofes.", now, ipsec.RoleIn)
	group := testIPsecLinkGroup()
	setTestIPsecOverlayIntent(t, state.Network.Zones["node-b.catofes."], "node-b.catofes.", group, now)
	appConfig := defaultAppConfig()
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{group}
	rt := &Runtime{
		Config:    appConfig,
		StatePath: filepath.Join(t.TempDir(), "photon.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}

	// Set up a sync peer with observed path.
	state.SyncPeers = map[string]syncPeerState{
		"node-b.catofes.": {
			DiscoveredAddr:       "192.0.2.1:33434",
			ObservedAddr:         "192.0.2.1:33434",
			ObservedLastSeenUnix: now.Unix(),
			ObservedUntilUnix:    now.Add(5 * time.Minute).Unix(),
		},
	}

	driver := &observedIPsecDriver{}
	service := newTestDaemonService(rt, state, config, time.Second)
	installTestIPsecDrivers(service, driver, driver)

	// Create the link first.
	service.notifyStateChanged()

	// Now revoke node-b.catofes.
	latest, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	parent := latest.Network.Zones["catofes."]
	delegation := parent.Delegations["node-b.catofes."]
	parent.Revocations["node-b.catofes."] = &zone.DelegationRevocation{
		ChildZone:             "node-b.catofes.",
		ParentZone:            "catofes.",
		RevokedAuthorityEpoch: delegation.AuthorityEpoch,
		RevokedAuthorityHash:  delegation.AuthorityHash,
		Reason:                "test revoke cleanup",
		RevokedAt:             now.Add(-time.Second).Unix(),
	}
	// Re-add the sync peer state that was lost during LoadState.
	latest.SyncPeers = map[string]syncPeerState{
		"node-b.catofes.": {
			DiscoveredAddr:       "192.0.2.1:33434",
			ObservedAddr:         "192.0.2.1:33434",
			ObservedLastSeenUnix: now.Unix(),
			ObservedUntilUnix:    now.Add(5 * time.Minute).Unix(),
		},
	}
	if err := rt.SaveState(latest); err != nil {
		t.Fatalf("SaveState(revoke): %v", err)
	}
	service.setState(latest)
	service.notifyStateChanged()

	// Verify peer cache was cleared after notifyStateChanged.
	current := service.currentState()
	peer := current.SyncPeers["node-b.catofes."]
	if peer.DiscoveredAddr != "" {
		t.Fatalf("discovered addr should be cleared: %s", peer.DiscoveredAddr)
	}
	if peer.ObservedAddr != "" {
		t.Fatalf("observed addr should be cleared: %s", peer.ObservedAddr)
	}
	if peer.LastError != "zone revoked" {
		t.Fatalf("last error = %q, want 'zone revoked'", peer.LastError)
	}
	// Verify link instance was torn down.
	if len(current.LinkInstances) != 0 {
		t.Fatalf("link instances should be empty after revocation, got %d", len(current.LinkInstances))
	}
}

type captureFirewallDriver struct {
	firewall.DryRunDriver
	desired []*firewall.FirewallDesiredState
}

func (d *captureFirewallDriver) Apply(ctx context.Context, plan firewall.FirewallPlan, desired *firewall.FirewallDesiredState) (firewall.FirewallApplyResult, error) {
	d.desired = append(d.desired, desired)
	return d.DryRunDriver.Apply(ctx, plan, desired)
}

// TestRevocationDenyFirstCombinedSmoke verifies the Phase 6.5 cross-layer
// revocation path in one daemon flow: firewall is flushed before routing and
// IPsec, BIRD retracts the revoked route, and IPsec tears down the revoked
// peer link without recreating it.
func TestRevocationDenyFirstCombinedSmoke(t *testing.T) {
	state, config := buildTestNetworkStateForRouting(t)
	now := time.Unix(4140, 0)
	addTestIPsecRecords(t, state.Network.Zones["node-b.catofes."], "node-b.catofes.", now, ipsec.RoleIn)
	group := testIPsecLinkGroup()
	setTestIPsecOverlayIntent(t, state.Network.Zones["node-b.catofes."], "node-b.catofes.", group, now)

	appConfig := defaultAppConfig()
	appConfig.DataDir = t.TempDir()
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{group}
	appConfig.Netns = netnsConfig{
		Names:      map[string]ipsec.NetNSSpec{"photontesth2": {Kind: ipsec.NetNSName, Name: "photontesth2", Create: true}},
		Forwarding: map[string]firewall.ForwardingPolicy{"photontesth2": {Transit: true}},
	}
	appConfig.Routing, _ = parseRoutingConfigInstances([]routingInstanceYAML{{ID: "main", NetNS: "photontesth2", Enabled: boolPtr(true), Mode: ipsec.RoutingModeManaged}}, appConfig.Netns, appConfig.DataDir)
	appConfig.Firewall.Instances = []FirewallInstanceConfig{{
		ID:                "photontesth2",
		NetNS:             "photontesth2",
		Enabled:           true,
		Mode:              firewall.ModeManaged,
		Backend:           firewall.BackendNone,
		DefaultPolicy:     firewall.DefaultPolicyDrop,
		XFRMTunnelPattern: "phx*",
	}}

	rt := &Runtime{
		Config:    appConfig,
		StatePath: filepath.Join(t.TempDir(), "photon.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}

	ipsecDriver := &observedIPsecDriver{}
	firewallDriver := &captureFirewallDriver{}
	service := newTestDaemonService(rt, state, config, time.Second)
	installTestLinuxDrivers(service, testLinuxDrivers{
		ipsec: ipsecDriver, xfrm: ipsecDriver, firewall: firewallDriver,
		birdProcess:       &fakeBirdProcessManager{running: false},
		birdClientFactory: func(socketPath string, timeout time.Duration) birdClient { return &fakeBirdClient{} },
	})

	service.notifyStateChanged()
	current := service.currentState()
	if len(current.LinkInstances) != 1 {
		t.Fatalf("initial link instances = %d, want 1", len(current.LinkInstances))
	}
	initialFirewall := lastFirewallDesired(t, firewallDriver)
	if !prefixIn(initialFirewall.Prefixes.MeshAuthorizedV4, "10.1.0.0/24") {
		t.Fatalf("initial firewall authorized prefixes = %v, want node-b route", initialFirewall.Prefixes.MeshAuthorizedV4)
	}
	latest := service.currentState()
	initialBirdCfg := readBirdConfigForNetns(t, latest, "photontesth2")
	if !strings.Contains(initialBirdCfg, "10.1.0.0/24") {
		t.Fatalf("initial BIRD config missing transit export for node-b route:\n%s", initialBirdCfg)
	}

	parent := latest.Network.Zones["catofes."]
	delegation := parent.Delegations["node-b.catofes."]
	parent.Revocations["node-b.catofes."] = &zone.DelegationRevocation{
		ChildZone:             "node-b.catofes.",
		ParentZone:            "catofes.",
		RevokedAuthorityEpoch: delegation.AuthorityEpoch,
		RevokedAuthorityHash:  delegation.AuthorityHash,
		Reason:                "combined revocation smoke",
		RevokedAt:             now.Add(-time.Second).Unix(),
	}
	latest.SyncPeers = map[string]syncPeerState{
		"node-b.catofes.": {
			DiscoveredAddr:       "192.0.2.1:33434",
			ObservedAddr:         "192.0.2.1:33434",
			ObservedLastSeenUnix: now.Unix(),
			ObservedUntilUnix:    now.Add(5 * time.Minute).Unix(),
		},
	}
	if err := rt.SaveState(latest); err != nil {
		t.Fatalf("SaveState(revoked): %v", err)
	}
	service.setState(latest)

	var order []string
	service.Hooks.OnReconcileFlush = func(layer string) {
		order = append(order, layer)
	}
	firewallDriver.desired = nil
	service.notifyStateChanged()

	wantOrder := []string{"revocation_cleanup", "firewall", "routing", "ipsec", "revocation_cleanup"}
	if !reflect.DeepEqual(order, wantOrder) {
		t.Fatalf("flush order = %v, want %v", order, wantOrder)
	}

	revokedFirewall := lastFirewallDesired(t, firewallDriver)
	if prefixIn(revokedFirewall.Prefixes.MeshAuthorizedV4, "10.1.0.0/24") {
		t.Fatalf("revoked node-b prefixes still authorized by firewall: %v", revokedFirewall.Prefixes.MeshAuthorizedV4)
	}
	if !prefixIn(revokedFirewall.Prefixes.RevokedV4, "10.1.0.0/24") {
		t.Fatalf("revoked node-b route missing from firewall audit set: %v", revokedFirewall.Prefixes.RevokedV4)
	}

	current = service.currentState()
	if len(current.LinkInstances) != 0 {
		t.Fatalf("link instances should be empty after revocation, got %d", len(current.LinkInstances))
	}
	if len(ipsecDriver.Terminated) == 0 || len(ipsecDriver.Unloaded) == 0 || len(ipsecDriver.DeletedIFs) == 0 {
		t.Fatalf("ipsec teardown incomplete: terminated=%v unloaded=%v deleted_ifs=%v", ipsecDriver.Terminated, ipsecDriver.Unloaded, ipsecDriver.DeletedIFs)
	}
	if peer := current.SyncPeers["node-b.catofes."]; peer.DiscoveredAddr != "" || peer.ObservedAddr != "" || peer.LastError != "zone revoked" {
		t.Fatalf("revoked peer cache not cleaned: %+v", peer)
	}

	latest = service.currentState()
	revokedBirdCfg := readBirdConfigForNetns(t, latest, "photontesth2")
	if strings.Contains(revokedBirdCfg, "10.1.0.0/24") {
		t.Fatalf("BIRD config still exports revoked node-b route:\n%s", revokedBirdCfg)
	}
}

func lastFirewallDesired(t *testing.T, driver *captureFirewallDriver) *firewall.FirewallDesiredState {
	t.Helper()
	if driver == nil || len(driver.desired) == 0 {
		t.Fatal("firewall driver did not receive desired state")
	}
	return driver.desired[len(driver.desired)-1]
}

func prefixIn(prefixes []netip.Prefix, want string) bool {
	prefix := netip.MustParsePrefix(want)
	return slices.Contains(prefixes, prefix)
}

func readBirdConfigForNetns(t *testing.T, state *stateFile, netns string) string {
	t.Helper()
	if state == nil || state.BirdInstances == nil || state.BirdInstances[netns] == nil {
		t.Fatalf("missing BIRD instance for netns %s", netns)
	}
	path := state.BirdInstances[netns].ConfigPath
	if path == "" {
		t.Fatalf("empty BIRD config path for netns %s", netns)
	}
	cfg, err := readFileString(path)
	if err != nil {
		t.Fatalf("read BIRD config %s: %v", path, err)
	}
	return cfg
}

// TestConfiguredBootstrapPeerRevoked verifies that a revoked bootstrap peer is
// detected in the impact's ConfiguredButRevoked list.
func TestConfiguredBootstrapPeerRevoked(t *testing.T) {
	state, _ := buildTestNetworkState(t)
	now := time.Unix(4140, 0)

	// Revoke node-b.catofes.
	parent := state.Network.Zones["catofes."]
	delegation := parent.Delegations["node-b.catofes."]
	parent.Revocations["node-b.catofes."] = &zone.DelegationRevocation{
		ChildZone:             "node-b.catofes.",
		ParentZone:            "catofes.",
		RevokedAuthorityEpoch: delegation.AuthorityEpoch,
		RevokedAuthorityHash:  delegation.AuthorityHash,
		RevokedAt:             now.Add(-time.Second).Unix(),
	}

	config := &syncConfigFile{
		Bootstrap: []syncConfigPeer{
			{ID: "node-b.catofes.", Addr: "192.0.2.1:33434"},
		},
	}

	impacts := AllRevocationImpact(state.Network, state.LinkInstances, state.SyncPeers, config, now)
	if len(impacts) != 1 {
		t.Fatalf("expected 1 impact, got %d", len(impacts))
	}
	found := slices.Contains(impacts[0].ConfiguredButRevoked, "node-b.catofes.")
	if !found {
		t.Fatalf("node-b.catofes. not in configured_but_revoked: %v", impacts[0].ConfiguredButRevoked)
	}
}
