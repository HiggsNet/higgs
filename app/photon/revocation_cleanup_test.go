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
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/firewall"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

// TestCollectAllRevokedZonesEmpty verifies that no revoked zones are returned
// when all zones have active delegations.
func TestCollectAllRevokedZonesEmpty(t *testing.T) {
	state, _ := buildTestNetworkState(t)
	now := time.Unix(4140, 0)
	revoked := collectAllRevokedZones(state.Network, now)
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

	revoked := collectAllRevokedZones(state.Network, now)
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

	impact := ComputeRevocationImpact(state.Network, state.LinkInstances, testGossipCheckpoint(state.SyncPeers), "node-b.catofes.", now)
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

	impact := ComputeRevocationImpact(state.Network, state.LinkInstances, testGossipCheckpoint(state.SyncPeers), "node-b.catofes.", now)
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
	view := service.StateStore.common.ReadView()
	peer := view.Gossip.Peers["node-b.catofes."]
	if peer.DiscoveredEndpoint != "" || peer.ObservedEndpoint != "" {
		t.Fatalf("peer cache not cleared: discovered=%s observed=%s", peer.DiscoveredEndpoint, peer.ObservedEndpoint)
	}
	if peer.LastFailure == nil || peer.LastFailure.Message != "zone revoked" {
		t.Fatalf("last failure = %+v, want zone revoked", peer.LastFailure)
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

	view := service.StateStore.common.ReadView()
	if got := view.Gossip.Peers["node-b.catofes."].DiscoveredEndpoint; got != "" {
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

	impacts := AllRevocationImpact(state.Network, state.LinkInstances, testGossipCheckpoint(state.SyncPeers), nil, now)
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

	impacts := AllRevocationImpact(state.Network, state.LinkInstances, testGossipCheckpoint(state.SyncPeers), nil, now)
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
	common, current := service.StateStore.readCommonAndRuntime()
	parent := common.State.Network.Zones["catofes."]
	delegation := parent.Delegations["node-b.catofes."]
	parent.Revocations["node-b.catofes."] = &zone.DelegationRevocation{
		ChildZone:             "node-b.catofes.",
		ParentZone:            "catofes.",
		RevokedAuthorityEpoch: delegation.AuthorityEpoch,
		RevokedAuthorityHash:  delegation.AuthorityHash,
		Reason:                "test revoke cleanup",
		RevokedAt:             now.Add(-time.Second).Unix(),
	}
	service = newTestDaemonServiceFromOwners(rt, common.State, common.Gossip, current, config, time.Second)
	installTestIPsecDrivers(service, driver, driver)
	service.notifyStateChanged()

	// Verify peer cache was cleared after notifyStateChanged.
	common, current = service.StateStore.readCommonAndRuntime()
	peer := common.Gossip.Peers["node-b.catofes."]
	if peer.DiscoveredEndpoint != "" {
		t.Fatalf("discovered addr should be cleared: %s", peer.DiscoveredEndpoint)
	}
	if peer.ObservedEndpoint != "" {
		t.Fatalf("observed addr should be cleared: %s", peer.ObservedEndpoint)
	}
	if peer.LastFailure == nil || peer.LastFailure.Message != "zone revoked" {
		t.Fatalf("last failure = %+v, want zone revoked", peer.LastFailure)
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
	common, current := service.StateStore.readCommonAndRuntime()
	if len(current.LinkInstances) != 1 {
		t.Fatalf("initial link instances = %d, want 1", len(current.LinkInstances))
	}
	initialFirewall := lastFirewallDesired(t, firewallDriver)
	if !prefixIn(initialFirewall.Prefixes.MeshAuthorizedV4, "10.1.0.0/24") {
		t.Fatalf("initial firewall authorized prefixes = %v, want node-b route", initialFirewall.Prefixes.MeshAuthorizedV4)
	}
	initialBirdCfg := readBirdConfigForNetns(t, current, "photontesth2")
	if !strings.Contains(initialBirdCfg, "10.1.0.0/24") {
		t.Fatalf("initial BIRD config missing transit export for node-b route:\n%s", initialBirdCfg)
	}

	parent := common.State.Network.Zones["catofes."]
	delegation := parent.Delegations["node-b.catofes."]
	parent.Revocations["node-b.catofes."] = &zone.DelegationRevocation{
		ChildZone:             "node-b.catofes.",
		ParentZone:            "catofes.",
		RevokedAuthorityEpoch: delegation.AuthorityEpoch,
		RevokedAuthorityHash:  delegation.AuthorityHash,
		Reason:                "combined revocation smoke",
		RevokedAt:             now.Add(-time.Second).Unix(),
	}
	common.Gossip.Peers = map[string]corestate.PeerCheckpoint{
		"node-b.catofes.": {
			DiscoveredEndpoint:   "192.0.2.1:33434",
			ObservedEndpoint:     "192.0.2.1:33434",
			ObservedLastSeenUnix: now.Unix(),
			ObservedUntilUnix:    now.Add(5 * time.Minute).Unix(),
		},
	}
	service = newTestDaemonServiceFromOwners(rt, common.State, common.Gossip, current, config, time.Second)
	installTestLinuxDrivers(service, testLinuxDrivers{
		ipsec: ipsecDriver, xfrm: ipsecDriver, firewall: firewallDriver,
		birdProcess:       &fakeBirdProcessManager{running: false},
		birdClientFactory: func(socketPath string, timeout time.Duration) birdClient { return &fakeBirdClient{} },
	})

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

	common, current = service.StateStore.readCommonAndRuntime()
	if len(current.LinkInstances) != 0 {
		t.Fatalf("link instances should be empty after revocation, got %d", len(current.LinkInstances))
	}
	if len(ipsecDriver.Terminated) == 0 || len(ipsecDriver.Unloaded) == 0 || len(ipsecDriver.DeletedIFs) == 0 {
		t.Fatalf("ipsec teardown incomplete: terminated=%v unloaded=%v deleted_ifs=%v", ipsecDriver.Terminated, ipsecDriver.Unloaded, ipsecDriver.DeletedIFs)
	}
	if peer := common.Gossip.Peers["node-b.catofes."]; peer.DiscoveredEndpoint != "" || peer.ObservedEndpoint != "" || peer.LastFailure == nil || peer.LastFailure.Message != "zone revoked" {
		t.Fatalf("revoked peer cache not cleaned: %+v", peer)
	}

	revokedBirdCfg := readBirdConfigForNetns(t, current, "photontesth2")
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

func readBirdConfigForNetns(t *testing.T, runtime *linuxRuntimeState, netns string) string {
	t.Helper()
	if runtime == nil || runtime.BirdInstances == nil || runtime.BirdInstances[netns] == nil {
		t.Fatalf("missing BIRD instance for netns %s", netns)
	}
	path := runtime.BirdInstances[netns].ConfigPath
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

	impacts := AllRevocationImpact(state.Network, state.LinkInstances, testGossipCheckpoint(state.SyncPeers), config, now)
	if len(impacts) != 1 {
		t.Fatalf("expected 1 impact, got %d", len(impacts))
	}
	found := slices.Contains(impacts[0].ConfiguredButRevoked, "node-b.catofes.")
	if !found {
		t.Fatalf("node-b.catofes. not in configured_but_revoked: %v", impacts[0].ConfiguredButRevoked)
	}
}
