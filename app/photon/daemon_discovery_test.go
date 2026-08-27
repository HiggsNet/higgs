package main

import (
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corehost "github.com/HiggsNet/photon/pkg/core/host"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
)

func TestPlanDaemonDiscoveredPeersSeparatesStateAndTransport(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Now()
	putSignedEndpointRecord(t, state, "203.0.113.10", 33434, now, 1)
	state.SyncPeers = map[string]syncPeerState{
		"node-b.catofes.": {
			ObservedAddr:          "198.51.100.20:33434",
			ObservedFirstSeenUnix: now.Add(-2 * time.Minute).Unix(),
			ObservedLastSeenUnix:  now.Add(-2 * time.Minute).Unix(),
			ObservedUntilUnix:     now.Add(-time.Minute).Unix(),
		},
	}
	plan := corehost.PlanGossipDiscovery(testDaemonGossipDiscoveryInput(state, config), now)
	updates := plan.Patches

	// Planning must not mutate either state or transport.
	original := state.SyncPeers["node-b.catofes."]
	if original.DiscoveredAddr != "" || original.ObservedAddr == "" {
		t.Fatalf("planning mutated source peer: %+v", original)
	}
	peer := updates["node-b.catofes."]
	if !peer.DiscoveredEndpoint.Set || peer.DiscoveredEndpoint.Value != "203.0.113.10:33434" {
		t.Fatalf("planned discovered endpoint = %+v", peer.DiscoveredEndpoint)
	}
	if !peer.ObservedEndpoint.Set || peer.ObservedEndpoint.Value != "" || !peer.ObservedUntilUnix.Set || peer.ObservedUntilUnix.Value != 0 {
		t.Fatalf("expired observed path was not cleared: %+v", peer)
	}

	foundKnown := slices.Contains(plan.KnownPeerIDs, "node-b.catofes.")
	if !foundKnown {
		t.Fatal("verified node-b was not included in known-peer plan")
	}

	transport := &gossip.Transport{}
	if addr := transport.PeerAddr("node-b.catofes."); addr != nil {
		t.Fatalf("transport changed before plan commit/apply: %v", addr)
	}
	corehost.ApplyGossipDiscoveryPlan(transport, plan)
	if addr := transport.PeerAddr("node-b.catofes."); addr == nil || addr.String() != "203.0.113.10:33434" {
		t.Fatalf("transport address after apply = %v", addr)
	}
	if addr := transport.ObservedPeerAddr("node-b.catofes."); addr != nil {
		t.Fatalf("expired observed address remained after apply: %v", addr)
	}
}

func testDaemonGossipDiscoveryInput(state *stateFile, config *syncConfigFile) corehost.GossipDiscoveryInput {
	checkpoint, _ := projectLegacyGossipCheckpoint(state.SyncPeers)
	return daemonGossipDiscoveryInput(corestate.View{State: &corestate.VerifiedState{
		ManagedZone: state.ManagedZone,
		Network:     state.Network,
	}, Gossip: checkpoint}, state.PeerCleanups, config)
}

func TestPlanDaemonDiscoveredPeersNoStateChangeStillRepairsTransport(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(time.Now().Unix(), 0)
	putSignedEndpointRecord(t, state, "203.0.113.10", 33434, now, 1)
	state.SyncPeers = map[string]syncPeerState{
		"node-b.catofes.": {
			DiscoveredAddr:     "203.0.113.10:33434",
			DiscoveredAtUnix:   now.Unix(),
			ObservedAddr:       "198.51.100.20:33434",
			ObservedUntilUnix:  now.Add(time.Minute).Unix(),
			ObservedGraceAddrs: []observedGraceAddrState{{Addr: "expired:33434", UntilUnix: now.Add(-time.Minute).Unix()}, {Addr: "198.51.100.21:33434", UntilUnix: now.Add(time.Minute).Unix()}},
		},
	}
	plan := corehost.PlanGossipDiscovery(testDaemonGossipDiscoveryInput(state, config), now)
	updates := plan.Patches
	if len(updates) != 0 {
		t.Fatalf("unchanged peer produced state updates: %+v", updates)
	}
	original := state.SyncPeers["node-b.catofes."]
	if len(original.ObservedGraceAddrs) != 2 ||
		original.ObservedGraceAddrs[0].Addr != "expired:33434" ||
		original.ObservedGraceAddrs[1].Addr != "198.51.100.21:33434" {
		t.Fatalf("planning compacted committed grace paths: %+v", original.ObservedGraceAddrs)
	}
	transport := &gossip.Transport{}
	corehost.ApplyGossipDiscoveryPlan(transport, plan)
	if addr := transport.PeerAddr("node-b.catofes."); addr == nil || addr.String() != "203.0.113.10:33434" {
		t.Fatalf("no-op state plan did not repair transport: %v", addr)
	}
	if paths := transport.ObservedPeerAddrs("node-b.catofes."); len(paths) != 2 {
		t.Fatalf("observed transport paths = %v, want current plus valid grace", paths)
	}
}

func TestPlanDaemonDiscoveredPeersRepairsConfiguredBootstrapWithoutZone(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(time.Now().Unix(), 0)
	peerID := "bootstrap.example."
	config.Bootstrap = []syncConfigPeer{{ID: peerID, Addr: "127.0.0.1:33434"}}
	plan := corehost.PlanGossipDiscovery(testDaemonGossipDiscoveryInput(state, config), now)
	updates := plan.Patches
	if len(updates) != 0 {
		t.Fatalf("configured bootstrap produced state updates: %+v", updates)
	}
	transport := &gossip.Transport{}
	corehost.ApplyGossipDiscoveryPlan(transport, plan)
	if addr := transport.PeerAddr(peerID); addr == nil || addr.String() != "127.0.0.1:33434" {
		t.Fatalf("configured bootstrap address after repair = %v", addr)
	}
}

func TestPlanDaemonDiscoveredPeersKeepsLifecycleCleanedCacheAbsent(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(time.Now().Unix(), 0)
	putSignedEndpointRecord(t, state, "203.0.113.10", 33434, now, 1)
	state.PeerCleanups = map[string]peerLifecycleCleanupState{
		"node-b.catofes.": {CleanupUnix: now.Unix(), Reason: peerCleanupReasonOffline},
	}

	plan := corehost.PlanGossipDiscovery(testDaemonGossipDiscoveryInput(state, config), now)
	updates := plan.Patches
	if _, ok := updates["node-b.catofes."]; ok {
		t.Fatalf("lifecycle-cleaned peer cache was recreated: %+v", updates)
	}
	transport := &gossip.Transport{}
	corehost.ApplyGossipDiscoveryPlan(transport, plan)
	if addr := transport.PeerAddr("node-b.catofes."); addr == nil || addr.String() != "203.0.113.10:33434" {
		t.Fatalf("lifecycle-cleaned peer is not dialable for recovery: %v", addr)
	}
}

func TestDaemonUpdateDiscoveredPeersCommitsThenRepairsTransportWithoutNoopRevision(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(time.Now().Unix(), 0)
	putSignedEndpointRecord(t, state, "203.0.113.10", 33434, now, 1)
	rt := &Runtime{
		Config:    defaultAppConfig(),
		StatePath: filepath.Join(t.TempDir(), "state.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState(initial): %v", err)
	}
	service := newTestDaemonService(rt, state, config, time.Second)
	transport := &gossip.Transport{}
	service.Sync.Transport = transport

	before := service.StateStore.Meta().Revision
	service.updateDiscoveredPeers()
	after := service.StateStore.Meta().Revision
	if after != before {
		t.Fatalf("discovery changed verified revision: before=%d after=%d", before, after)
	}
	if addr := transport.PeerAddr("node-b.catofes."); addr == nil || addr.String() != "203.0.113.10:33434" {
		t.Fatalf("transport address = %v", addr)
	}
	if got := service.currentState().SyncPeers["node-b.catofes."].DiscoveredAddr; got != "203.0.113.10:33434" {
		t.Fatalf("committed DiscoveredAddr = %q", got)
	}
	transport.RemovePeerAddrs("node-b.catofes.")
	service.updateDiscoveredPeers()
	if got := service.StateStore.Meta().Revision; got != after {
		t.Fatalf("no-op discovery changed revision: before=%d after=%d", after, got)
	}
	if addr := transport.PeerAddr("node-b.catofes."); addr == nil || addr.String() != "203.0.113.10:33434" {
		t.Fatalf("no-op discovery did not repair transport: %v", addr)
	}
}
