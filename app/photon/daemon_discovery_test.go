package main

import (
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/Catofes/photon/pkg/core/gossip"
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
			ObservedSource:        string(gossip.MessagePing),
		},
	}
	view := syncPeerMutationView{
		ManagedZone: state.ManagedZone,
		Network:     state.Network,
		SyncPeers:   state.SyncPeers,
	}

	updates, plan := planDaemonDiscoveredPeers(view, config, now)

	// Planning must not mutate either state or transport.
	original := state.SyncPeers["node-b.catofes."]
	if original.DiscoveredAddr != "" || original.ObservedAddr == "" {
		t.Fatalf("planning mutated source peer: %+v", original)
	}
	peer := updates["node-b.catofes."]
	if peer.DiscoveredAddr != "203.0.113.10:33434" {
		t.Fatalf("planned DiscoveredAddr = %q", peer.DiscoveredAddr)
	}
	if peer.ObservedAddr != "" || peer.ObservedUntilUnix != 0 {
		t.Fatalf("expired observed path was not cleared: %+v", peer)
	}

	foundKnown := slices.Contains(plan.knownPeerIDs, "node-b.catofes.")
	if !foundKnown {
		t.Fatal("verified node-b was not included in known-peer plan")
	}

	transport := &gossip.Transport{}
	if addr := transport.PeerAddr("node-b.catofes."); addr != nil {
		t.Fatalf("transport changed before plan commit/apply: %v", addr)
	}
	applyDaemonDiscoveryPlan(transport, plan)
	if addr := transport.PeerAddr("node-b.catofes."); addr == nil || addr.String() != "203.0.113.10:33434" {
		t.Fatalf("transport address after apply = %v", addr)
	}
	if addr := transport.ObservedPeerAddr("node-b.catofes."); addr != nil {
		t.Fatalf("expired observed address remained after apply: %v", addr)
	}
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
	view := syncPeerMutationView{
		ManagedZone: state.ManagedZone,
		Network:     state.Network,
		SyncPeers:   state.SyncPeers,
	}

	updates, plan := planDaemonDiscoveredPeers(view, config, now)
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
	applyDaemonDiscoveryPlan(transport, plan)
	if addr := transport.PeerAddr("node-b.catofes."); addr == nil || addr.String() != "203.0.113.10:33434" {
		t.Fatalf("no-op state plan did not repair transport: %v", addr)
	}
	if paths := transport.ObservedPeerAddrs("node-b.catofes."); len(paths) != 2 {
		t.Fatalf("observed transport paths = %v, want current plus valid grace", paths)
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
	service := newDaemonService(rt, state, config, time.Second)
	transport := &gossip.Transport{}
	service.Sync.Transport = transport

	before := service.StateStore.Meta().Revision
	service.updateDiscoveredPeers()
	after := service.StateStore.Meta().Revision
	if after != before+1 {
		t.Fatalf("discovery revision = %d, want %d", after, before+1)
	}
	if addr := transport.PeerAddr("node-b.catofes."); addr == nil || addr.String() != "203.0.113.10:33434" {
		t.Fatalf("transport address = %v", addr)
	}
	if got := service.currentState().SyncPeers["node-b.catofes."].DiscoveredAddr; got != "203.0.113.10:33434" {
		t.Fatalf("committed DiscoveredAddr = %q", got)
	}
	persisted, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if got := persisted.SyncPeers["node-b.catofes."].DiscoveredAddr; got != "203.0.113.10:33434" {
		t.Fatalf("persisted DiscoveredAddr = %q", got)
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
