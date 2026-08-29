package main

import (
	"errors"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corehost "github.com/HiggsNet/photon/pkg/core/host"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
)

func TestSeedObservedPeerPathDoesNotCompactStateGraceSlice(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Now()
	peerID := "node-b.catofes."
	if state.SyncPeers == nil {
		state.SyncPeers = make(map[string]syncPeerState)
	}
	state.SyncPeers[peerID] = syncPeerState{
		ObservedAddr:      "127.0.0.1:3000",
		ObservedUntilUnix: now.Add(time.Minute).Unix(),
		ObservedGraceAddrs: []observedGraceAddrState{
			{Addr: "127.0.0.1:1000", UntilUnix: now.Add(-time.Second).Unix()},
			{Addr: "127.0.0.1:2000", UntilUnix: now.Add(time.Minute).Unix()},
		},
	}
	transport := &gossip.Transport{}
	service := newTestDaemonService(&Runtime{Clock: func() time.Time { return now }}, state, config, defaultDaemonInterval)
	service.Sync.Transport = transport
	service.updateDiscoveredPeers()

	grace := state.SyncPeers[peerID].ObservedGraceAddrs
	if len(grace) != 2 || grace[0].Addr != "127.0.0.1:1000" || grace[1].Addr != "127.0.0.1:2000" {
		t.Fatalf("state grace paths were compacted in place: %+v", grace)
	}
	if got := transport.ObservedPeerAddrs(peerID); len(got) != 2 || got[0].String() != "127.0.0.1:3000" || got[1].String() != "127.0.0.1:2000" {
		t.Fatalf("transport observed paths = %v, want active plus unexpired grace", got)
	}
}

func TestObservedPathParticipatesInOutboundPeersAndTransport(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Now()
	state.SyncPeers = map[string]syncPeerState{
		"node-b.catofes.": {
			ObservedAddr:          "127.0.0.1:2000",
			ObservedFirstSeenUnix: now.Unix(),
			ObservedLastSeenUnix:  now.Unix(),
			ObservedUntilUnix:     now.Add(time.Minute).Unix(),
			LastError:             "sync once timed out",
		},
	}

	service := newTestDaemonService(&Runtime{Clock: func() time.Time { return now }}, state, config, defaultDaemonInterval)
	peers := corehost.GossipOutboundPeers(service.hostRuntime.GossipDiscoveryInput(service.currentGossipSuppressions()), now)
	if len(peers) != 1 || peers[0] != "node-b.catofes." {
		t.Fatalf("outboundSyncPeers = %v, want node-b.catofes.", peers)
	}

	transport := &gossip.Transport{}
	service.Sync.Transport = transport
	service.updateDiscoveredPeers()

	if addr := transport.ObservedPeerAddr("node-b.catofes."); addr == nil || addr.String() != "127.0.0.1:2000" {
		t.Fatalf("ObservedPeerAddr = %v, want 127.0.0.1:2000", addr)
	}

	now = now.Add(2 * time.Minute)
	if peers := corehost.GossipOutboundPeers(service.hostRuntime.GossipDiscoveryInput(service.currentGossipSuppressions()), now); len(peers) != 0 {
		t.Fatalf("outboundSyncPeers after observed expiry = %v, want empty", peers)
	}
	service.updateDiscoveredPeers()
	if addr := transport.ObservedPeerAddr("node-b.catofes."); addr != nil {
		t.Fatalf("ObservedPeerAddr after expiry = %v, want nil", addr)
	}
}

func TestObservedPathPreferenceAndFailureCount(t *testing.T) {
	now := time.Unix(1000, 0)
	state, config := buildTestNetworkState(t)
	state.SyncPeers = map[string]syncPeerState{"node-b.catofes.": {
		DiscoveredAddr:    "127.0.0.1:9999",
		ObservedAddr:      "127.0.0.1:2000",
		ObservedUntilUnix: now.Add(time.Minute).Unix(),
	}}
	service := newTestDaemonService(&Runtime{Clock: func() time.Time { return now }}, state, config, defaultDaemonInterval)
	input := service.hostRuntime.GossipDiscoveryInput(service.currentGossipSuppressions())
	if corehost.PlanGossipDiscovery(input, now).Peers["node-b.catofes."].PreferObserved {
		t.Fatalf("observedPathPreferFirst should prefer direct endpoint before failure")
	}
	peer := input.Peers["node-b.catofes."]
	peer.LastFailure = &corestate.PeerFailure{Code: corestate.PeerFailureTimeout, Message: "sync once timed out", AtUnix: now.Unix()}
	input.Peers["node-b.catofes."] = peer
	if !corehost.PlanGossipDiscovery(input, now).Peers["node-b.catofes."].PreferObserved {
		t.Fatalf("observedPathPreferFirst should prefer observed path after failure")
	}
	peer.LastFailure = nil
	peer.DiscoveredEndpoint = "10.16.255.8:33435"
	input.Peers["node-b.catofes."] = peer
	if !corehost.PlanGossipDiscovery(input, now).Peers["node-b.catofes."].PreferObserved {
		t.Fatalf("observedPathPreferFirst should prefer observed path over private discovered endpoint")
	}

	peer.ObservedFailureCount = 1
	recordPeerSyncCheckpoint(&peer, nil, now)
	if got := peer.ObservedFailureCount; got != 0 {
		t.Fatalf("ObservedFailureCount after success = %d, want 0", got)
	}
}

func TestRecordPeerSyncAtUsesInjectedTime(t *testing.T) {
	peer := corestate.PeerCheckpoint{}
	now := time.Unix(1000, 0)

	recordPeerSyncCheckpoint(&peer, errors.New("dial failed"), now)

	if peer.LastAttemptUnix != now.Unix() {
		t.Fatalf("LastAttemptUnix = %d, want %d", peer.LastAttemptUnix, now.Unix())
	}
	if peer.BackoffUntilUnix != now.Add(2*time.Second).Unix() {
		t.Fatalf("BackoffUntilUnix = %d, want %d", peer.BackoffUntilUnix, now.Add(2*time.Second).Unix())
	}

	recoveredAt := now.Add(time.Minute)
	recordPeerSyncCheckpoint(&peer, nil, recoveredAt)
	if peer.LastSyncUnix != recoveredAt.Unix() {
		t.Fatalf("LastSyncUnix = %d, want %d", peer.LastSyncUnix, recoveredAt.Unix())
	}
}
