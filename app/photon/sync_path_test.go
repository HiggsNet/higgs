package main

import (
	"errors"
	"github.com/HiggsNet/photon/pkg/core/gossip"
	"net"
	"testing"
	"time"
)

func TestRecordVerifiedObservedPathRequiresVerifiedPeer(t *testing.T) {
	state, _ := buildTestNetworkState(t)
	now := time.Unix(1000, 0)

	recordVerifiedObservedPath(state, "node-b.catofes.", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 2000}, gossip.MessagePing, now)

	peerState := state.SyncPeers["node-b.catofes."]
	if peerState.ObservedAddr != "127.0.0.1:2000" {
		t.Fatalf("ObservedAddr = %q, want 127.0.0.1:2000", peerState.ObservedAddr)
	}
	if peerState.ObservedFirstSeenUnix != now.Unix() || peerState.ObservedLastSeenUnix != now.Unix() {
		t.Fatalf("observed timestamps = first %d last %d, want %d", peerState.ObservedFirstSeenUnix, peerState.ObservedLastSeenUnix, now.Unix())
	}
	if peerState.ObservedUntilUnix != now.Add(observedPathTTL).Unix() {
		t.Fatalf("ObservedUntilUnix = %d, want %d", peerState.ObservedUntilUnix, now.Add(observedPathTTL).Unix())
	}
	if peerState.ObservedSource != string(gossip.MessagePing) {
		t.Fatalf("ObservedSource = %q, want %q", peerState.ObservedSource, gossip.MessagePing)
	}

	recordVerifiedObservedPath(state, "unknown.catofes.", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 3000}, gossip.MessagePing, now)
	if got := state.SyncPeers["unknown.catofes."].ObservedAddr; got != "" {
		t.Fatalf("unverified peer observed addr = %q, want empty", got)
	}
}

func TestRecordVerifiedObservedPathMigratesNewSource(t *testing.T) {
	state, _ := buildTestNetworkState(t)
	now := time.Now()

	recordVerifiedObservedPath(state, "node-b.catofes.", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 2000}, gossip.MessagePing, now)
	recordVerifiedObservedPath(state, "node-b.catofes.", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 3000}, gossip.MessagePong, now.Add(time.Second))

	peerState := state.SyncPeers["node-b.catofes."]
	if peerState.ObservedAddr != "127.0.0.1:3000" {
		t.Fatalf("ObservedAddr after migration = %q, want 127.0.0.1:3000", peerState.ObservedAddr)
	}
	if peerState.ObservedFirstSeenUnix != now.Add(time.Second).Unix() {
		t.Fatalf("ObservedFirstSeenUnix = %d, want migrated timestamp %d", peerState.ObservedFirstSeenUnix, now.Add(time.Second).Unix())
	}
	if peerState.ObservedSource != string(gossip.MessagePong) {
		t.Fatalf("ObservedSource = %q, want %q", peerState.ObservedSource, gossip.MessagePong)
	}
	if len(peerState.ObservedGraceAddrs) != 1 {
		t.Fatalf("ObservedGraceAddrs = %#v, want previous address retained", peerState.ObservedGraceAddrs)
	}
	if peerState.ObservedGraceAddrs[0].Addr != "127.0.0.1:2000" {
		t.Fatalf("ObservedGraceAddrs[0].Addr = %q, want old address", peerState.ObservedGraceAddrs[0].Addr)
	}
	if peerState.ObservedGraceAddrs[0].UntilUnix != now.Add(time.Second).Add(observedPathMigrationGrace).Unix() {
		t.Fatalf("ObservedGraceAddrs[0].UntilUnix = %d, want migration grace", peerState.ObservedGraceAddrs[0].UntilUnix)
	}
	transport := &gossip.Transport{}
	rt := &Runtime{Clock: func() time.Time { return now.Add(2 * time.Second) }}
	sr := newSyncRuntime(&syncConfigFile{PeerID: "node-a.catofes."}, transport, rt)
	sr.seedObservedPeerPathAt(state, "node-b.catofes.", sr.now())
	if got := transport.ObservedPeerAddrs("node-b.catofes."); len(got) != 2 || got[0].String() != "127.0.0.1:3000" || got[1].String() != "127.0.0.1:2000" {
		t.Fatalf("ObservedPeerAddrs after migration = %v, want new addr plus grace old addr", got)
	}

	rt.Clock = func() time.Time { return now.Add(2*time.Second + observedPathMigrationGrace) }
	sr.seedObservedPeerPathAt(state, "node-b.catofes.", sr.now())
	if got := transport.ObservedPeerAddrs("node-b.catofes."); len(got) != 1 || got[0].String() != "127.0.0.1:3000" {
		t.Fatalf("ObservedPeerAddrs after grace expiry = %v, want only new addr", got)
	}
}

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
	sr := newSyncRuntime(config, transport, &Runtime{Clock: func() time.Time { return now }})

	sr.seedObservedPeerPathAt(state, peerID, sr.now())

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

	peers := outboundSyncPeersAt(state, config, now)
	if len(peers) != 1 || peers[0] != "node-b.catofes." {
		t.Fatalf("outboundSyncPeers = %v, want node-b.catofes.", peers)
	}

	transport := &gossip.Transport{}
	rt := &Runtime{Clock: func() time.Time { return now }}
	sr := newSyncRuntime(config, transport, rt)
	sr.seedObservedPeerPathAt(state, "node-b.catofes.", sr.now())

	if addr := transport.ObservedPeerAddr("node-b.catofes."); addr == nil || addr.String() != "127.0.0.1:2000" {
		t.Fatalf("ObservedPeerAddr = %v, want 127.0.0.1:2000", addr)
	}

	now = now.Add(2 * time.Minute)
	if peers := outboundSyncPeersAt(state, config, now); len(peers) != 0 {
		t.Fatalf("outboundSyncPeers after observed expiry = %v, want empty", peers)
	}
	sr.seedObservedPeerPathAt(state, "node-b.catofes.", sr.now())
	if addr := transport.ObservedPeerAddr("node-b.catofes."); addr != nil {
		t.Fatalf("ObservedPeerAddr after expiry = %v, want nil", addr)
	}
}

func TestObservedPathPreferenceAndFailureCount(t *testing.T) {
	now := time.Unix(1000, 0)
	peerState := syncPeerState{
		DiscoveredAddr:    "127.0.0.1:9999",
		ObservedAddr:      "127.0.0.1:2000",
		ObservedUntilUnix: now.Add(time.Minute).Unix(),
	}
	if observedPathPreferFirst(peerState, now) {
		t.Fatalf("observedPathPreferFirst should prefer direct endpoint before failure")
	}
	peerState.LastError = "sync once timed out"
	if !observedPathPreferFirst(peerState, now) {
		t.Fatalf("observedPathPreferFirst should prefer observed path after failure")
	}
	peerState.LastError = ""
	peerState.DiscoveredAddr = "10.16.255.8:33435"
	if !observedPathPreferFirst(peerState, now) {
		t.Fatalf("observedPathPreferFirst should prefer observed path over private discovered endpoint")
	}

	peerState.ObservedFailureCount = 1
	state := &stateFile{SyncPeers: map[string]syncPeerState{"node-b": peerState}}
	recordPeerSyncAt(state, "node-b", nil, now)
	if got := state.SyncPeers["node-b"].ObservedFailureCount; got != 0 {
		t.Fatalf("ObservedFailureCount after success = %d, want 0", got)
	}
}

func TestRecordPeerSyncAtUsesInjectedTime(t *testing.T) {
	state := &stateFile{}
	now := time.Unix(1000, 0)

	recordPeerSyncAt(state, "node-b", errors.New("dial failed"), now)

	peerState := state.SyncPeers["node-b"]
	if peerState.LastAttemptUnix != now.Unix() {
		t.Fatalf("LastAttemptUnix = %d, want %d", peerState.LastAttemptUnix, now.Unix())
	}
	if peerState.BackoffUntilUnix != now.Add(2*time.Second).Unix() {
		t.Fatalf("BackoffUntilUnix = %d, want %d", peerState.BackoffUntilUnix, now.Add(2*time.Second).Unix())
	}

	recoveredAt := now.Add(time.Minute)
	recordPeerSyncAt(state, "node-b", nil, recoveredAt)
	peerState = state.SyncPeers["node-b"]
	if peerState.LastSyncUnix != recoveredAt.Unix() {
		t.Fatalf("LastSyncUnix = %d, want %d", peerState.LastSyncUnix, recoveredAt.Unix())
	}
}
