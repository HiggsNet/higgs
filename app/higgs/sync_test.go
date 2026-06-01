package main

import (
	"crypto/ed25519"
	"net"
	"testing"
	"time"

	"github.com/Catofes/higgs/pkg/core/gossip"
	"github.com/Catofes/higgs/pkg/core/zone"
	higgscrypto "github.com/Catofes/higgs/pkg/crypto"
)

func TestShouldRelayToPeer(t *testing.T) {
	now := time.Unix(100, 0)
	tests := []struct {
		name    string
		state   syncPeerState
		peerID  string
		source  string
		allowed bool
		reason  string
	}{
		{
			name:   "empty peer",
			peerID: "",
			source: "node-a",
			reason: "empty_peer_id",
		},
		{
			name:   "source peer",
			peerID: "node-a",
			source: "node-a",
			reason: "source_peer",
		},
		{
			name:   "backoff",
			state:  syncPeerState{BackoffUntilUnix: now.Add(time.Second).Unix()},
			peerID: "node-b",
			source: "node-a",
			reason: "backoff",
		},
		{
			name:   "throttled",
			state:  syncPeerState{LastRelayUnix: now.Unix()},
			peerID: "node-b",
			source: "node-a",
			reason: "relay_throttled",
		},
		{
			name:    "allowed",
			state:   syncPeerState{LastRelayUnix: now.Add(-relayMinInterval).Unix()},
			peerID:  "node-b",
			source:  "node-a",
			allowed: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowed, reason := shouldRelayToPeer(tt.state, tt.peerID, tt.source, now)
			if allowed != tt.allowed || reason != tt.reason {
				t.Fatalf("shouldRelayToPeer() = %v, %q; want %v, %q", allowed, reason, tt.allowed, tt.reason)
			}
		})
	}
}

func TestRecordRelaySuppression(t *testing.T) {
	state := &stateFile{}
	now := time.Unix(100, 0)

	recordRelaySuppression(state, "node-b", "relay_throttled", now)

	peerState := state.SyncPeers["node-b"]
	if peerState.LastRelaySuppression != "relay_throttled" {
		t.Fatalf("LastRelaySuppression = %q, want relay_throttled", peerState.LastRelaySuppression)
	}
	if peerState.LastRelaySuppressedAt != now.Unix() {
		t.Fatalf("LastRelaySuppressedAt = %d, want %d", peerState.LastRelaySuppressedAt, now.Unix())
	}
}

func TestRecordRelaySuccess(t *testing.T) {
	state := &stateFile{
		SyncPeers: map[string]syncPeerState{
			"node-b": {LastRelaySuppression: "relay_throttled", LastRelaySuppressedAt: 99},
		},
	}
	now := time.Unix(100, 0)

	recordRelaySuccess(state, "node-b", "node-a", now)

	peerState := state.SyncPeers["node-b"]
	if peerState.LastRelayUnix != now.Unix() {
		t.Fatalf("LastRelayUnix = %d, want %d", peerState.LastRelayUnix, now.Unix())
	}
	if peerState.LastUpdateSource != "node-a" {
		t.Fatalf("LastUpdateSource = %q, want node-a", peerState.LastUpdateSource)
	}
	if peerState.LastRelaySuppression != "" || peerState.LastRelaySuppressedAt != 0 {
		t.Fatalf("relay suppression was not cleared: %#v", peerState)
	}
}

func buildTestNetworkState(t *testing.T) (*stateFile, *syncConfigFile) {
	t.Helper()

	rootPub, rootPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(root): %v", err)
	}
	catofesPub, catofesPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(catofes): %v", err)
	}
	nodeBPub, nodeBPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(node-b): %v", err)
	}

	rootAuthority := &zone.ZoneAuthority{
		Zone:      zone.RootZone,
		Epoch:     1,
		Threshold: 1,
		Keys: []zone.AuthorizedKey{{
			Key: rootPub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermDelegate},
			}},
		}},
	}
	catofesAuthority := &zone.ZoneAuthority{
		Zone:      "catofes.",
		Epoch:     1,
		Threshold: 1,
		Keys: []zone.AuthorizedKey{{
			Key: catofesPub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermDelegate},
			}},
		}},
	}
	nodeBAuthority := &zone.ZoneAuthority{
		Zone:      "node-b.catofes.",
		Epoch:     1,
		Threshold: 1,
		Keys: []zone.AuthorizedKey{{
			Key: nodeBPub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermWrite},
			}},
		}},
	}

	catofesDelegation := &zone.Delegation{
		ZoneName:  "catofes.",
		Scope:     zone.DelegationScopeDirectChild,
		Authority: *catofesAuthority,
	}
	if err := higgscrypto.SignDelegation(catofesDelegation, zone.RootZone, rootPriv); err != nil {
		t.Fatalf("SignDelegation(catofes): %v", err)
	}

	nodeBDelegation := &zone.Delegation{
		ZoneName:  "node-b.catofes.",
		Scope:     zone.DelegationScopeDirectChild,
		Authority: *nodeBAuthority,
	}
	if err := higgscrypto.SignDelegation(nodeBDelegation, "catofes.", catofesPriv); err != nil {
		t.Fatalf("SignDelegation(node-b): %v", err)
	}

	ns := zone.NewNetworkState()
	ns.Zones[zone.RootZone] = zone.NewZoneState(zone.RootZone, rootAuthority)
	ns.Zones["catofes."] = zone.NewZoneState("catofes.", catofesAuthority)
	ns.Zones["node-b.catofes."] = zone.NewZoneState("node-b.catofes.", nodeBAuthority)
	ns.Zones[zone.RootZone].Delegations["catofes."] = catofesDelegation
	ns.Zones["catofes."].Delegations["node-b.catofes."] = nodeBDelegation

	configureValidation(ns)

	now := time.Unix(123, 0)
	if err := higgscrypto.VerifyChain(ns, "catofes.", now); err != nil {
		t.Fatalf("VerifyChain(catofes): %v", err)
	}
	if err := higgscrypto.VerifyChain(ns, "node-b.catofes.", now); err != nil {
		t.Fatalf("VerifyChain(node-b): %v", err)
	}

	state := &stateFile{
		ManagedZone:    "node-a.catofes.",
		Network:        ns,
		ZonePrivateKey: nodeBPriv,
	}
	config := &syncConfigFile{
		PeerID:     "node-a.catofes.",
		ListenAddr: "127.0.0.1:0",
	}
	return state, config
}

func TestOpenSyncTransportAddsVerifiedZones(t *testing.T) {
	state, config := buildTestNetworkState(t)

	transport, err := openSyncTransport(config, state)
	if err != nil {
		t.Fatalf("openSyncTransport: %v", err)
	}
	defer transport.Close()

	found := false
	for _, id := range transport.KnownPeerIDs() {
		if id == "node-b.catofes." {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("KnownPeerIDs() does not contain node-b.catofes.")
	}

	if transport.PeerAddr("node-b.catofes.") != nil {
		t.Fatalf("PeerAddr(node-b.catofes.) should be nil when no endpoint record exists")
	}
}

func TestUpdateDiscoveredPeersAddsAddrsForEndpoints(t *testing.T) {
	state, config := buildTestNetworkState(t)

	transport, err := openSyncTransport(config, state)
	if err != nil {
		t.Fatalf("openSyncTransport: %v", err)
	}
	defer transport.Close()

	// node-b has no endpoint record yet
	if transport.PeerAddr("node-b.catofes.") != nil {
		t.Fatalf("PeerAddr(node-b.catofes.) should be nil before update")
	}

	// Add endpoint record for node-b
	endpoints := []gossip.LocalEndpoint{
		{IP: net.ParseIP("127.0.0.1"), Port: 9999, Scope: "global", Priority: 100, Source: gossip.SourceAdvertise},
	}
	value := gossip.EndpointRecordBytes(endpoints, time.Now())
	record := &zone.Record{
		Zone:      "node-b.catofes.",
		Key:       gossip.EndpointRecordKeyUDP,
		Type:      "sync.endpoint",
		Value:     value,
		Version:   1,
		Timestamp: time.Now().Unix(),
	}
	if err := higgscrypto.SignRecord(record, state.ZonePrivateKey); err != nil {
		t.Fatalf("SignRecord: %v", err)
	}
	if err := state.Network.Put(record); err != nil {
		t.Fatalf("Put: %v", err)
	}

	updateDiscoveredPeers(state, transport, config)

	addr := transport.PeerAddr("node-b.catofes.")
	if addr == nil {
		t.Fatalf("PeerAddr(node-b.catofes.) should not be nil after update")
	}
	if addr.IP.String() != "127.0.0.1" || addr.Port != 9999 {
		t.Fatalf("PeerAddr = %s, want 127.0.0.1:9999", addr.String())
	}
}
