package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Catofes/higgs/pkg/core/gossip"
	"github.com/Catofes/higgs/pkg/core/zone"
	higgscrypto "github.com/Catofes/higgs/pkg/crypto"
	"github.com/Catofes/higgs/pkg/transport/ipsec"
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

func TestRecordPeerSyncBackoffAndRecovery(t *testing.T) {
	state := &stateFile{}

	recordPeerSync(state, "node-b", errors.New("dial failed"))
	failed := state.SyncPeers["node-b"]
	if failed.FailureCount != 1 {
		t.Fatalf("FailureCount after failure = %d, want 1", failed.FailureCount)
	}
	if failed.LastError != "dial failed" {
		t.Fatalf("LastError = %q, want dial failed", failed.LastError)
	}
	if failed.BackoffUntilUnix == 0 {
		t.Fatalf("BackoffUntilUnix was not set")
	}

	recordPeerSync(state, "node-b", nil)
	recovered := state.SyncPeers["node-b"]
	if recovered.FailureCount != 0 || recovered.LastError != "" || recovered.BackoffUntilUnix != 0 {
		t.Fatalf("peer did not recover cleanly: %#v", recovered)
	}
	if recovered.LastSyncUnix == 0 {
		t.Fatalf("LastSyncUnix was not set on recovery")
	}

	lastSuccess := recovered.LastSyncUnix
	recordPeerSync(state, "node-b", errors.New("sync receive timed out"))
	failedAgain := state.SyncPeers["node-b"]
	if failedAgain.LastSyncUnix != lastSuccess {
		t.Fatalf("LastSyncUnix after later failure = %d, want previous %d", failedAgain.LastSyncUnix, lastSuccess)
	}
	if got := formatLastSuccess(failedAgain); got == "never" {
		t.Fatalf("formatLastSuccess after later failure = %q, want previous success timestamp", got)
	}
}

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
	sr := newSyncRuntime(state, &syncConfigFile{PeerID: "node-a.catofes."}, transport, rt)
	sr.seedObservedPeerPath("node-b.catofes.")
	if got := transport.ObservedPeerAddrs("node-b.catofes."); len(got) != 2 || got[0].String() != "127.0.0.1:3000" || got[1].String() != "127.0.0.1:2000" {
		t.Fatalf("ObservedPeerAddrs after migration = %v, want new addr plus grace old addr", got)
	}

	rt.Clock = func() time.Time { return now.Add(2*time.Second + observedPathMigrationGrace) }
	sr.seedObservedPeerPath("node-b.catofes.")
	if got := transport.ObservedPeerAddrs("node-b.catofes."); len(got) != 1 || got[0].String() != "127.0.0.1:3000" {
		t.Fatalf("ObservedPeerAddrs after grace expiry = %v, want only new addr", got)
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
	sr := newSyncRuntime(state, config, transport, rt)
	sr.seedObservedPeerPath("node-b.catofes.")

	if addr := transport.ObservedPeerAddr("node-b.catofes."); addr == nil || addr.String() != "127.0.0.1:2000" {
		t.Fatalf("ObservedPeerAddr = %v, want 127.0.0.1:2000", addr)
	}

	now = now.Add(2 * time.Minute)
	if peers := outboundSyncPeersAt(state, config, now); len(peers) != 0 {
		t.Fatalf("outboundSyncPeers after observed expiry = %v, want empty", peers)
	}
	sr.seedObservedPeerPath("node-b.catofes.")
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

	state := &stateFile{SyncPeers: map[string]syncPeerState{"node-b": peerState}}
	recordObservedPathFailure(state, "node-b")
	if got := state.SyncPeers["node-b"].ObservedFailureCount; got != 1 {
		t.Fatalf("ObservedFailureCount = %d, want 1", got)
	}
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

func TestRejectedDigestCacheSkipsSameRootWithinTTL(t *testing.T) {
	state, _ := buildTestNetworkState(t)
	now := time.Unix(1000, 0)
	digest := gossip.ZoneDigest{Zone: "node-b.catofes.", RootHash: []byte("bad-root")}

	recordRejectedDigest(state, "node-b.catofes.", digest, "verify_failed", now)

	if got := fetchListForPeer(state, "node-b.catofes.", []gossip.ZoneDigest{digest}, now.Add(time.Minute)); len(got) != 0 {
		t.Fatalf("fetchListForPeer() = %v, want skipped rejected digest", got)
	}
}

func TestRejectedDigestCacheAllowsRootChangeAndExpiry(t *testing.T) {
	state, _ := buildTestNetworkState(t)
	now := time.Unix(1000, 0)
	oldDigest := gossip.ZoneDigest{Zone: "node-b.catofes.", RootHash: []byte("bad-root")}
	newDigest := gossip.ZoneDigest{Zone: "node-b.catofes.", RootHash: []byte("new-root")}

	recordRejectedDigest(state, "node-b.catofes.", oldDigest, "verify_failed", now)

	if got := fetchListForPeer(state, "node-b.catofes.", []gossip.ZoneDigest{newDigest}, now.Add(time.Minute)); len(got) != 1 {
		t.Fatalf("fetchListForPeer(new root) = %v, want retry", got)
	}
	if got := fetchListForPeer(state, "node-b.catofes.", []gossip.ZoneDigest{oldDigest}, now.Add(rejectedDigestTTL+time.Second)); len(got) != 1 {
		t.Fatalf("fetchListForPeer(expired) = %v, want retry", got)
	}
}

func TestHandleAnnounceRecordsRejectedDigestOnVerifyFailure(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(2000, 0)
	badRecord := &zone.Record{
		Zone:      "node-b.catofes.",
		Key:       "bad",
		Type:      "policy.string",
		Value:     []byte("original"),
		Version:   1,
		Timestamp: now.Unix(),
	}
	if err := higgscrypto.SignRecord(badRecord, state.ZonePrivateKey); err != nil {
		t.Fatalf("SignRecord: %v", err)
	}
	badRecord.Value = []byte("tampered")
	digest := gossip.ZoneDigest{Zone: "node-b.catofes.", RootHash: []byte("bad-root")}
	message := &gossip.Message{
		Type:   gossip.MessageAnnounce,
		PeerID: "node-b.catofes.",
		Announce: &gossip.Announce{
			Zones: []gossip.ZoneDigest{digest},
			Snapshots: []gossip.ZoneSnapshot{{
				Zone:      "node-b.catofes.",
				Authority: state.Network.Zones["node-b.catofes."].Authority,
				Records:   map[string]*zone.Record{"bad": badRecord},
			}},
		},
	}
	sr := newSyncRuntime(state, config, nil, &Runtime{Clock: func() time.Time { return now }})

	if err := sr.handleAnnounce(message, gossip.DefaultSyncLimits()); err == nil {
		t.Fatalf("handleAnnounce succeeded, want verify failure")
	}
	if !isRejectedDigestActive(state, "node-b.catofes.", "node-b.catofes.", digest.RootHash, now.Add(time.Minute)) {
		t.Fatalf("rejected digest was not recorded")
	}
}

func TestRejectedRecordCacheSkipsSameObjectWithinTTL(t *testing.T) {
	state, _ := buildTestNetworkState(t)
	now := time.Unix(3000, 0)
	record := &zone.Record{
		Zone:      "node-b.catofes.",
		Key:       "bad-record",
		Type:      "policy.string",
		Value:     []byte("original"),
		Version:   1,
		Timestamp: now.Unix(),
	}
	if err := higgscrypto.SignRecord(record, state.ZonePrivateKey); err != nil {
		t.Fatalf("SignRecord: %v", err)
	}
	record.Value = []byte("tampered")
	snapshot := &gossip.RecordSnapshot{Zone: "node-b.catofes.", Record: record}

	recordRejectedRecord(state, "node-b.catofes.", snapshot, "verify_failed", now)

	if !isRejectedRecordActive(state, "node-b.catofes.", snapshot, "", now.Add(time.Minute)) {
		t.Fatalf("rejected record was not active")
	}
	if isRejectedRecordActive(state, "node-b.catofes.", snapshot, "", now.Add(rejectedDigestTTL+time.Second)) {
		t.Fatalf("rejected record stayed active after TTL")
	}
	changed := *record
	changed.Value = []byte("different tamper")
	if isRejectedRecordActive(state, "node-b.catofes.", &gossip.RecordSnapshot{Zone: "node-b.catofes.", Record: &changed}, "", now.Add(time.Minute)) {
		t.Fatalf("changed record hash should be retried")
	}
}

func TestRelayRejectsSourceAndBackoffToLimitStorm(t *testing.T) {
	now := time.Unix(1000, 0)
	state := &stateFile{SyncPeers: map[string]syncPeerState{
		"node-b.catofes.": {},
		"node-c.catofes.": {BackoffUntilUnix: now.Add(time.Minute).Unix()},
	}}

	if allowed, reason := shouldRelayToPeer(state.SyncPeers["node-b.catofes."], "node-b.catofes.", "node-b.catofes.", now); allowed || reason != "source_peer" {
		t.Fatalf("source relay decision = %v %q, want source_peer suppression", allowed, reason)
	}
	if allowed, reason := shouldRelayToPeer(state.SyncPeers["node-c.catofes."], "node-c.catofes.", "node-b.catofes.", now); allowed || reason != "backoff" {
		t.Fatalf("backoff relay decision = %v %q, want backoff suppression", allowed, reason)
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
		skipRestrictedSocket(t, err)
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

func TestAddVerifiedZonePeersAddsDelegatedChildWithoutZoneState(t *testing.T) {
	state, config := buildTestNetworkState(t)
	delete(state.Network.Zones, zone.ZonePath("node-b.catofes."))
	transport := &gossip.Transport{}
	sr := newSyncRuntime(state, config, transport, &Runtime{Clock: func() time.Time { return time.Unix(123, 0) }})

	sr.addVerifiedZonePeers()

	found := false
	for _, id := range transport.KnownPeerIDs() {
		if id == "node-b.catofes." {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("KnownPeerIDs() does not contain delegated node-b.catofes.")
	}
}

func TestHandlePingWithDifferentCatalogSummaryRequestsPeerCatalog(t *testing.T) {
	state, _ := buildTestNetworkState(t)
	config := &syncConfigFile{
		PeerID:          "node-b.catofes.",
		ListenAddr:      "127.0.0.1:0",
		MaxMessageBytes: gossip.DefaultDatagramBudget,
	}
	now := time.Unix(2000, 0)
	rt := &Runtime{
		StatePath: filepath.Join(t.TempDir(), "higgs.db"),
		Clock:     func() time.Time { return now },
	}

	transportA, err := gossip.Listen(gossip.Config{
		PeerID:          "node-a.catofes.",
		ListenAddr:      "127.0.0.1:0",
		MaxMessageBytes: gossip.DefaultDatagramBudget,
	})
	if err != nil {
		skipRestrictedSocket(t, err)
		t.Fatalf("Listen(A): %v", err)
	}
	defer transportA.Close()

	transportB, err := gossip.Listen(gossip.Config{
		PeerID:          config.PeerID,
		ListenAddr:      config.ListenAddr,
		MaxMessageBytes: gossip.DefaultDatagramBudget,
		KnownPeers: map[string]*net.UDPAddr{
			"node-a.catofes.": transportA.LocalAddr(),
		},
	})
	if err != nil {
		skipRestrictedSocket(t, err)
		t.Fatalf("Listen(B): %v", err)
	}
	defer transportB.Close()

	localSummary, err := gossip.CatalogSummaryFor(state.Network, gossip.DefaultDatagramBudget)
	if err != nil {
		t.Fatalf("CatalogSummaryFor: %v", err)
	}
	remoteSummary := &gossip.CatalogSummary{
		CatalogRoot: append([]byte(nil), localSummary.CatalogRoot...),
		ZoneCount:   localSummary.ZoneCount,
	}
	remoteSummary.CatalogRoot[0] ^= 0xff

	sr := newSyncRuntime(state, config, transportB, rt)
	state.Lock()
	err = sr.handlePacket(&gossip.Packet{
		Addr: transportA.LocalAddr(),
		Message: &gossip.Message{
			Type:   gossip.MessagePing,
			PeerID: "node-a.catofes.",
			Ping:   &gossip.Ping{Summary: remoteSummary},
		},
	})
	state.Unlock()
	if err != nil {
		t.Fatalf("handlePacket(Ping): %v", err)
	}

	deadline := time.Now().Add(time.Second)
	var sawFetch bool
	for time.Now().Before(deadline) {
		packet, err := receiveWithDeadline(transportA, time.Now().Add(100*time.Millisecond))
		if err != nil {
			if isReceiveTimeout(err) {
				continue
			}
			t.Fatalf("receive A: %v", err)
		}
		if packet.Message.Type == gossip.MessageFetchCatalogPage {
			sawFetch = true
			break
		}
	}
	if !sawFetch {
		t.Fatalf("B did not request A catalog after different ping summary")
	}
}

func TestHandleObjectChunkAppliesZoneSnapshot(t *testing.T) {
	prepareStatePersistence(t)
	udpChunkAssemblies = newChunkAssemblyStore()
	sourceState, _ := buildTestNetworkState(t)
	snapshot, err := gossip.Snapshot(sourceState.Network, "catofes.")
	if err != nil {
		t.Fatalf("Snapshot(catofes): %v", err)
	}
	data, err := gossip.EncodeZoneSnapshotObject(snapshot)
	if err != nil {
		t.Fatalf("EncodeZoneSnapshotObject: %v", err)
	}
	objectHash := sha256.Sum256(data)
	rootHash := gossip.ZoneRoot(sourceState.Network.Zones["catofes."])
	targetState := sourceState
	config := &syncConfigFile{PeerID: "node-a.catofes.", ListenAddr: "127.0.0.1:0"}
	delete(targetState.Network.Zones, zone.ZonePath("catofes."))
	delete(targetState.Network.Zones, zone.ZonePath("node-b.catofes."))
	if err := saveState(targetState); err != nil {
		t.Fatalf("saveState(target): %v", err)
	}
	rt, err := NewRuntime()
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	rt.Clock = func() time.Time { return time.Unix(123, 0) }
	sr := newSyncRuntime(targetState, config, nil, rt)

	chunkSize := len(data) / 2
	if chunkSize == 0 {
		t.Fatalf("encoded snapshot unexpectedly empty")
	}
	chunks := []*gossip.ObjectChunk{
		{
			Object:     gossip.ObjectPullZone,
			Zone:       "catofes.",
			RootHash:   rootHash,
			ObjectHash: objectHash[:],
			Index:      0,
			Total:      2,
			Data:       data[:chunkSize],
		},
		{
			Object:     gossip.ObjectPullZone,
			Zone:       "catofes.",
			RootHash:   rootHash,
			ObjectHash: objectHash[:],
			Index:      1,
			Total:      2,
			Data:       data[chunkSize:],
		},
	}
	for _, chunk := range []*gossip.ObjectChunk{chunks[1], chunks[0]} {
		err := sr.handleObjectChunk(&gossip.Message{
			Type:        gossip.MessageObjectChunk,
			PeerID:      "node-b.catofes.",
			ObjectChunk: chunk,
		}, gossip.DefaultSyncLimits())
		if err != nil {
			t.Fatalf("handleObjectChunk: %v", err)
		}
	}
	if targetState.Network.Zones["catofes."] == nil {
		t.Fatalf("catofes. zone was not applied from chunks")
	}
	stats := targetState.SyncPeers["node-b.catofes."].DatagramStats
	if stats == nil || stats.ChunkFallbacks == 0 {
		t.Fatalf("chunk fallback stats were not recorded: %#v", stats)
	}
}

func TestSnapshotRecordMessagesPrioritizesActiveRecord(t *testing.T) {
	snapshot := &gossip.ZoneSnapshot{
		Zone: "node-b.catofes.",
		Records: map[string]*zone.Record{
			"identity": {
				Zone:    "node-b.catofes.",
				Key:     "identity",
				Version: 2,
				Value:   []byte("node-b-restarted"),
			},
		},
		RecordHistory: map[string][]*zone.Record{
			"identity": {
				{
					Zone:    "node-b.catofes.",
					Key:     "identity",
					Version: 1,
					Value:   []byte("node-b"),
				},
			},
		},
	}

	records := snapshotRecordMessages(snapshot)
	if len(records) != 2 {
		t.Fatalf("records = %d, want 2", len(records))
	}
	if records[0].Record == nil || records[0].Record.Version != 2 || string(records[0].Record.Value) != "node-b-restarted" {
		t.Fatalf("first record = %#v, want active v2", records[0].Record)
	}
	if records[1].Record == nil || records[1].Record.Version != 1 || string(records[1].Record.Value) != "node-b" {
		t.Fatalf("second record = %#v, want history v1", records[1].Record)
	}
}

func TestSyncRuntimeTransportConfigUsesInjectedDeps(t *testing.T) {
	state, config := buildTestNetworkState(t)
	knownAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 10001}
	replay := gossip.NewReplayWindow(time.Minute)
	quotas := gossip.NewPeerQuotas(gossip.QuotaConfig{ByteRate: 1, ByteBurst: 1, ObjectRate: 1, ObjectBurst: 1})
	var logged bool
	logger := func(gossip.Event) { logged = true }
	now := time.Unix(1234, 0)
	rt := &Runtime{Clock: func() time.Time { return now }}

	syncRuntime := newSyncRuntime(state, config, nil, rt)
	syncRuntime.TransportDeps = &SyncTransportDeps{
		KnownPeers: map[string]*net.UDPAddr{"node-b.catofes.": knownAddr},
		Replay:     replay,
		Quotas:     quotas,
		Log:        logger,
	}

	transportConfig := syncRuntime.transportConfig(syncRuntime.syncTransportDeps())
	if transportConfig.KnownPeers["node-b.catofes."] != knownAddr {
		t.Fatalf("KnownPeers did not use injected map")
	}
	if transportConfig.Replay != replay {
		t.Fatalf("Replay did not use injected replay window")
	}
	if transportConfig.Quotas != quotas {
		t.Fatalf("Quotas did not use injected quotas")
	}
	transportConfig.Log(gossip.Event{})
	if !logged {
		t.Fatalf("Log did not use injected logger")
	}
	if got := transportConfig.Clock(); !got.Equal(now) {
		t.Fatalf("Clock = %s, want %s", got, now)
	}
}

func TestDefaultSyncTransportDeps(t *testing.T) {
	config := &syncConfigFile{
		PeerID:          "node-a.catofes.",
		ListenAddr:      "127.0.0.1:0",
		MaxMessageBytes: 4096,
		Bootstrap: []syncConfigPeer{{
			ID:   "node-b.catofes.",
			Addr: "127.0.0.1:10001",
		}},
	}

	deps := defaultSyncTransportDeps(config)
	if deps.Replay == nil {
		t.Fatalf("Replay is nil")
	}
	if deps.Quotas == nil {
		t.Fatalf("Quotas is nil")
	}
	if addr := deps.KnownPeers["node-b.catofes."]; addr == nil || addr.String() != "127.0.0.1:10001" {
		t.Fatalf("KnownPeers[node-b] = %v, want 127.0.0.1:10001", addr)
	}
}

func TestUpdateDiscoveredPeersAddsAddrsForEndpoints(t *testing.T) {
	state, config := buildTestNetworkState(t)

	transport, err := openSyncTransport(config, state)
	if err != nil {
		skipRestrictedSocket(t, err)
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

func TestUpdateDiscoveredPeersRanksPrivateEndpointsAfterPublic(t *testing.T) {
	state, config := buildTestNetworkState(t)
	prepareStatePersistence(t)
	transport := &gossip.Transport{}
	now := time.Now()
	endpoints := []gossip.LocalEndpoint{
		{IP: net.ParseIP("10.16.255.8"), Port: 33435, Scope: "global", Priority: 200, Source: gossip.SourceInterface},
		{IP: net.ParseIP("203.0.113.10"), Port: 33434, Scope: "global", Priority: 10, Source: gossip.SourceReflector},
	}
	record := &zone.Record{
		Zone:      "node-b.catofes.",
		Key:       gossip.EndpointRecordKeyUDP,
		Type:      "sync.endpoint",
		Value:     gossip.EndpointRecordBytes(endpoints, now),
		Version:   1,
		Timestamp: now.Unix(),
	}
	if err := higgscrypto.SignRecord(record, state.ZonePrivateKey); err != nil {
		t.Fatalf("SignRecord: %v", err)
	}
	if err := state.Network.PutAt(record, now); err != nil {
		t.Fatalf("PutAt: %v", err)
	}

	updateDiscoveredPeers(state, transport, config)

	addr := transport.PeerAddr("node-b.catofes.")
	if addr == nil || addr.String() != "203.0.113.10:33434" {
		t.Fatalf("PeerAddr = %v, want 203.0.113.10:33434", addr)
	}
	if got := state.SyncPeers["node-b.catofes."].DiscoveredAddr; got != "203.0.113.10:33434" {
		t.Fatalf("DiscoveredAddr = %q, want 203.0.113.10:33434", got)
	}
}

func TestUpdateDiscoveredPeersUpdatesEndpointAddrWithoutUDP(t *testing.T) {
	state, config := buildTestNetworkState(t)
	config.EndpointGrace = time.Nanosecond
	prepareStatePersistence(t)
	transport := &gossip.Transport{}

	now := time.Now()
	putSignedEndpointRecord(t, state, "127.0.0.1", 9999, now, 1)
	updateDiscoveredPeers(state, transport, config)
	if addr := transport.PeerAddr("node-b.catofes."); addr == nil || addr.String() != "127.0.0.1:9999" {
		t.Fatalf("PeerAddr after first update = %v, want 127.0.0.1:9999", addr)
	}

	putSignedEndpointRecord(t, state, "127.0.0.1", 10000, now.Add(time.Second), 2)
	updateDiscoveredPeers(state, transport, config)
	if addr := transport.PeerAddr("node-b.catofes."); addr == nil || addr.String() != "127.0.0.1:10000" {
		t.Fatalf("PeerAddr after endpoint change = %v, want 127.0.0.1:10000", addr)
	}
}

func TestReflectorEndpointPublishSmoke(t *testing.T) {
	state, config := buildTestNetworkState(t)
	state.ManagedZone = "node-b.catofes."
	config.PeerID = "node-b.catofes."
	config.ListenAddr = "127.0.0.1:33434"
	config.EndpointTTL = time.Hour
	config.EndpointGrace = 10 * time.Minute

	reflectorIP := "198.51.100.10"
	oldCollect := collectSyncLocalEndpoints
	collectSyncLocalEndpoints = func(port uint16, advertiseAddrs, reflectors []string, timeout time.Duration, filterPrivateIPv4 bool) ([]gossip.LocalEndpoint, error) {
		return []gossip.LocalEndpoint{{
			IP:       net.ParseIP(reflectorIP),
			Port:     port,
			Scope:    "global",
			Priority: 50,
			Source:   gossip.SourceReflector,
		}}, nil
	}
	defer func() { collectSyncLocalEndpoints = oldCollect }()
	config.Reflectors = []string{"https://reflector.example"}

	dir := t.TempDir()
	rt := &Runtime{
		Config:    defaultAppConfig(),
		StatePath: filepath.Join(dir, "higgs.db"),
		Clock:     func() time.Time { return time.Unix(1000, 0) },
	}
	sr := newSyncRuntime(state, config, nil, rt)

	if err := sr.publishEndpointRecord(); err != nil {
		t.Fatalf("publishEndpointRecord(first): %v", err)
	}
	first := endpointRecordFromState(t, state, "node-b.catofes.")
	if len(first.Endpoints) == 0 || first.Endpoints[0].Address != "198.51.100.10" {
		t.Fatalf("first endpoint record = %#v, want reflector ip", first)
	}
	if first.Endpoints[0].Source != "reflector" {
		t.Fatalf("first endpoint source = %q, want reflector", first.Endpoints[0].Source)
	}

	reflectorIP = "198.51.100.20"
	rt.Clock = func() time.Time { return time.Unix(1060, 0) }
	if err := sr.publishEndpointRecord(); err != nil {
		t.Fatalf("publishEndpointRecord(second): %v", err)
	}
	second := endpointRecordFromState(t, state, "node-b.catofes.")
	if len(second.Endpoints) < 2 {
		t.Fatalf("second endpoints = %#v, want new endpoint plus grace fallback", second.Endpoints)
	}
	if second.Endpoints[0].Address != "198.51.100.20" {
		t.Fatalf("new endpoint = %s, want 198.51.100.20", second.Endpoints[0].Address)
	}
	if second.Endpoints[1].Address != "198.51.100.10" || !strings.Contains(second.Endpoints[1].Source, "grace") {
		t.Fatalf("grace endpoint = %#v, want old reflector endpoint retained", second.Endpoints[1])
	}
}

func TestEndpointPublishSkipsWhenEndpointsUnchanged(t *testing.T) {
	state, config := buildTestNetworkState(t)
	state.ManagedZone = "node-b.catofes."
	config.PeerID = "node-b.catofes."
	config.ListenAddr = "127.0.0.1:33434"
	config.EndpointTTL = time.Hour
	config.EndpointGrace = 10 * time.Minute

	oldCollect := collectSyncLocalEndpoints
	collectSyncLocalEndpoints = func(port uint16, advertiseAddrs, reflectors []string, timeout time.Duration, filterPrivateIPv4 bool) ([]gossip.LocalEndpoint, error) {
		return []gossip.LocalEndpoint{{
			IP:       net.ParseIP("198.51.100.10"),
			Port:     port,
			Scope:    "global",
			Priority: 50,
			Source:   gossip.SourceReflector,
		}}, nil
	}
	defer func() { collectSyncLocalEndpoints = oldCollect }()
	config.Reflectors = []string{"https://reflector.example"}

	dir := t.TempDir()
	rt := &Runtime{
		Config:    defaultAppConfig(),
		StatePath: filepath.Join(dir, "higgs.db"),
		Clock:     func() time.Time { return time.Unix(1000, 0) },
	}
	sr := newSyncRuntime(state, config, nil, rt)

	if err := sr.publishEndpointRecord(); err != nil {
		t.Fatalf("publishEndpointRecord(first): %v", err)
	}
	first := state.Network.Zones["node-b.catofes."].Records[gossip.EndpointRecordKeyUDP]
	if first == nil {
		t.Fatal("first endpoint record missing")
	}
	if first.Version != 1 {
		t.Fatalf("first version = %d, want 1", first.Version)
	}

	rt.Clock = func() time.Time { return time.Unix(1300, 0) }
	if err := sr.publishEndpointRecord(); err != nil {
		t.Fatalf("publishEndpointRecord(second): %v", err)
	}
	second := state.Network.Zones["node-b.catofes."].Records[gossip.EndpointRecordKeyUDP]
	if second.Version != first.Version {
		t.Fatalf("second version = %d, want %d (unchanged)", second.Version, first.Version)
	}
}

func TestEndpointPublishDisabledClearsExistingEndpoint(t *testing.T) {
	state, config := buildTestNetworkState(t)
	state.ManagedZone = "node-b.catofes."
	config.PeerID = "node-b.catofes."
	config.DisableEndpointPublish = true
	dir := t.TempDir()
	rt := &Runtime{
		Config:    defaultAppConfig(),
		StatePath: filepath.Join(dir, "higgs.db"),
		Clock:     func() time.Time { return time.Unix(1000, 0) },
	}
	now := time.Unix(900, 0)
	endpoints := []gossip.LocalEndpoint{
		{IP: net.ParseIP("10.16.255.8"), Port: 33435, Scope: "global", Priority: 100, Source: gossip.SourceInterface},
	}
	record := &zone.Record{
		Zone:      "node-b.catofes.",
		Key:       gossip.EndpointRecordKeyUDP,
		Type:      "sync.endpoint",
		Value:     gossip.EndpointRecordBytes(endpoints, now),
		Version:   1,
		Timestamp: now.Unix(),
	}
	if err := higgscrypto.SignRecord(record, state.ZonePrivateKey); err != nil {
		t.Fatalf("SignRecord(endpoint): %v", err)
	}
	if err := state.Network.PutAt(record, now); err != nil {
		t.Fatalf("PutAt(endpoint): %v", err)
	}
	sr := newSyncRuntime(state, config, nil, rt)

	if err := sr.publishEndpointRecord(); err != nil {
		t.Fatalf("publishEndpointRecord(clear): %v", err)
	}
	clearedRecord := state.Network.Zones["node-b.catofes."].Records[gossip.EndpointRecordKeyUDP]
	if clearedRecord.Version != 2 {
		t.Fatalf("cleared endpoint version = %d, want 2", clearedRecord.Version)
	}
	cleared := endpointRecordFromState(t, state, "node-b.catofes.")
	if len(cleared.Endpoints) != 0 {
		t.Fatalf("cleared endpoints = %#v, want empty", cleared.Endpoints)
	}
	if history := state.Network.Zones["node-b.catofes."].RecordHistory[gossip.EndpointRecordKeyUDP]; len(history) != 1 {
		t.Fatalf("endpoint history len = %d, want previous record retained", len(history))
	}

	if err := sr.publishEndpointRecord(); err != nil {
		t.Fatalf("publishEndpointRecord(clear again): %v", err)
	}
	if got := state.Network.Zones["node-b.catofes."].Records[gossip.EndpointRecordKeyUDP].Version; got != 2 {
		t.Fatalf("endpoint version after second clear = %d, want 2", got)
	}
}

func TestEndpointPublishSkipsRootAdminState(t *testing.T) {
	dir := t.TempDir()
	rt := &Runtime{
		Config:    defaultAppConfig(),
		StatePath: filepath.Join(dir, "root.db"),
		Clock:     func() time.Time { return time.Unix(1000, 0) },
	}
	if _, err := initRootStateInRuntime(rt); err != nil {
		t.Fatalf("initRootStateInRuntime: %v", err)
	}
	state, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState(root): %v", err)
	}
	config := &syncConfigFile{PeerID: "node-admin", ListenAddr: "127.0.0.1:33540"}
	sr := newSyncRuntime(state, config, nil, rt)

	if err := sr.publishEndpointRecord(); err != nil {
		t.Fatalf("publishEndpointRecord(root): %v", err)
	}
	if record := state.Network.Zones[zone.RootZone].Records[gossip.EndpointRecordKeyUDP]; record != nil {
		t.Fatalf("root admin unexpectedly published endpoint record")
	}
}

func endpointRecordFromState(t *testing.T, state *stateFile, path zone.ZonePath) gossip.EndpointRecord {
	t.Helper()
	zs := state.Network.Zones[path]
	if zs == nil {
		t.Fatalf("zone %s missing", path)
	}
	record := zs.Records[gossip.EndpointRecordKeyUDP]
	if record == nil {
		t.Fatalf("endpoint record missing")
	}
	var er gossip.EndpointRecord
	if err := json.Unmarshal(record.Value, &er); err != nil {
		t.Fatalf("Unmarshal(endpoint record): %v", err)
	}
	return er
}

func TestUpdateDiscoveredPeersRevokesExpiredEndpointWithoutUDP(t *testing.T) {
	state, config := buildTestNetworkState(t)
	config.EndpointGrace = time.Nanosecond
	prepareStatePersistence(t)
	transport := &gossip.Transport{}

	putSignedEndpointRecord(t, state, "127.0.0.1", 9999, time.Unix(1, 0), 1)
	state.SyncPeers = map[string]syncPeerState{
		"node-b.catofes.": {
			LastSyncUnix:     time.Unix(1, 0).Unix(),
			DiscoveredAddr:   "127.0.0.1:9999",
			DiscoveredAtUnix: time.Unix(1, 0).Unix(),
		},
	}
	transport.SetPeerAddrs("node-b.catofes.", []*net.UDPAddr{{IP: net.ParseIP("127.0.0.1"), Port: 9999}})

	updateDiscoveredPeers(state, transport, config)
	if addr := transport.PeerAddr("node-b.catofes."); addr != nil {
		t.Fatalf("PeerAddr after expired endpoint = %v, want nil", addr)
	}
	if got := state.SyncPeers["node-b.catofes."].DiscoveredAddr; got != "" {
		t.Fatalf("DiscoveredAddr = %q, want cleared", got)
	}
}

func TestAppendRecentSuccessfulDiscoveredAddr(t *testing.T) {
	now := time.Unix(1000, 0)
	addrs := []*net.UDPAddr{{IP: net.ParseIP("127.0.0.1"), Port: 1000}}
	peerState := syncPeerState{
		LastSyncUnix:     now.Add(-time.Minute).Unix(),
		DiscoveredAddr:   "127.0.0.1:2000",
		DiscoveredAtUnix: now.Add(-2 * time.Minute).Unix(),
	}

	addrs = appendRecentSuccessfulDiscoveredAddr(addrs, peerState, 10*time.Minute, now)

	if len(addrs) != 2 {
		t.Fatalf("addrs = %d, want 2", len(addrs))
	}
	if addrs[1].String() != "127.0.0.1:2000" {
		t.Fatalf("fallback addr = %s, want 127.0.0.1:2000", addrs[1])
	}
}

func TestAppendRecentSuccessfulDiscoveredAddrExpires(t *testing.T) {
	now := time.Unix(1000, 0)
	peerState := syncPeerState{
		LastSyncUnix:   now.Add(-20 * time.Minute).Unix(),
		DiscoveredAddr: "127.0.0.1:2000",
	}

	addrs := appendRecentSuccessfulDiscoveredAddr(nil, peerState, 10*time.Minute, now)
	if len(addrs) != 0 {
		t.Fatalf("addrs = %#v, want expired fallback to be dropped", addrs)
	}
}

func TestHandleAnnounceRejectsSnapshotZoneLimit(t *testing.T) {
	state, _ := buildTestNetworkState(t)
	message := &gossip.Message{
		Type: gossip.MessageAnnounce,
		Announce: &gossip.Announce{Snapshots: []gossip.ZoneSnapshot{
			{Zone: "catofes."},
			{Zone: "node-b.catofes."},
		}},
	}

	err := handleAnnounce(state, nil, message, gossip.SyncLimits{MaxZones: 1, MaxRecords: 1024, MaxBytes: gossip.DefaultMaxMessage})
	if !errors.Is(err, gossip.ErrZoneSnapshotTooLarge) {
		t.Fatalf("handleAnnounce = %v, want ErrZoneSnapshotTooLarge", err)
	}
}

func TestSyncStatusVerboseOutput(t *testing.T) {
	prepareDiagnosticsState(t)

	output := runCLIAndCaptureStdout(t, "higgs", "sync", "status", "--verbose")

	assertOutputContains(t, output,
		"peer_id: node-a.catofes.",
		"listen_addr: 127.0.0.1:0",
		"known_peers: 1",
		"known_zones: 3",
		"limits: max_datagram_bytes=4096 max_sync_zones=8 max_sync_records=64 wire_version=1 wire_codec=msgpack",
		"allowlist_source: bootstrap+discovery",
		"bootstrap_peers: 1",
		"bootstrap peer=node-b.catofes. configured_addr=127.0.0.1:9999 resolved_addr=127.0.0.1:9999",
		"datagram peer=node-b.catofes. too_large_dropped=2 digest_only_announces=1 chunk_fallbacks=0",
		"object_pull peer=node-b.catofes. attempts=3 successes=2 failures=1 large_object_unreachable=1",
		"zone node-b.catofes.",
	)
}

func TestDebugPeerOutput(t *testing.T) {
	prepareDiagnosticsState(t)

	output := runCLIAndCaptureStdout(t, "higgs", "debug", "peer", "node-b.catofes.")

	assertOutputContains(t, output,
		"peer_id: node-b.catofes.",
		"source: bootstrap",
		"configured_addr: 127.0.0.1:9999",
		"resolved_addr: 127.0.0.1:2000",
		"last_success: 2023-11-14T22:13:20Z",
		"last_error: -",
		"discovered_addr: 127.0.0.1:2000",
		"observed_addr: 127.0.0.1:3000",
		"observed_status: active",
		"last_update_source: node-c.catofes.",
		"datagram_too_large_dropped: 2",
		"datagram_last_too_large: 2023-11-14T22:13:20Z direction=send object=record zone=node-b.catofes. key=bigdata bytes=1800 limit=1200",
		"object_pull_attempts: 3",
		"object_pull_last: 2023-11-14T22:13:20Z object=record zone=node-b.catofes. key=bigdata bytes=4096 source_peer=node-b.catofes. unreachable=true error=no TCP address",
	)
}

func TestDebugZoneOutput(t *testing.T) {
	prepareDiagnosticsState(t)

	output := runCLIAndCaptureStdout(t, "higgs", "debug", "zone", "node-b.catofes.")

	assertOutputContains(t, output,
		"zone: node-b.catofes.",
		"records: 1",
		"history: 0",
		"delegations: 0",
		"parent_proof: 0",
		"verify: ok",
		"record key=sync/endpoint/udp version=1 type=sync.endpoint",
	)
}

func TestDebugRecordsOutputFiltersByPrefixAndPrintsValues(t *testing.T) {
	now := time.Unix(1700000000, 0)
	state, _ := buildTestNetworkState(t)
	addTestIPsecRecords(t, state.Network.Zones["node-b.catofes."], "node-b.catofes.", now, ipsec.AcceptInbound)
	var out bytes.Buffer
	if err := writeDebugRecords(&out, state, "node-b.catofes.", "ipsec/", true); err != nil {
		t.Fatalf("writeDebugRecords: %v", err)
	}
	output := out.String()
	assertOutputContains(t, output,
		"zones: 1",
		"records: 4",
		"prefix: ipsec/",
		"zone node-b.catofes.",
		"record key=ipsec/profile version=1 type=ipsec.profile.v1",
		"record key=ipsec/transport-key version=1 type=ipsec.transport_key.v1",
		"value: {",
	)
	if strings.Contains(output, "sync/endpoint/udp") {
		t.Fatalf("debug records prefix leaked endpoint record:\n%s", output)
	}
}

func prepareDiagnosticsState(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	dataDir := filepath.Join(dir, "data")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	config := strings.Join([]string{
		"data_dir: " + dataDir,
		"peer_id: node-a.catofes.",
		"listen_addr: 127.0.0.1:0",
		"max_message_bytes: 4096",
		"max_sync_zones: 8",
		"max_sync_records: 64",
		"bootstrap:",
		"  - id: node-b.catofes.",
		"    addr: 127.0.0.1:9999",
		"",
	}, "\n")
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatalf("WriteFile(config): %v", err)
	}
	t.Setenv("HIGGS_CONFIG", configPath)

	state, _ := buildTestNetworkState(t)
	now := time.Unix(1700000000, 0)
	observedNow := time.Now()
	endpoints := []gossip.LocalEndpoint{
		{IP: net.ParseIP("127.0.0.1"), Port: 9999, Scope: "global", Priority: 100, Source: gossip.SourceAdvertise},
	}
	record := &zone.Record{
		Zone:      "node-b.catofes.",
		Key:       gossip.EndpointRecordKeyUDP,
		Type:      "sync.endpoint",
		Value:     gossip.EndpointRecordBytes(endpoints, now),
		Version:   1,
		Timestamp: now.Unix(),
	}
	if err := higgscrypto.SignRecord(record, state.ZonePrivateKey); err != nil {
		t.Fatalf("SignRecord(endpoint): %v", err)
	}
	if err := state.Network.PutAt(record, now); err != nil {
		t.Fatalf("PutAt(endpoint): %v", err)
	}
	state.SyncPeers = map[string]syncPeerState{
		"node-b.catofes.": {
			LastSyncUnix:          now.Unix(),
			DiscoveredAddr:        "127.0.0.1:2000",
			DiscoveredAtUnix:      now.Unix(),
			ObservedAddr:          "127.0.0.1:3000",
			ObservedFirstSeenUnix: observedNow.Unix(),
			ObservedLastSeenUnix:  observedNow.Unix(),
			ObservedLastSyncUnix:  observedNow.Unix(),
			ObservedUntilUnix:     observedNow.Add(time.Hour).Unix(),
			ObservedSource:        string(gossip.MessagePing),
			LastUpdateSource:      "node-c.catofes.",
			DatagramStats: &datagramStats{
				TooLargeDropped:       2,
				DigestOnlyAnnounces:   1,
				LastTooLargeUnix:      now.Unix(),
				LastTooLargeDirection: "send",
				LastTooLargeObject:    "record",
				LastTooLargeZone:      "node-b.catofes.",
				LastTooLargeKey:       "bigdata",
				LastTooLargeBytes:     1800,
				LastTooLargeLimit:     gossip.DefaultDatagramBudget,
			},
			ObjectPullStats: &objectPullStats{
				Attempts:               3,
				Successes:              2,
				Failures:               1,
				LargeObjectUnreachable: 1,
				LastUnix:               now.Unix(),
				LastError:              "no TCP address",
				LastObject:             "record",
				LastZone:               "node-b.catofes.",
				LastKey:                "bigdata",
				LastBytes:              4096,
				LastSourcePeer:         "node-b.catofes.",
				LastUnreachable:        true,
			},
		},
	}
	if err := saveState(state); err != nil {
		t.Fatalf("saveState: %v", err)
	}
}

func prepareStatePersistence(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	dataDir := filepath.Join(dir, "data")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(configPath, []byte("data_dir: "+dataDir+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(config): %v", err)
	}
	t.Setenv("HIGGS_CONFIG", configPath)
}

func putSignedEndpointRecord(t *testing.T, state *stateFile, ip string, port uint16, now time.Time, version uint64) {
	t.Helper()
	endpoints := []gossip.LocalEndpoint{
		{IP: net.ParseIP(ip), Port: port, Scope: "global", Priority: 100, Source: gossip.SourceAdvertise},
	}
	record := &zone.Record{
		Zone:      "node-b.catofes.",
		Key:       gossip.EndpointRecordKeyUDP,
		Type:      "sync.endpoint",
		Value:     gossip.EndpointRecordBytes(endpoints, now),
		Version:   version,
		Timestamp: now.Unix(),
	}
	if err := higgscrypto.SignRecord(record, state.ZonePrivateKey); err != nil {
		t.Fatalf("SignRecord(endpoint): %v", err)
	}
	if err := state.Network.PutAt(record, now); err != nil {
		t.Fatalf("PutAt(endpoint): %v", err)
	}
}

func runCLIAndCaptureStdout(t *testing.T, args ...string) string {
	t.Helper()
	oldStdout := os.Stdout
	readEnd, writeEnd, err := os.Pipe()
	if err != nil {
		t.Fatalf("Pipe: %v", err)
	}
	os.Stdout = writeEnd
	err = rootCommand().Run(context.Background(), args)
	if closeErr := writeEnd.Close(); closeErr != nil {
		t.Fatalf("Close(stdout pipe): %v", closeErr)
	}
	os.Stdout = oldStdout
	data, readErr := io.ReadAll(readEnd)
	if readErr != nil {
		t.Fatalf("ReadAll(stdout): %v", readErr)
	}
	if err != nil {
		t.Fatalf("Run(%v): %v\nstdout:\n%s", args, err, string(data))
	}
	return string(data)
}

func assertOutputContains(t *testing.T, output string, want ...string) {
	t.Helper()
	for _, fragment := range want {
		if !strings.Contains(output, fragment) {
			t.Fatalf("output missing %q\noutput:\n%s", fragment, output)
		}
	}
}

func skipRestrictedSocket(t *testing.T, err error) {
	t.Helper()
	if errors.Is(err, os.ErrPermission) {
		t.Skipf("UDP sockets are not permitted in this environment: %v", err)
	}
}

func TestBuildPeerAddrsPutsAdvertiseBeforeBootstrap(t *testing.T) {
	now := time.Now()
	bootstrap := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 33434}
	entries := []gossip.EndpointEntry{
		{Address: "203.0.113.10", Port: 33434, Source: "reflector", Priority: 50},
		{Address: "10.0.0.5", Port: 33434, Source: "interface", Priority: 10},
		{Address: "198.51.100.2", Port: 33434, Source: "advertise", Priority: 100},
	}

	addrs := buildPeerAddrs("peer-a", entries, bootstrap, syncPeerState{}, time.Minute, nil, now)
	if len(addrs) != 4 {
		t.Fatalf("addrs = %d, want 4", len(addrs))
	}
	if addrs[0].String() != "198.51.100.2:33434" {
		t.Fatalf("first addr = %v, want advertise 198.51.100.2:33434", addrs[0])
	}
	if addrs[1].String() != bootstrap.String() {
		t.Fatalf("second addr = %v, want bootstrap %v", addrs[1], bootstrap)
	}
}

func TestBuildPeerAddrsRespectsSourceOrder(t *testing.T) {
	now := time.Now()
	bootstrap := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 33434}
	entries := []gossip.EndpointEntry{
		{Address: "203.0.113.10", Port: 33434, Source: "reflector"},
		{Address: "198.51.100.2", Port: 33434, Source: "advertise"},
	}

	addrs := buildPeerAddrs("peer-a", entries, bootstrap, syncPeerState{}, time.Minute, []string{"bootstrap", "advertise", "reflector"}, now)
	if len(addrs) != 3 {
		t.Fatalf("addrs = %d, want 3", len(addrs))
	}
	if addrs[0].String() != bootstrap.String() {
		t.Fatalf("first addr = %v, want bootstrap", addrs[0])
	}
	if addrs[1].String() != "198.51.100.2:33434" {
		t.Fatalf("second addr = %v, want advertise 198.51.100.2:33434", addrs[1])
	}
}

func TestFilterEndpointDiscoveryInputsLoopbackOnly(t *testing.T) {
	config := &syncConfigFile{
		ListenAddr:        ":33434",
		AdvertiseAddrs:    []string{"127.0.0.1:33434", "203.0.113.10:33434"},
		Reflectors:        []string{"auto"},
		EndpointDiscovery: "loopback_only",
	}
	advertise, reflectors := filterEndpointDiscoveryInputs(config, 33434)
	if len(reflectors) != 0 {
		t.Fatalf("reflectors = %v, want empty", reflectors)
	}
	foundPublic := false
	for _, addr := range advertise {
		if strings.Contains(addr, "203.0.113.10") {
			foundPublic = true
		}
	}
	if foundPublic {
		t.Fatalf("public advertise addr should be filtered in loopback_only: %v", advertise)
	}
	if len(advertise) == 0 {
		t.Fatalf("expected at least one loopback advertise addr")
	}
}

func TestFilterEndpointDiscoveryInputsAdvertiseOnly(t *testing.T) {
	config := &syncConfigFile{
		ListenAddr:        "127.0.0.1:33434",
		AdvertiseAddrs:    []string{"203.0.113.10:33434"},
		Reflectors:        []string{"auto"},
		EndpointDiscovery: "advertise_only",
	}
	advertise, reflectors := filterEndpointDiscoveryInputs(config, 33434)
	if len(reflectors) != 0 {
		t.Fatalf("reflectors = %v, want empty", reflectors)
	}
	if len(advertise) != 1 || advertise[0] != "203.0.113.10:33434" {
		t.Fatalf("advertise = %v, want [203.0.113.10:33434]", advertise)
	}
}

func TestFilterEndpointDiscoveryInputsAutoLoopbackBootstrap(t *testing.T) {
	config := &syncConfigFile{
		ListenAddr: ":33434",
		Bootstrap: []syncConfigPeer{
			{ID: "peer-a", Addr: "127.0.0.1:33435"},
		},
		AdvertiseAddrs: []string{"203.0.113.10:33434"},
		Reflectors:     []string{"auto"},
	}
	advertise, reflectors := filterEndpointDiscoveryInputs(config, 33434)
	if len(reflectors) != 0 {
		t.Fatalf("auto loopback-only should suppress reflectors")
	}
	foundPublic := false
	for _, addr := range advertise {
		if strings.Contains(addr, "203.0.113.10") {
			foundPublic = true
		}
	}
	if foundPublic {
		t.Fatalf("auto loopback-only should filter public advertise addrs: %v", advertise)
	}
}

func TestFilterEndpointDiscoveryInputsAutoPublicBootstrap(t *testing.T) {
	config := &syncConfigFile{
		ListenAddr: ":33434",
		Bootstrap: []syncConfigPeer{
			{ID: "peer-a", Addr: "203.0.113.10:33435"},
		},
		AdvertiseAddrs: []string{"203.0.113.10:33434"},
		Reflectors:     []string{"auto"},
	}
	advertise, reflectors := filterEndpointDiscoveryInputs(config, 33434)
	if len(reflectors) == 0 {
		t.Fatalf("auto with public bootstrap should keep reflectors")
	}
	if len(advertise) != 1 || advertise[0] != "203.0.113.10:33434" {
		t.Fatalf("advertise = %v, want [203.0.113.10:33434]", advertise)
	}
}
