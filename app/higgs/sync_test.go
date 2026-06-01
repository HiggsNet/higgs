package main

import (
	"context"
	"crypto/ed25519"
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
		"limits: max_message_bytes=4096 max_sync_zones=8 max_sync_records=64 wire_version=1",
		"allowlist_source: bootstrap+discovery",
		"bootstrap_peers: 1",
		"bootstrap peer=node-b.catofes. configured_addr=127.0.0.1:9999 resolved_addr=127.0.0.1:9999",
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
		"last_update_source: node-c.catofes.",
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
			LastSyncUnix:     now.Unix(),
			DiscoveredAddr:   "127.0.0.1:2000",
			DiscoveredAtUnix: now.Unix(),
			LastUpdateSource: "node-c.catofes.",
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
