package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"github.com/Catofes/higgs/pkg/core/gossip"
	"github.com/Catofes/higgs/pkg/core/zone"
	higgscrypto "github.com/Catofes/higgs/pkg/crypto"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

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
		"gossip:",
		"  peer_id: node-a.catofes.",
		"  listen_addr: 127.0.0.1:0",
		"  max_datagram_bytes: 4096",
		"  max_sync_zones: 8",
		"  max_sync_records: 64",
		"  bootstrap:",
		"    - id: node-b.catofes.",
		"      addr: 127.0.0.1:9999",
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
			ActivePullState:       string(SyncSessionObjectPulling),
			ActivePullLastEvent:   "catalog_page",
			ActivePullUpdatedUnix: now.Unix(),
			HintAccepted:          2,
			HintSuppressed:        1,
			LastHintUnix:          now.Unix(),
			LastHintReason:        "announce_hint",
			LastHintSuppression:   "session_active",
			ReadOnlyResponder:     3,
			LastResponderUnix:     now.Unix(),
			LastResponderKind:     "chunk_fallback",
			LastResponderZone:     "node-b.catofes.",
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
