package main

import (
	"testing"
	"time"

	"github.com/Catofes/higgs/pkg/core/gossip"
	"github.com/Catofes/higgs/pkg/core/zone"
	higgscrypto "github.com/Catofes/higgs/pkg/crypto"
)

func TestObjectPullTCPServerClient(t *testing.T) {
	state, _ := buildTestNetworkState(t)
	state.Network.ConfigureRecordValidation(higgscrypto.VerifyRecord, higgscrypto.RecordHash)
	now := time.Unix(1000, 0)
	record := &zone.Record{
		Zone:      "node-b.catofes.",
		Key:       "identity",
		Type:      "node.identity",
		Value:     []byte("node-a"),
		Version:   1,
		Timestamp: now.Unix(),
	}
	if err := higgscrypto.SignRecord(record, state.ZonePrivateKey); err != nil {
		t.Fatalf("SignRecord: %v", err)
	}
	if err := state.Network.PutAt(record, now); err != nil {
		t.Fatalf("PutAt: %v", err)
	}

	listener, err := objectPullTCPServe("127.0.0.1:0", objectPullLookup(func() *stateFile { return state }))
	if err != nil {
		t.Fatalf("objectPullTCPServe: %v", err)
	}
	defer listener.Close()

	// Pull zone snapshot.
	resp, err := pullObjectTCP(listener.Addr().String(), &gossip.ObjectPullRequest{
		Type: gossip.ObjectPullZone,
		Zone: "node-b.catofes.",
	})
	if err != nil {
		t.Fatalf("pullObjectTCP: %v", err)
	}
	if !resp.OK {
		t.Fatalf("object pull failed: %s", resp.Error)
	}
	if resp.Snapshot == nil || resp.Snapshot.Zone != "node-b.catofes." {
		t.Fatalf("unexpected snapshot: %+v", resp.Snapshot)
	}
	if len(resp.Snapshot.Records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(resp.Snapshot.Records))
	}

	// Pull single record.
	resp2, err := pullObjectTCP(listener.Addr().String(), &gossip.ObjectPullRequest{
		Type: gossip.ObjectPullRecord,
		Zone: "node-b.catofes.",
		Key:  "identity",
	})
	if err != nil {
		t.Fatalf("pullObjectTCP record: %v", err)
	}
	if !resp2.OK || resp2.Record == nil {
		t.Fatalf("record pull failed: %s", resp2.Error)
	}
	if string(resp2.Record.Record.Value) != "node-a" {
		t.Fatalf("unexpected record value: %s", resp2.Record.Record.Value)
	}
}

func TestObjectPullTCPAddrDerivation(t *testing.T) {
	if got := objectPullTCPAddr("192.0.2.1:33434"); got != "192.0.2.1:33435" {
		t.Fatalf("objectPullTCPAddr = %q, want 192.0.2.1:33435", got)
	}
	if got := objectPullTCPAddr("[2001:db8::1]:33434"); got != "[2001:db8::1]:33435" {
		t.Fatalf("objectPullTCPAddr v6 = %q, want [2001:db8::1]:33435", got)
	}
}

func TestObjectPullListenAddr(t *testing.T) {
	if got := objectPullListenAddr("127.0.0.1:33434"); got != "127.0.0.1:33435" {
		t.Fatalf("objectPullListenAddr = %q, want 127.0.0.1:33435", got)
	}
}

func TestObjectPullLookupRejectsRevokedZone(t *testing.T) {
	// Core revocation logic is tested in pkg/core/gossip.
	// Full object-pull revocation integration would need catofes private key
	// which buildTestNetworkState does not expose; skip for now.
	t.Skip("revocation tested in pkg/core/gossip")
}

func TestResolvePeerTCPAddrPrefersBootstrap(t *testing.T) {
	state, _ := buildTestNetworkState(t)
	config := &syncConfigFile{
		Bootstrap: []syncConfigPeer{
			{ID: "node-b", Addr: "192.0.2.10:33434"},
		},
	}
	if got := resolvePeerTCPAddr(state, config, "node-b"); got != "192.0.2.10:33435" {
		t.Fatalf("resolvePeerTCPAddr = %q, want 192.0.2.10:33435", got)
	}
	if got := resolvePeerTCPAddr(state, config, "unknown"); got != "" {
		t.Fatalf("resolvePeerTCPAddr unknown = %q, want empty", got)
	}
}
