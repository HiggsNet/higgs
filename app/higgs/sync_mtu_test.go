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

func TestSendSnapshotsSkipsOversizedRecords(t *testing.T) {
	state, _ := buildTestNetworkState(t)
	state.Network.ConfigureRecordValidation(higgscrypto.VerifyRecord, higgscrypto.RecordHash)
	now := time.Unix(1000, 0)

	// Create a record with a large value that exceeds the 1200-byte datagram budget.
	largeValue := make([]byte, 2000)
	for i := range largeValue {
		largeValue[i] = byte(i % 256)
	}
	record := &zone.Record{
		Zone:      "node-b.catofes.",
		Key:       "bigdata",
		Type:      "test.data",
		Value:     largeValue,
		Version:   1,
		Timestamp: now.Unix(),
	}
	if err := higgscrypto.SignRecord(record, state.ZonePrivateKey); err != nil {
		t.Fatalf("SignRecord: %v", err)
	}
	if err := state.Network.PutAt(record, now); err != nil {
		t.Fatalf("PutAt: %v", err)
	}

	transport, err := gossip.Listen(gossip.Config{
		PeerID:          "node-a",
		ListenAddr:      "127.0.0.1:0",
		MaxMessageBytes: gossip.DefaultDatagramBudget,
	})
	if err != nil {
		skipRestrictedSocket(t, err)
		t.Fatalf("Listen: %v", err)
	}
	defer transport.Close()
	transport.SetPeerAddrs("peer", []*net.UDPAddr{transport.LocalAddr()})

	// sendSnapshots should return nil even though the record is too large for UDP.
	if err := sendSnapshots(state.Network, transport, "peer", []zone.ZonePath{"node-b.catofes."}); err != nil {
		t.Fatalf("sendSnapshots returned error for oversized record: %v", err)
	}
}

func TestSendSnapshotsRecordsDatagramStats(t *testing.T) {
	state, _ := buildTestNetworkState(t)
	state.Network.ConfigureRecordValidation(higgscrypto.VerifyRecord, higgscrypto.RecordHash)
	now := time.Unix(1000, 0)

	largeValue := make([]byte, 2000)
	record := &zone.Record{
		Zone:      "node-b.catofes.",
		Key:       "bigdata",
		Type:      "test.data",
		Value:     largeValue,
		Version:   1,
		Timestamp: now.Unix(),
	}
	if err := higgscrypto.SignRecord(record, state.ZonePrivateKey); err != nil {
		t.Fatalf("SignRecord: %v", err)
	}
	if err := state.Network.PutAt(record, now); err != nil {
		t.Fatalf("PutAt: %v", err)
	}

	transport, err := gossip.Listen(gossip.Config{
		PeerID:          "node-a",
		ListenAddr:      "127.0.0.1:0",
		MaxMessageBytes: gossip.DefaultDatagramBudget,
	})
	if err != nil {
		skipRestrictedSocket(t, err)
		t.Fatalf("Listen: %v", err)
	}
	defer transport.Close()
	transport.SetPeerAddrs("node-b.catofes.", []*net.UDPAddr{transport.LocalAddr()})

	if err := sendSnapshotsWithStats(state, state.Network, transport, "node-b.catofes.", []zone.ZonePath{"node-b.catofes."}, now); err != nil {
		t.Fatalf("sendSnapshotsWithStats: %v", err)
	}
	stats := state.SyncPeers["node-b.catofes."].DatagramStats
	if stats == nil || stats.TooLargeDropped == 0 {
		t.Fatalf("datagram stats = %#v, want too_large_dropped", stats)
	}
	if stats.LastTooLargeObject != "record" || stats.LastTooLargeZone != "node-b.catofes." || stats.LastTooLargeKey != "bigdata" {
		t.Fatalf("last too-large stats = %#v", stats)
	}
}

func TestSendSnapshotsSkipsOversizedSkeleton(t *testing.T) {
	state, _ := buildTestNetworkState(t)
	state.Network.ConfigureRecordValidation(higgscrypto.VerifyRecord, higgscrypto.RecordHash)
	// Add many delegations to inflate the zone skeleton.
	for i := 0; i < 50; i++ {
		child := zone.ZonePath("child-" + string(rune('a'+i%26)) + ".catofes.")
		pub, priv, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatalf("GenerateKeyPair: %v", err)
		}
		authority := &zone.ZoneAuthority{
			Zone:      child,
			Epoch:     1,
			Threshold: 1,
			Keys: []zone.AuthorizedKey{{
				Key: pub,
				Capabilities: []zone.Capability{{
					Permissions: []zone.Permission{zone.PermWrite},
				}},
			}},
		}
		delegation := &zone.Delegation{
			ZoneName:  child,
			Scope:     zone.DelegationScopeDirectChild,
			Authority: *authority,
		}
		if err := higgscrypto.SignDelegation(delegation, "catofes.", state.ZonePrivateKey); err != nil {
			t.Fatalf("SignDelegation: %v", err)
		}
		state.Network.Zones["catofes."].Delegations[child] = delegation
		state.Network.Zones[child] = zone.NewZoneState(child, authority)
		_ = priv
	}

	transport, err := gossip.Listen(gossip.Config{
		PeerID:          "node-a",
		ListenAddr:      "127.0.0.1:0",
		MaxMessageBytes: gossip.DefaultDatagramBudget,
	})
	if err != nil {
		skipRestrictedSocket(t, err)
		t.Fatalf("Listen: %v", err)
	}
	defer transport.Close()
	transport.SetPeerAddrs("peer", []*net.UDPAddr{transport.LocalAddr()})

	// sendSnapshots should return nil even though the skeleton exceeds the budget.
	if err := sendSnapshots(state.Network, transport, "peer", []zone.ZonePath{"catofes."}); err != nil {
		t.Fatalf("sendSnapshots returned error for oversized skeleton: %v", err)
	}
}

func TestPlanSnapshotDatagramsBatchesRecordsWithinBudget(t *testing.T) {
	state, _ := buildTestNetworkState(t)
	state.Network.ConfigureRecordValidation(higgscrypto.VerifyRecord, higgscrypto.RecordHash)
	now := time.Unix(1000, 0)

	for _, key := range []string{"alpha", "beta"} {
		record := &zone.Record{
			Zone:      "node-b.catofes.",
			Key:       key,
			Type:      "test.data",
			Value:     []byte("small-" + key),
			Version:   1,
			Timestamp: now.Unix(),
		}
		if err := higgscrypto.SignRecord(record, state.ZonePrivateKey); err != nil {
			t.Fatalf("SignRecord(%s): %v", key, err)
		}
		if err := state.Network.PutAt(record, now); err != nil {
			t.Fatalf("PutAt(%s): %v", key, err)
		}
	}

	plan := planSnapshotDatagrams(state.Network, []zone.ZonePath{"node-b.catofes."}, gossip.DefaultDatagramBudget, now)
	if len(plan.Oversized) != 0 {
		t.Fatalf("oversized = %#v, want none", plan.Oversized)
	}
	if len(plan.Announces) < 3 {
		t.Fatalf("announces = %d, want digest, skeleton, records", len(plan.Announces))
	}
	if got := len(plan.Announces[0].Zones); got == 0 {
		t.Fatalf("first announce zones = %d, want digest batch", got)
	}
	var recordBatchFound bool
	for _, announce := range plan.Announces {
		if len(announce.Records) >= 2 {
			recordBatchFound = true
		}
		if size := announceWireSize(announce); size > gossip.DefaultDatagramBudget {
			t.Fatalf("announce size = %d exceeds budget", size)
		}
	}
	if !recordBatchFound {
		t.Fatalf("plan did not batch multiple records: %#v", plan.Announces)
	}
}
