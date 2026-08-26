package main

import (
	"bytes"
	"crypto/ed25519"
	"net"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
)

func TestSendDetachedSnapshotsChunksOversizedRecords(t *testing.T) {
	resetUDPSentChunkCacheForTest(t)
	state, _ := buildTestNetworkState(t)
	state.Network.ConfigureRecordValidation(photoncrypto.VerifyRecord, photoncrypto.RecordHash)
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
	if err := photoncrypto.SignRecord(record, state.ZonePrivateKey); err != nil {
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

	plan := planSnapshotDatagrams(state.Network, []zone.ZonePath{"node-b.catofes."}, transport.MaxMessageBytes(), now)
	snapshot, err := gossip.Snapshot(state.Network, "node-b.catofes.")
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	diag, err := sendDetachedSnapshotWithDiagnostics(snapshot, plan, transport, "peer", now, nil)
	if err != nil {
		t.Fatalf("sendDetachedSnapshotWithDiagnostics returned error for oversized record: %v", err)
	}
	if diag.ChunkFallbacks == 0 {
		t.Fatal("sendDetachedSnapshotWithDiagnostics sent no snapshot chunks")
	}
}

func TestSendDetachedSnapshotsIgnoresRecordPayloadForAnnounceStats(t *testing.T) {
	resetUDPSentChunkCacheForTest(t)
	state, _ := buildTestNetworkState(t)
	state.Network.ConfigureRecordValidation(photoncrypto.VerifyRecord, photoncrypto.RecordHash)
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
	if err := photoncrypto.SignRecord(record, state.ZonePrivateKey); err != nil {
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

	plan := planSnapshotDatagrams(state.Network, []zone.ZonePath{"node-b.catofes."}, transport.MaxMessageBytes(), now)
	snapshot, err := gossip.Snapshot(state.Network, "node-b.catofes.")
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	diag, err := sendDetachedSnapshotWithDiagnostics(snapshot, plan, transport, "node-b.catofes.", now, nil)
	if err != nil {
		t.Fatalf("sendDetachedSnapshotWithDiagnostics: %v", err)
	}
	if len(diag.Oversized) != 0 {
		t.Fatalf("diagnostics = %#v, want no record payload accounting for hint-only announce", diag)
	}
}

func TestSendDetachedSnapshotsChunksOversizedSkeleton(t *testing.T) {
	resetUDPSentChunkCacheForTest(t)
	state, _ := buildTestNetworkState(t)
	state.Network.ConfigureRecordValidation(photoncrypto.VerifyRecord, photoncrypto.RecordHash)
	// Add many delegations to inflate the zone skeleton.
	for i := range 50 {
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
		if err := photoncrypto.SignDelegation(delegation, "catofes.", state.ZonePrivateKey); err != nil {
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

	now := time.Now()
	plan := planSnapshotDatagrams(state.Network, []zone.ZonePath{"catofes."}, transport.MaxMessageBytes(), now)
	snapshot, err := gossip.Snapshot(state.Network, "catofes.")
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	diag, err := sendDetachedSnapshotWithDiagnostics(snapshot, plan, transport, "peer", now, nil)
	if err != nil {
		t.Fatalf("sendDetachedSnapshotWithDiagnostics returned error for oversized skeleton: %v", err)
	}
	if diag.ChunkFallbacks == 0 {
		t.Fatal("sendDetachedSnapshotWithDiagnostics sent no snapshot chunks")
	}
}

func resetUDPSentChunkCacheForTest(t *testing.T) {
	t.Helper()
	original := udpSentChunkCache
	udpSentChunkCache = newSentChunkCache()
	t.Cleanup(func() {
		udpSentChunkCache = original
	})
}

func TestPlanSnapshotDatagramsEmitsDigestHintsOnly(t *testing.T) {
	state, _ := buildTestNetworkState(t)
	state.Network.ConfigureRecordValidation(photoncrypto.VerifyRecord, photoncrypto.RecordHash)
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
		if err := photoncrypto.SignRecord(record, state.ZonePrivateKey); err != nil {
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
	if len(plan.Announces) != 1 {
		t.Fatalf("announces = %d, want one digest hint batch", len(plan.Announces))
	}
	if got := len(plan.Announces[0].Zones); got == 0 {
		t.Fatalf("first announce zones = %d, want digest batch", got)
	}
	for _, announce := range plan.Announces {
		if size := announceWireSize(announce); size > gossip.DefaultDatagramBudget {
			t.Fatalf("announce size = %d exceeds budget", size)
		}
	}
}

func TestPlanSnapshotDatagramsIgnoresRecordPayloadSize(t *testing.T) {
	state, _ := buildTestNetworkState(t)
	state.Network.ConfigureRecordValidation(photoncrypto.VerifyRecord, photoncrypto.RecordHash)
	now := time.Unix(1000, 0)

	largeValue := make([]byte, 3000)
	record := &zone.Record{
		Zone:      "node-b.catofes.",
		Key:       "bigdata",
		Type:      "test.data",
		Value:     largeValue,
		Version:   1,
		Timestamp: now.Unix(),
	}
	if err := photoncrypto.SignRecord(record, state.ZonePrivateKey); err != nil {
		t.Fatalf("SignRecord: %v", err)
	}
	if err := state.Network.PutAt(record, now); err != nil {
		t.Fatalf("PutAt: %v", err)
	}

	plan := planSnapshotDatagrams(state.Network, []zone.ZonePath{"node-b.catofes."}, gossip.DefaultDatagramBudget, now)
	if len(plan.Oversized) != 0 {
		t.Fatalf("oversized = %#v, want none because ANNOUNCE only carries digest hints", plan.Oversized)
	}
	for _, announce := range plan.Announces {
		if size := announceWireSize(announce); size > gossip.DefaultDatagramBudget {
			t.Fatalf("announce size = %d exceeds budget %d", size, gossip.DefaultDatagramBudget)
		}
	}
}

func TestCatalogSyncAvoidsOversizedFullDigestPing(t *testing.T) {
	var digests []gossip.ZoneDigest
	for i := range 80 {
		digests = append(digests, gossip.ZoneDigest{
			Zone:     zone.ZonePath("node-" + string(rune('a'+i%26)) + "-" + string(rune('a'+i/26)) + ".catofes."),
			RootHash: bytes.Repeat([]byte{byte(i)}, 32),
		})
	}
	summary := &gossip.CatalogSummary{CatalogRoot: gossip.CatalogRoot(digests), ZoneCount: len(digests)}
	summarySize := messageWireSize(&gossip.Message{
		Type: gossip.MessagePing,
		Ping: &gossip.Ping{Summary: summary},
	})
	if summarySize > gossip.DefaultDatagramBudget {
		t.Fatalf("catalog summary ping size=%d exceeds %d", summarySize, gossip.DefaultDatagramBudget)
	}
	cursor := ""
	for {
		page, err := gossip.CatalogPageForDigests(digests, cursor, gossip.DefaultDatagramBudget, "photon-unicom-pek.kxxoling.")
		if err != nil {
			t.Fatalf("CatalogPageForDigests(%q): %v", cursor, err)
		}
		size, err := gossip.WireEncodeSizeForPeer(&gossip.Message{Type: gossip.MessageCatalogPage, CatalogPage: page}, "photon-unicom-pek.kxxoling.")
		if err != nil {
			t.Fatalf("WireEncodeSizeForPeer(%q): %v", cursor, err)
		}
		if size > gossip.DefaultDatagramBudget {
			t.Fatalf("catalog page size=%d exceeds %d", size, gossip.DefaultDatagramBudget)
		}
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
	}
}
