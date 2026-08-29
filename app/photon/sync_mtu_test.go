package main

import (
	"bytes"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
)

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

	plan := gossip.PlanSnapshotDatagrams(state.Network, []zone.ZonePath{"node-b.catofes."}, gossip.DefaultDatagramBudget, now)
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
		if size := gossip.MessageWireSize(&gossip.Message{Type: gossip.MessageAnnounce, Announce: announce}); size > gossip.DefaultDatagramBudget {
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

	plan := gossip.PlanSnapshotDatagrams(state.Network, []zone.ZonePath{"node-b.catofes."}, gossip.DefaultDatagramBudget, now)
	if len(plan.Oversized) != 0 {
		t.Fatalf("oversized = %#v, want none because ANNOUNCE only carries digest hints", plan.Oversized)
	}
	for _, announce := range plan.Announces {
		if size := gossip.MessageWireSize(&gossip.Message{Type: gossip.MessageAnnounce, Announce: announce}); size > gossip.DefaultDatagramBudget {
			t.Fatalf("announce size = %d exceeds budget %d", size, gossip.DefaultDatagramBudget)
		}
	}
}

func TestCatalogSyncAvoidsOversizedFullDigestPing(t *testing.T) {
	var digests []corestate.ZoneDigest
	for i := range 80 {
		digests = append(digests, corestate.ZoneDigest{
			Zone:     zone.ZonePath("node-" + string(rune('a'+i%26)) + "-" + string(rune('a'+i/26)) + ".catofes."),
			RootHash: bytes.Repeat([]byte{byte(i)}, 32),
		})
	}
	summary := corestate.CatalogSummaryForDigests(digests)
	summarySize := gossip.MessageWireSize(&gossip.Message{
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
