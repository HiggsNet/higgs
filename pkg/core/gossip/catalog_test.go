package gossip

import (
	"bytes"
	"errors"
	"testing"

	"github.com/HiggsNet/photon/pkg/core/zone"
)

func TestCatalogSummaryForDigestsMatchesCatalogRoot(t *testing.T) {
	entries := []ZoneDigest{
		{Zone: "a.catofes.", RootHash: bytes.Repeat([]byte{1}, 32)},
		{Zone: "b.catofes.", RootHash: bytes.Repeat([]byte{2}, 32)},
	}
	summary, err := CatalogSummaryForDigests(entries, DefaultDatagramBudget)
	if err != nil {
		t.Fatalf("CatalogSummaryForDigests: %v", err)
	}
	if summary.ZoneCount != len(entries) || !bytes.Equal(summary.CatalogRoot, CatalogRoot(entries)) {
		t.Fatalf("summary = %#v, want zone_count=%d root=%x", summary, len(entries), CatalogRoot(entries))
	}
}

func TestCatalogPageForDigestsIsBoundedAndStable(t *testing.T) {
	var entries []ZoneDigest
	for i := range 80 {
		entries = append(entries, ZoneDigest{
			Zone:     zone.ZonePath("node-" + string(rune('a'+i%26)) + "-" + string(rune('a'+i/26)) + ".catofes."),
			RootHash: bytes.Repeat([]byte{byte(i)}, 32),
		})
	}

	page, err := CatalogPageForDigests(entries, "", 300)
	if err != nil {
		t.Fatalf("CatalogPageForDigests: %v", err)
	}
	if len(page.Entries) == 0 || page.NextCursor == "" {
		t.Fatalf("page entries=%d next=%q, want bounded non-final page", len(page.Entries), page.NextCursor)
	}
	size, err := WireEncodeSize(&Message{Type: MessageCatalogPage, CatalogPage: page})
	if err != nil {
		t.Fatalf("WireEncodeSize: %v", err)
	}
	if size > 300 {
		t.Fatalf("catalog page size=%d, want <= 300", size)
	}

	again, err := CatalogPageForDigests(entries, "", 300)
	if err != nil {
		t.Fatalf("CatalogPageForDigests again: %v", err)
	}
	if again.NextCursor != page.NextCursor || !bytes.Equal(again.CatalogRoot, page.CatalogRoot) {
		t.Fatalf("page is not stable: first=%q again=%q", page.NextCursor, again.NextCursor)
	}
}

func TestCatalogPageForDigestsEmptyPage(t *testing.T) {
	entries := []ZoneDigest{{Zone: "catofes.", RootHash: []byte("root")}}
	page, err := CatalogPageForDigests(entries, "1", DefaultDatagramBudget)
	if err != nil {
		t.Fatalf("CatalogPageForDigests: %v", err)
	}
	if len(page.Entries) != 0 || page.NextCursor != "" {
		t.Fatalf("page = %+v, want empty terminal page", page)
	}
}

func TestCatalogPageForDigestsFailsClosedForOversizedEntry(t *testing.T) {
	entries := []ZoneDigest{{
		Zone:     zone.ZonePath("very-long-node-name-that-cannot-fit-small-budget.catofes."),
		RootHash: bytes.Repeat([]byte{1}, 32),
	}}
	_, err := CatalogPageForDigests(entries, "", 80)
	if !errors.Is(err, ErrCatalogPageTooLarge) {
		t.Fatalf("CatalogPageForDigests err=%v, want ErrCatalogPageTooLarge", err)
	}
}

func TestCatalogSyncMessagesFitDatagramBudget(t *testing.T) {
	var digests []ZoneDigest
	for i := range 80 {
		digests = append(digests, ZoneDigest{
			Zone:     zone.ZonePath("node-" + string(rune('a'+i%26)) + "-" + string(rune('a'+i/26)) + ".catofes."),
			RootHash: bytes.Repeat([]byte{byte(i)}, 32),
		})
	}
	summary := &CatalogSummary{CatalogRoot: CatalogRoot(digests), ZoneCount: len(digests)}
	if size := MessageWireSize(&Message{Type: MessagePing, Ping: &Ping{Summary: summary}}); size > DefaultDatagramBudget {
		t.Fatalf("catalog summary ping size=%d exceeds %d", size, DefaultDatagramBudget)
	}
	for cursor := ""; ; {
		page, err := CatalogPageForDigests(digests, cursor, DefaultDatagramBudget)
		if err != nil {
			t.Fatalf("CatalogPageForDigests(%q): %v", cursor, err)
		}
		if size := MessageWireSize(&Message{Type: MessageCatalogPage, CatalogPage: page}); size > DefaultDatagramBudget {
			t.Fatalf("catalog page size=%d exceeds %d", size, DefaultDatagramBudget)
		}
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
	}
}
