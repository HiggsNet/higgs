package gossip

import (
	"bytes"
	"errors"
	"testing"

	"github.com/Catofes/higgs/pkg/core/zone"
)

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
