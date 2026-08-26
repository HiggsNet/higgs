package gossip

import (
	"bytes"
	"fmt"
	"strconv"

	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
)

var ErrCatalogPageTooLarge = fmt.Errorf("catalog page exceeds datagram budget")

func CatalogRoot(entries []ZoneDigest) []byte {
	parts := make([][]byte, 0, 1+len(entries)*3)
	parts = append(parts, []byte("photon.catalog.v1"))
	for _, entry := range entries {
		parts = append(parts, []byte(entry.Zone), entry.RootHash)
	}
	return photoncrypto.Hash(parts...)
}

func CatalogSummaryFor(ns *zone.NetworkState, budget int) (*CatalogSummary, error) {
	return CatalogSummaryForDigests(ZoneDigests(ns), budget)
}

// CatalogSummaryForDigests builds a catalog summary from an already computed
// digest projection. Callers that need both values can avoid hashing every
// zone twice while retaining the same catalog-root construction.
func CatalogSummaryForDigests(entries []ZoneDigest, budget int) (*CatalogSummary, error) {
	root := CatalogRoot(entries)
	return &CatalogSummary{
		CatalogRoot: root,
		ZoneCount:   len(entries),
	}, nil
}

func CatalogPageFor(ns *zone.NetworkState, cursor string, budget int, senderPeerID string) (*CatalogPage, error) {
	return CatalogPageForDigests(ZoneDigests(ns), cursor, budget, senderPeerID)
}

// CatalogPageForDigests builds a page that remains within budget after
// Transport.Send installs senderPeerID and full-width nonce/timestamp fields.
func CatalogPageForDigests(entries []ZoneDigest, cursor string, budget int, senderPeerID string) (*CatalogPage, error) {
	if budget <= 0 {
		budget = DefaultDatagramBudget
	}
	start, err := parseCatalogCursor(cursor, len(entries))
	if err != nil {
		return nil, err
	}
	root := CatalogRoot(entries)
	page := &CatalogPage{CatalogRoot: root}
	for i := start; i < len(entries); i++ {
		next := &CatalogPage{
			CatalogRoot: root,
			Entries:     append(append([]ZoneDigest(nil), page.Entries...), entries[i]),
		}
		if i+1 < len(entries) {
			next.NextCursor = strconv.Itoa(i + 1)
		}
		size, err := WireEncodeSizeForPeer(&Message{Type: MessageCatalogPage, CatalogPage: next}, senderPeerID)
		if err != nil {
			return nil, err
		}
		if size > budget {
			if len(page.Entries) == 0 {
				return nil, fmt.Errorf("%w: cursor=%q zone=%s bytes=%d limit=%d", ErrCatalogPageTooLarge, cursor, entries[i].Zone, size, budget)
			}
			page.NextCursor = strconv.Itoa(i)
			return page, nil
		}
		page = next
	}
	return page, nil
}

func CatalogDiff(local []ZoneDigest, remote []ZoneDigest) []ZoneDigest {
	localByZone := make(map[zone.ZonePath][]byte, len(local))
	for _, entry := range local {
		localByZone[entry.Zone] = entry.RootHash
	}
	var out []ZoneDigest
	for _, entry := range remote {
		if !entry.Zone.Valid() {
			continue
		}
		if !bytes.Equal(localByZone[entry.Zone], entry.RootHash) {
			out = append(out, entry)
		}
	}
	return out
}

func parseCatalogCursor(cursor string, length int) (int, error) {
	if cursor == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(cursor)
	if err != nil || n < 0 || n > length {
		return 0, fmt.Errorf("invalid catalog cursor %q", cursor)
	}
	return n, nil
}
