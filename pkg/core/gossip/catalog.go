package gossip

import (
	"fmt"
	"strconv"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
)

var ErrCatalogPageTooLarge = fmt.Errorf("catalog page exceeds datagram budget")

func CatalogPageForDigests(entries []corestate.ZoneDigest, cursor string, budget int) (*corestate.CatalogPage, error) {
	if budget <= 0 {
		budget = DefaultDatagramBudget
	}
	start, err := parseCatalogCursor(cursor, len(entries))
	if err != nil {
		return nil, err
	}
	root := corestate.CatalogRoot(entries)
	page := &corestate.CatalogPage{CatalogRoot: root}
	for i := start; i < len(entries); i++ {
		next := &corestate.CatalogPage{
			CatalogRoot: root,
			Entries:     append(append([]corestate.ZoneDigest(nil), page.Entries...), entries[i]),
		}
		if i+1 < len(entries) {
			next.NextCursor = strconv.Itoa(i + 1)
		}
		size, err := WireEncodeSize(&Message{Type: MessageCatalogPage, CatalogPage: next})
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
