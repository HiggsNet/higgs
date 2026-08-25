package gossip

import (
	"bytes"

	"github.com/HiggsNet/photon/pkg/core/zone"
)

type ReadOnlyRequestKind string

const (
	ReadOnlyFetchZone     ReadOnlyRequestKind = "fetch_zone"
	ReadOnlyChunkFallback ReadOnlyRequestKind = "chunk_fallback"
	ReadOnlyCatalogPage   ReadOnlyRequestKind = "catalog_page"
)

type ReadOnlyRequest struct {
	Kind ReadOnlyRequestKind
	Zone zone.ZonePath
}

// ClassifyReadOnlyRequest identifies messages that only read local verified
// state to construct a response. It rejects message types with missing payloads.
func ClassifyReadOnlyRequest(message *Message) (ReadOnlyRequest, bool) {
	if message == nil {
		return ReadOnlyRequest{}, false
	}
	switch message.Type {
	case MessageFetchZone:
		if message.FetchZone == nil {
			return ReadOnlyRequest{}, false
		}
		kind := ReadOnlyFetchZone
		if message.FetchZone.ChunkFallback {
			kind = ReadOnlyChunkFallback
		}
		return ReadOnlyRequest{Kind: kind, Zone: message.FetchZone.Zone}, true
	case MessageFetchCatalogPage:
		if message.FetchCatalogPage == nil {
			return ReadOnlyRequest{}, false
		}
		return ReadOnlyRequest{Kind: ReadOnlyCatalogPage}, true
	default:
		return ReadOnlyRequest{}, false
	}
}

// CatalogRootsMatch reports whether two non-nil catalog summaries advertise
// the same root. ZoneCount is metadata and does not change root identity.
func CatalogRootsMatch(left, right *CatalogSummary) bool {
	return left != nil && right != nil && bytes.Equal(left.CatalogRoot, right.CatalogRoot)
}

// PlanPingResponse creates the ordered protocol responses for an inbound
// PING. The caller owns transport send, diagnostics and persistence.
func PlanPingResponse(ping *Ping, localSummary *CatalogSummary) []*Message {
	if ping == nil || localSummary == nil {
		return nil
	}
	messages := []*Message{{
		Type: MessagePong,
		Pong: &Pong{Summary: localSummary},
	}}
	if ping.Summary != nil && !CatalogRootsMatch(ping.Summary, localSummary) {
		messages = append(messages, &Message{
			Type:             MessageFetchCatalogPage,
			FetchCatalogPage: &FetchCatalogPage{},
		})
	}
	return messages
}
