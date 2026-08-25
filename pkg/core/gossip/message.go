package gossip

import (
	"errors"
	"fmt"

	"github.com/HiggsNet/photon/pkg/core/zone"
)

const (
	DefaultPort           = 33434
	DefaultWindow         = 5 * 60
	DefaultMaxMessage     = 1200 // conservative datagram budget; IPv6 + NAT + tunnel safe
	DefaultDatagramBudget = 1200 // alias for clarity in new code
	WireVersion           = 1
)

type MessageType string

const (
	MessagePing             MessageType = "ping"
	MessagePong             MessageType = "pong"
	MessageFetchZone        MessageType = "fetch_zone"
	MessageFetchRecord      MessageType = "fetch_record"
	MessageFetchCatalogPage MessageType = "fetch_catalog_page"
	MessageCatalogPage      MessageType = "catalog_page"
	MessageAnnounce         MessageType = "announce"
	MessageObjectChunk      MessageType = "object_chunk"
	MessageObjectChunkNACK  MessageType = "object_chunk_nack"
)

type Message struct {
	Version   int         `json:"version" msgpack:"v"`
	Type      MessageType `json:"type" msgpack:"t"`
	PeerID    string      `json:"peer_id" msgpack:"p"`
	Nonce     uint64      `json:"nonce" msgpack:"n"`
	Timestamp int64       `json:"timestamp" msgpack:"ts"`

	Ping             *Ping             `json:"ping,omitempty" msgpack:"g,omitempty"`
	Pong             *Pong             `json:"pong,omitempty" msgpack:"o,omitempty"`
	FetchZone        *FetchZone        `json:"fetch_zone,omitempty" msgpack:"f,omitempty"`
	FetchRecord      *FetchRecord      `json:"fetch_record,omitempty" msgpack:"r,omitempty"`
	FetchCatalogPage *FetchCatalogPage `json:"fetch_catalog_page,omitempty" msgpack:"fc,omitempty"`
	CatalogPage      *CatalogPage      `json:"catalog_page,omitempty" msgpack:"cp,omitempty"`
	Announce         *Announce         `json:"announce,omitempty" msgpack:"a,omitempty"`
	ObjectChunk      *ObjectChunk      `json:"object_chunk,omitempty" msgpack:"c,omitempty"`
	ObjectChunkNACK  *ObjectChunkNACK  `json:"object_chunk_nack,omitempty" msgpack:"cn,omitempty"`
}

type ZoneDigest struct {
	Zone     zone.ZonePath `json:"zone" msgpack:"z"`
	RootHash []byte        `json:"root_hash" msgpack:"h"`
}

type Ping struct {
	Summary *CatalogSummary `json:"summary,omitempty" msgpack:"s,omitempty"`
}

type Pong struct {
	Summary *CatalogSummary `json:"summary,omitempty" msgpack:"s,omitempty"`
}

type CatalogSummary struct {
	CatalogRoot []byte       `json:"catalog_root" msgpack:"r"`
	ZoneCount   int          `json:"zone_count" msgpack:"z"`
	FirstPage   *CatalogPage `json:"first_page,omitempty" msgpack:"p,omitempty"`
	NextCursor  string       `json:"next_cursor,omitempty" msgpack:"c,omitempty"`
}

type FetchCatalogPage struct {
	Cursor string `json:"cursor,omitempty" msgpack:"c,omitempty"`
}

type CatalogPage struct {
	CatalogRoot []byte       `json:"catalog_root" msgpack:"r"`
	Entries     []ZoneDigest `json:"entries" msgpack:"e"`
	NextCursor  string       `json:"next_cursor,omitempty" msgpack:"c,omitempty"`
}

type FetchZone struct {
	Zone          zone.ZonePath `json:"zone" msgpack:"z"`
	ChunkFallback bool          `json:"chunk_fallback,omitempty" msgpack:"c,omitempty"`
}

type FetchRecord struct {
	Zone    zone.ZonePath `json:"zone" msgpack:"z"`
	Key     string        `json:"key" msgpack:"k"`
	Version uint64        `json:"version,omitempty" msgpack:"v,omitempty"`
}

type Announce struct {
	Zones []ZoneDigest `json:"zones,omitempty" msgpack:"z,omitempty"`
}

type ObjectChunk struct {
	TransferID []byte                `json:"transfer_id" msgpack:"x"`
	Object     ObjectPullRequestType `json:"object" msgpack:"o"`
	Zone       zone.ZonePath         `json:"zone" msgpack:"z"`
	Key        string                `json:"key,omitempty" msgpack:"k,omitempty"`
	Version    uint64                `json:"version,omitempty" msgpack:"v,omitempty"`
	RootHash   []byte                `json:"root_hash,omitempty" msgpack:"rh,omitempty"`
	ObjectHash []byte                `json:"object_hash" msgpack:"h"`
	Index      uint16                `json:"index" msgpack:"i"`
	Total      uint16                `json:"total" msgpack:"t"`
	Data       []byte                `json:"data" msgpack:"d"`
}

// ObjectChunkNACK requests bounded retransmission of missing chunks from a
// recently advertised transfer. It never requests an object by selector: the
// sender must already have the exact transfer in its short-lived send cache.
type ObjectChunkNACK struct {
	TransferID []byte   `json:"transfer_id" msgpack:"x"`
	Missing    []uint16 `json:"missing" msgpack:"m"`
}

// MarshalMessage encodes a Message using the default send codec (MessagePack).
func MarshalMessage(message *Message) ([]byte, error) {
	return encodeMessage(DefaultSendCodec, message)
}

// UnmarshalMessage decodes a MessagePack Message from raw wire bytes.
func UnmarshalMessage(data []byte) (*Message, error) {
	return decodeMessage(data)
}

func validateMessage(message *Message) error {
	if message == nil {
		return errors.New("gossip message is nil")
	}
	if message.Version != 0 && message.Version != WireVersion {
		return fmt.Errorf("unsupported gossip wire version: %d", message.Version)
	}
	if message.PeerID == "" {
		return errors.New("gossip message peer id is empty")
	}
	if message.Nonce == 0 {
		return errors.New("gossip message nonce is empty")
	}
	if message.Timestamp == 0 {
		return errors.New("gossip message timestamp is empty")
	}

	bodies := 0
	for _, present := range []bool{
		message.Ping != nil,
		message.Pong != nil,
		message.FetchZone != nil,
		message.FetchRecord != nil,
		message.FetchCatalogPage != nil,
		message.CatalogPage != nil,
		message.Announce != nil,
		message.ObjectChunk != nil,
		message.ObjectChunkNACK != nil,
	} {
		if present {
			bodies++
		}
	}
	if bodies != 1 {
		return fmt.Errorf("gossip message must carry exactly one body, got %d", bodies)
	}

	switch message.Type {
	case MessagePing:
		if message.Ping == nil {
			return errors.New("ping message missing ping body")
		}
	case MessagePong:
		if message.Pong == nil {
			return errors.New("pong message missing pong body")
		}
	case MessageFetchZone:
		if message.FetchZone == nil || !message.FetchZone.Zone.Valid() {
			return errors.New("fetch_zone message has invalid zone")
		}
	case MessageFetchRecord:
		if message.FetchRecord == nil || !message.FetchRecord.Zone.Valid() || message.FetchRecord.Key == "" {
			return errors.New("fetch_record message has invalid selector")
		}
	case MessageFetchCatalogPage:
		if message.FetchCatalogPage == nil {
			return errors.New("fetch_catalog_page message missing body")
		}
	case MessageCatalogPage:
		if message.CatalogPage == nil || len(message.CatalogPage.CatalogRoot) == 0 {
			return errors.New("catalog_page message has invalid page")
		}
		for _, entry := range message.CatalogPage.Entries {
			if !entry.Zone.Valid() || len(entry.RootHash) == 0 {
				return errors.New("catalog_page message has invalid entry")
			}
		}
	case MessageAnnounce:
		if message.Announce == nil {
			return errors.New("announce message missing announce body")
		}
	case MessageObjectChunk:
		if message.ObjectChunk == nil || len(message.ObjectChunk.TransferID) != 16 || !message.ObjectChunk.Zone.Valid() || len(message.ObjectChunk.ObjectHash) == 0 || message.ObjectChunk.Total == 0 || message.ObjectChunk.Index >= message.ObjectChunk.Total || len(message.ObjectChunk.Data) == 0 {
			return errors.New("object_chunk message has invalid chunk")
		}
		if message.ObjectChunk.Object != ObjectPullZone && message.ObjectChunk.Object != ObjectPullRecord {
			return errors.New("object_chunk message has invalid object type")
		}
	case MessageObjectChunkNACK:
		if message.ObjectChunkNACK == nil || len(message.ObjectChunkNACK.TransferID) != 16 || len(message.ObjectChunkNACK.Missing) == 0 || len(message.ObjectChunkNACK.Missing) > 128 {
			return errors.New("object_chunk_nack message has invalid repair request")
		}
		seen := make(map[uint16]struct{}, len(message.ObjectChunkNACK.Missing))
		for _, index := range message.ObjectChunkNACK.Missing {
			if _, ok := seen[index]; ok {
				return errors.New("object_chunk_nack message has duplicate index")
			}
			seen[index] = struct{}{}
		}
	default:
		return fmt.Errorf("unknown gossip message type: %s", message.Type)
	}
	return nil
}
