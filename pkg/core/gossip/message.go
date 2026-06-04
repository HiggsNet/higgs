package gossip

import (
	"errors"
	"fmt"

	"github.com/Catofes/higgs/pkg/core/zone"
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
	MessagePing        MessageType = "ping"
	MessagePong        MessageType = "pong"
	MessageFetchZone   MessageType = "fetch_zone"
	MessageFetchRecord MessageType = "fetch_record"
	MessageAnnounce    MessageType = "announce"
	MessageObjectChunk MessageType = "object_chunk"
)

type Message struct {
	Version   int         `json:"version" msgpack:"v"`
	Type      MessageType `json:"type" msgpack:"t"`
	PeerID    string      `json:"peer_id" msgpack:"p"`
	Nonce     uint64      `json:"nonce" msgpack:"n"`
	Timestamp int64       `json:"timestamp" msgpack:"ts"`

	Ping        *Ping        `json:"ping,omitempty" msgpack:"g,omitempty"`
	Pong        *Pong        `json:"pong,omitempty" msgpack:"o,omitempty"`
	FetchZone   *FetchZone   `json:"fetch_zone,omitempty" msgpack:"f,omitempty"`
	FetchRecord *FetchRecord `json:"fetch_record,omitempty" msgpack:"r,omitempty"`
	Announce    *Announce    `json:"announce,omitempty" msgpack:"a,omitempty"`
	ObjectChunk *ObjectChunk `json:"object_chunk,omitempty" msgpack:"c,omitempty"`
}

type ZoneDigest struct {
	Zone     zone.ZonePath `json:"zone" msgpack:"z"`
	RootHash []byte        `json:"root_hash" msgpack:"h"`
}

type Ping struct {
	Zones []ZoneDigest `json:"zones" msgpack:"z"`
}

type Pong struct {
	Zones      []ZoneDigest    `json:"zones,omitempty" msgpack:"z,omitempty"`
	FetchZones []zone.ZonePath `json:"fetch_zones" msgpack:"fz"`
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
	Zones     []ZoneDigest     `json:"zones,omitempty" msgpack:"z,omitempty"`
	Snapshots []ZoneSnapshot   `json:"snapshots,omitempty" msgpack:"s,omitempty"`
	Records   []RecordSnapshot `json:"records,omitempty" msgpack:"r,omitempty"`
}

type ObjectChunk struct {
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

type RecordSnapshot struct {
	Zone   zone.ZonePath `json:"zone" msgpack:"z"`
	Record *zone.Record  `json:"record" msgpack:"r"`
}

type ZoneSnapshot struct {
	Zone          zone.ZonePath                                `json:"zone" msgpack:"z"`
	Authority     *zone.ZoneAuthority                          `json:"authority" msgpack:"a"`
	ParentProof   []*zone.Delegation                           `json:"parent_proof,omitempty" msgpack:"pp,omitempty"`
	Delegations   map[zone.ZonePath]*zone.Delegation           `json:"delegations,omitempty" msgpack:"d,omitempty"`
	Revocations   map[zone.ZonePath]*zone.DelegationRevocation `json:"revocations,omitempty" msgpack:"rv,omitempty"`
	Records       map[string]*zone.Record                      `json:"records,omitempty" msgpack:"rc,omitempty"`
	RecordHistory map[string][]*zone.Record                    `json:"record_history,omitempty" msgpack:"rh,omitempty"`
}

// MarshalMessage encodes a Message using the default send codec (MessagePack).
func MarshalMessage(message *Message) ([]byte, error) {
	return encodeMessage(DefaultSendCodec, message)
}

// UnmarshalMessage decodes a Message from raw wire bytes, auto-detecting codec.
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
		message.Announce != nil,
		message.ObjectChunk != nil,
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
	case MessageAnnounce:
		if message.Announce == nil {
			return errors.New("announce message missing announce body")
		}
	case MessageObjectChunk:
		if message.ObjectChunk == nil || !message.ObjectChunk.Zone.Valid() || len(message.ObjectChunk.ObjectHash) == 0 || message.ObjectChunk.Total == 0 || message.ObjectChunk.Index >= message.ObjectChunk.Total || len(message.ObjectChunk.Data) == 0 {
			return errors.New("object_chunk message has invalid chunk")
		}
		if message.ObjectChunk.Object != ObjectPullZone && message.ObjectChunk.Object != ObjectPullRecord {
			return errors.New("object_chunk message has invalid object type")
		}
	default:
		return fmt.Errorf("unknown gossip message type: %s", message.Type)
	}
	return nil
}
