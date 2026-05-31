package gossip

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/Catofes/higgs/pkg/core/zone"
)

const (
	DefaultPort       = 33434
	DefaultWindow     = 5 * 60
	DefaultMaxMessage = 64 << 10
	WireVersion       = 1
)

var wireMagic = []byte("higgs.gossip.v1\n")

type MessageType string

const (
	MessagePing        MessageType = "ping"
	MessagePong        MessageType = "pong"
	MessageFetchZone   MessageType = "fetch_zone"
	MessageFetchRecord MessageType = "fetch_record"
	MessageAnnounce    MessageType = "announce"
)

type Message struct {
	Version   int         `json:"version"`
	Type      MessageType `json:"type"`
	PeerID    string      `json:"peer_id"`
	Nonce     uint64      `json:"nonce"`
	Timestamp int64       `json:"timestamp"`

	Ping        *Ping        `json:"ping,omitempty"`
	Pong        *Pong        `json:"pong,omitempty"`
	FetchZone   *FetchZone   `json:"fetch_zone,omitempty"`
	FetchRecord *FetchRecord `json:"fetch_record,omitempty"`
	Announce    *Announce    `json:"announce,omitempty"`
}

type ZoneDigest struct {
	Zone     zone.ZonePath `json:"zone"`
	RootHash []byte        `json:"root_hash"`
}

type Ping struct {
	Zones []ZoneDigest `json:"zones"`
}

type Pong struct {
	Zones      []ZoneDigest    `json:"zones,omitempty"`
	FetchZones []zone.ZonePath `json:"fetch_zones"`
}

type FetchZone struct {
	Zone zone.ZonePath `json:"zone"`
}

type FetchRecord struct {
	Zone    zone.ZonePath `json:"zone"`
	Key     string        `json:"key"`
	Version uint64        `json:"version,omitempty"`
}

type Announce struct {
	Zones     []ZoneDigest     `json:"zones,omitempty"`
	Snapshots []ZoneSnapshot   `json:"snapshots,omitempty"`
	Records   []RecordSnapshot `json:"records,omitempty"`
}

type RecordSnapshot struct {
	Zone   zone.ZonePath `json:"zone"`
	Record *zone.Record  `json:"record"`
}

type ZoneSnapshot struct {
	Zone           zone.ZonePath                      `json:"zone"`
	Authority      *zone.ZoneAuthority                `json:"authority"`
	ParentProof    []*zone.Delegation                 `json:"parent_proof,omitempty"`
	Delegations    map[zone.ZonePath]*zone.Delegation `json:"delegations,omitempty"`
	Records        map[string]*zone.Record            `json:"records,omitempty"`
	RecordHistory  map[string][]*zone.Record          `json:"record_history,omitempty"`
	PendingRecords map[string][]*zone.Record          `json:"pending_records,omitempty"`
}

func MarshalMessage(message *Message) ([]byte, error) {
	if message != nil && message.Version == 0 {
		message.Version = WireVersion
	}
	if err := validateMessage(message); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(message)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(wireMagic)+len(payload))
	out = append(out, wireMagic...)
	out = append(out, payload...)
	return out, nil
}

func UnmarshalMessage(data []byte) (*Message, error) {
	if !bytes.HasPrefix(data, wireMagic) {
		return nil, errors.New("gossip message has invalid magic")
	}
	var message Message
	if err := json.Unmarshal(data[len(wireMagic):], &message); err != nil {
		return nil, err
	}
	if err := validateMessage(&message); err != nil {
		return nil, err
	}
	return &message, nil
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
	default:
		return fmt.Errorf("unknown gossip message type: %s", message.Type)
	}
	return nil
}
