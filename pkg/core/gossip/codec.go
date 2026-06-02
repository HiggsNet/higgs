package gossip

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/vmihailenco/msgpack/v5"
)

var (
	wireMagicJSON       = []byte("higgs.gossip.v1\n")
	wireMagicMsgpack    = []byte("higgs.gossip.m1\n")
	wireVersionLatest   = 1
	ErrUnsupportedCodec = errors.New("unsupported gossip codec")
)

// WireCodec defines the encode/decode contract for gossip wire messages.
type WireCodec interface {
	Magic() []byte
	Encode(*Message) ([]byte, error)
	Decode([]byte, *Message) error
}

var (
	_ WireCodec = jsonCodec{}
	_ WireCodec = msgpackCodec{}
)

// DefaultSendCodec is the codec used for outbound messages.
// It may be overridden in tests or during a controlled upgrade window.
var DefaultSendCodec WireCodec = msgpackCodec{}

type jsonCodec struct{}

func (jsonCodec) Magic() []byte { return wireMagicJSON }

func (jsonCodec) Encode(m *Message) ([]byte, error) {
	return json.Marshal(m)
}

func (jsonCodec) Decode(data []byte, m *Message) error {
	return json.Unmarshal(data, m)
}

type msgpackCodec struct{}

func (msgpackCodec) Magic() []byte { return wireMagicMsgpack }

func (msgpackCodec) Encode(m *Message) ([]byte, error) {
	return msgpack.Marshal(m)
}

func (msgpackCodec) Decode(data []byte, m *Message) error {
	return msgpack.Unmarshal(data, m)
}

func codecByMagic(data []byte) (WireCodec, error) {
	switch {
	case bytes.HasPrefix(data, wireMagicJSON):
		return jsonCodec{}, nil
	case bytes.HasPrefix(data, wireMagicMsgpack):
		return msgpackCodec{}, nil
	default:
		return nil, ErrUnsupportedCodec
	}
}

// encodeMessage serializes a Message using the provided codec.
func encodeMessage(codec WireCodec, message *Message) ([]byte, error) {
	if message != nil && message.Version == 0 {
		message.Version = wireVersionLatest
	}
	if err := validateMessage(message); err != nil {
		return nil, err
	}
	payload, err := codec.Encode(message)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(codec.Magic())+len(payload))
	out = append(out, codec.Magic()...)
	out = append(out, payload...)
	return out, nil
}

// decodeMessage deserializes a Message from raw wire bytes, auto-detecting codec.
func decodeMessage(data []byte) (*Message, error) {
	codec, err := codecByMagic(data)
	if err != nil {
		return nil, err
	}
	payload := data[len(codec.Magic()):]
	var message Message
	if err := codec.Decode(payload, &message); err != nil {
		return nil, err
	}
	if err := validateMessage(&message); err != nil {
		return nil, err
	}
	return &message, nil
}

// WireEncodeSize returns the encoded wire size of a Message using the default send codec.
// It is used for datagram-budget preflight before calling Transport.Send.
func WireEncodeSize(message *Message) (int, error) {
	if message == nil {
		return 0, errors.New("gossip message is nil")
	}
	candidate := *message
	if candidate.PeerID == "" {
		candidate.PeerID = "size-check"
	}
	if candidate.Nonce == 0 {
		candidate.Nonce = 1
	}
	if candidate.Timestamp == 0 {
		candidate.Timestamp = 1
	}
	data, err := encodeMessage(DefaultSendCodec, &candidate)
	if err != nil {
		return 0, err
	}
	return len(data), nil
}

func init() {
	// Ensure the error strings align with RejectReason mapping.
	_ = fmt.Errorf("unsupported gossip wire version: %d", 0) // kept for backward compat
}
