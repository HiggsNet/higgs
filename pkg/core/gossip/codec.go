package gossip

import (
	"bytes"
	"errors"
	"math"

	"github.com/vmihailenco/msgpack/v5"
)

var (
	wireMagicMsgpack    = []byte("photon.gossip.m1\n")
	wireVersionLatest   = 1
	ErrUnsupportedCodec = errors.New("unsupported gossip codec")
)

// WireCodec defines the encode/decode contract for gossip wire messages.
type WireCodec interface {
	Magic() []byte
	Encode(*Message) ([]byte, error)
	Decode([]byte, *Message) error
}

var _ WireCodec = msgpackCodec{}

// DefaultSendCodec is the codec used for outbound messages.
var DefaultSendCodec WireCodec = msgpackCodec{}

type msgpackCodec struct{}

func (msgpackCodec) Magic() []byte { return wireMagicMsgpack }

func (msgpackCodec) Encode(m *Message) ([]byte, error) {
	return msgpack.Marshal(m)
}

func (msgpackCodec) Decode(data []byte, m *Message) error {
	return msgpack.Unmarshal(data, m)
}

func codecByMagic(data []byte) (WireCodec, error) {
	if bytes.HasPrefix(data, wireMagicMsgpack) {
		return msgpackCodec{}, nil
	}
	return nil, ErrUnsupportedCodec
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

// decodeMessage deserializes a MessagePack Message from raw wire bytes.
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

// WireEncodeSize returns a conservative encoded wire size using a synthetic
// sender identity. Callers that enforce a datagram budget for a real outbound
// message should use WireEncodeSizeForPeer so the sender envelope is exact.
func WireEncodeSize(message *Message) (int, error) {
	return WireEncodeSizeForPeer(message, "size-check")
}

// WireEncodeSizeForPeer returns the encoded wire size of message with the
// sender identity that Transport.Send will install. Max-width nonce and
// timestamp values reserve the largest MessagePack integer representation, so
// a page accepted by a builder cannot grow beyond its budget at send time.
func WireEncodeSizeForPeer(message *Message, senderPeerID string) (int, error) {
	if message == nil {
		return 0, errors.New("gossip message is nil")
	}
	candidate := *message
	if senderPeerID != "" {
		candidate.PeerID = senderPeerID
	} else if candidate.PeerID == "" {
		candidate.PeerID = "size-check"
	}
	if candidate.Nonce == 0 {
		candidate.Nonce = math.MaxUint64
	}
	if candidate.Timestamp == 0 {
		candidate.Timestamp = math.MaxInt64
	}
	data, err := encodeMessage(DefaultSendCodec, &candidate)
	if err != nil {
		return 0, err
	}
	return len(data), nil
}
