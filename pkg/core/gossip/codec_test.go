package gossip

import (
	"bytes"
	"testing"

	"github.com/Catofes/higgs/pkg/core/zone"
)

func TestMsgpackCodecRoundTrip(t *testing.T) {
	message := &Message{
		Type:      MessagePing,
		PeerID:    "node-a",
		Nonce:     42,
		Timestamp: 1717171717,
		Ping: &Ping{Zones: []ZoneDigest{{
			Zone:     "catofes.",
			RootHash: []byte{1, 2, 3, 4},
		}}},
	}
	codec := msgpackCodec{}
	data, err := encodeMessage(codec, message)
	if err != nil {
		t.Fatalf("encodeMessage: %v", err)
	}
	if !bytes.HasPrefix(data, wireMagicMsgpack) {
		t.Fatalf("expected msgpack magic prefix, got %q", data[:len(wireMagicMsgpack)])
	}
	got, err := decodeMessage(data)
	if err != nil {
		t.Fatalf("decodeMessage: %v", err)
	}
	if got.Type != MessagePing || got.PeerID != "node-a" || got.Nonce != 42 {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
	if len(got.Ping.Zones) != 1 || got.Ping.Zones[0].Zone != "catofes." {
		t.Fatalf("digest mismatch: %+v", got.Ping.Zones)
	}
}

func TestJSONCodecBackwardCompat(t *testing.T) {
	message := &Message{
		Type:      MessagePong,
		PeerID:    "node-b",
		Nonce:     7,
		Timestamp: 1717171717,
		Pong: &Pong{
			Zones:      []ZoneDigest{{Zone: "catofes.", RootHash: []byte{5}}},
			FetchZones: []zone.ZonePath{"test."},
		},
	}
	codec := jsonCodec{}
	data, err := encodeMessage(codec, message)
	if err != nil {
		t.Fatalf("encodeMessage: %v", err)
	}
	if !bytes.HasPrefix(data, wireMagicJSON) {
		t.Fatalf("expected JSON magic prefix, got %q", data[:len(wireMagicJSON)])
	}
	got, err := decodeMessage(data)
	if err != nil {
		t.Fatalf("decodeMessage: %v", err)
	}
	if got.Type != MessagePong || len(got.Pong.FetchZones) != 1 {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
}

func TestUnknownCodecRejected(t *testing.T) {
	data := append([]byte("higgs.gossip.x9\n"), []byte(`{}`)...)
	_, err := decodeMessage(data)
	if err == nil {
		t.Fatalf("expected error for unknown codec")
	}
	if RejectReason(err) != "unsupported_codec" {
		t.Fatalf("RejectReason = %q, want unsupported_codec; err=%v", RejectReason(err), err)
	}
}

func TestDefaultSendCodecIsMsgpack(t *testing.T) {
	if _, ok := DefaultSendCodec.(msgpackCodec); !ok {
		t.Fatalf("DefaultSendCodec should be msgpackCodec, got %T", DefaultSendCodec)
	}
}

func BenchmarkPingJSON(b *testing.B) {
	message := &Message{
		Type:      MessagePing,
		PeerID:    "node-a.catofes.",
		Nonce:     123456789,
		Timestamp: 1717171717,
		Ping: &Ping{Zones: []ZoneDigest{
			{Zone: "catofes.", RootHash: make([]byte, 32)},
			{Zone: "node-a.catofes.", RootHash: make([]byte, 32)},
		}},
	}
	codec := jsonCodec{}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = encodeMessage(codec, message)
	}
}

func BenchmarkPingMsgpack(b *testing.B) {
	message := &Message{
		Type:      MessagePing,
		PeerID:    "node-a.catofes.",
		Nonce:     123456789,
		Timestamp: 1717171717,
		Ping: &Ping{Zones: []ZoneDigest{
			{Zone: "catofes.", RootHash: make([]byte, 32)},
			{Zone: "node-a.catofes.", RootHash: make([]byte, 32)},
		}},
	}
	codec := msgpackCodec{}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = encodeMessage(codec, message)
	}
}

func TestMsgpackSmallerThanJSON(t *testing.T) {
	message := &Message{
		Type:      MessageAnnounce,
		PeerID:    "node-a.catofes.",
		Nonce:     999,
		Timestamp: 1717171717,
		Announce: &Announce{
			Zones: []ZoneDigest{{Zone: "catofes.", RootHash: make([]byte, 32)}},
			Records: []RecordSnapshot{{
				Zone: "catofes.",
				Record: &zone.Record{
					Zone:      "catofes.",
					Key:       "identity",
					Type:      "node.identity",
					Value:     []byte("node-a"),
					ValueHash: make([]byte, 32),
					Version:   1,
					Timestamp: 1717171717,
					SignedBy:  make([]byte, 32),
					Signature: make([]byte, 64),
				},
			}},
		},
	}
	jsonData, _ := encodeMessage(jsonCodec{}, message)
	msgpackData, _ := encodeMessage(msgpackCodec{}, message)
	if len(msgpackData) >= len(jsonData) {
		t.Fatalf("msgpack (%d bytes) should be smaller than JSON (%d bytes)", len(msgpackData), len(jsonData))
	}
	t.Logf("JSON=%d bytes, MessagePack=%d bytes, savings=%d bytes", len(jsonData), len(msgpackData), len(jsonData)-len(msgpackData))
}
