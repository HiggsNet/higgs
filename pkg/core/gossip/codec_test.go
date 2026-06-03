package gossip

import (
	"bytes"
	"crypto/ed25519"
	"net"
	"testing"
	"time"

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

func TestTypicalMessagePackSizesBeatJSON(t *testing.T) {
	digest := ZoneDigest{Zone: "node-a.catofes.", RootHash: make([]byte, 32)}
	record := sampleWireRecord("identity", []byte("node-a"))
	endpointValue := EndpointRecordBytes([]LocalEndpoint{{
		IP:       net.ParseIP("192.0.2.10"),
		Port:     33434,
		Scope:    "global",
		Priority: 100,
		Source:   SourceAdvertise,
	}}, time.Unix(1717171717, 0))
	endpointRecord := sampleWireRecord(EndpointRecordKeyUDP, endpointValue)
	delegation := sampleWireDelegation("node-b.catofes.")
	revocation := sampleWireRevocation("node-b.catofes.")
	authority := sampleWireAuthority("catofes.")

	cases := []struct {
		name    string
		message *Message
	}{
		{
			name:    "ping digests",
			message: commonWireMessage(MessagePing, &Ping{Zones: []ZoneDigest{digest}}, nil, nil, nil, nil),
		},
		{
			name:    "pong fetch zones",
			message: commonWireMessage(MessagePong, nil, &Pong{Zones: []ZoneDigest{digest}, FetchZones: []zone.ZonePath{"catofes.", "node-a.catofes."}}, nil, nil, nil),
		},
		{
			name:    "fetch zone",
			message: commonWireMessage(MessageFetchZone, nil, nil, &FetchZone{Zone: "node-a.catofes."}, nil, nil),
		},
		{
			name:    "fetch record",
			message: commonWireMessage(MessageFetchRecord, nil, nil, nil, &FetchRecord{Zone: "node-a.catofes.", Key: "identity", Version: 7}, nil),
		},
		{
			name:    "announce digest",
			message: commonWireMessage(MessageAnnounce, nil, nil, nil, nil, &Announce{Zones: []ZoneDigest{digest}}),
		},
		{
			name:    "announce record",
			message: commonWireMessage(MessageAnnounce, nil, nil, nil, nil, &Announce{Zones: []ZoneDigest{digest}, Records: []RecordSnapshot{{Zone: "node-a.catofes.", Record: record}}}),
		},
		{
			name:    "announce endpoint record",
			message: commonWireMessage(MessageAnnounce, nil, nil, nil, nil, &Announce{Zones: []ZoneDigest{digest}, Records: []RecordSnapshot{{Zone: "node-a.catofes.", Record: endpointRecord}}}),
		},
		{
			name: "announce metadata snapshot",
			message: commonWireMessage(MessageAnnounce, nil, nil, nil, nil, &Announce{Zones: []ZoneDigest{digest}, Snapshots: []ZoneSnapshot{{
				Zone:        "catofes.",
				Authority:   authority,
				ParentProof: []*zone.Delegation{delegation},
			}}}),
		},
		{
			name: "announce delegation snapshot",
			message: commonWireMessage(MessageAnnounce, nil, nil, nil, nil, &Announce{Zones: []ZoneDigest{digest}, Snapshots: []ZoneSnapshot{{
				Zone:        "catofes.",
				Authority:   authority,
				Delegations: map[zone.ZonePath]*zone.Delegation{"node-b.catofes.": delegation},
			}}}),
		},
		{
			name: "announce revocation snapshot",
			message: commonWireMessage(MessageAnnounce, nil, nil, nil, nil, &Announce{Zones: []ZoneDigest{digest}, Snapshots: []ZoneSnapshot{{
				Zone:        "catofes.",
				Authority:   authority,
				Revocations: map[zone.ZonePath]*zone.DelegationRevocation{"node-b.catofes.": revocation},
			}}}),
		},
	}

	for _, tc := range cases {
		jsonData, err := encodeMessage(jsonCodec{}, tc.message)
		if err != nil {
			t.Fatalf("%s JSON encode: %v", tc.name, err)
		}
		msgpackData, err := encodeMessage(msgpackCodec{}, tc.message)
		if err != nil {
			t.Fatalf("%s MessagePack encode: %v", tc.name, err)
		}
		if len(msgpackData) >= len(jsonData) {
			t.Fatalf("%s MessagePack size = %d, want less than JSON size %d", tc.name, len(msgpackData), len(jsonData))
		}
		t.Logf("%s JSON=%d MessagePack=%d savings=%d", tc.name, len(jsonData), len(msgpackData), len(jsonData)-len(msgpackData))
	}
}

func TestCommonMessageSizesWithinDatagramBudget(t *testing.T) {
	digest := ZoneDigest{Zone: "node-a.catofes.", RootHash: make([]byte, 32)}
	record := sampleWireRecord("identity", []byte("node-a"))
	endpointValue := EndpointRecordBytes([]LocalEndpoint{{
		IP:       net.ParseIP("192.0.2.10"),
		Port:     33434,
		Scope:    "global",
		Priority: 100,
		Source:   SourceAdvertise,
	}}, time.Unix(1717171717, 0))
	endpointRecord := sampleWireRecord(EndpointRecordKeyUDP, endpointValue)
	delegation := sampleWireDelegation("node-b.catofes.")
	revocation := sampleWireRevocation("node-b.catofes.")
	authority := sampleWireAuthority("catofes.")

	cases := []struct {
		name    string
		message *Message
	}{
		{
			name:    "ping",
			message: commonWireMessage(MessagePing, &Ping{Zones: []ZoneDigest{digest}}, nil, nil, nil, nil),
		},
		{
			name:    "pong",
			message: commonWireMessage(MessagePong, nil, &Pong{Zones: []ZoneDigest{digest}, FetchZones: []zone.ZonePath{"catofes."}}, nil, nil, nil),
		},
		{
			name: "metadata snapshot",
			message: commonWireMessage(MessageAnnounce, nil, nil, nil, nil, &Announce{Zones: []ZoneDigest{digest}, Snapshots: []ZoneSnapshot{{
				Zone:        "catofes.",
				Authority:   authority,
				ParentProof: []*zone.Delegation{delegation},
			}}}),
		},
		{
			name:    "single record",
			message: commonWireMessage(MessageAnnounce, nil, nil, nil, nil, &Announce{Zones: []ZoneDigest{digest}, Records: []RecordSnapshot{{Zone: "node-a.catofes.", Record: record}}}),
		},
		{
			name:    "endpoint record",
			message: commonWireMessage(MessageAnnounce, nil, nil, nil, nil, &Announce{Zones: []ZoneDigest{digest}, Records: []RecordSnapshot{{Zone: "node-a.catofes.", Record: endpointRecord}}}),
		},
		{
			name: "delegation snapshot",
			message: commonWireMessage(MessageAnnounce, nil, nil, nil, nil, &Announce{Zones: []ZoneDigest{digest}, Snapshots: []ZoneSnapshot{{
				Zone:        "catofes.",
				Authority:   authority,
				Delegations: map[zone.ZonePath]*zone.Delegation{"node-b.catofes.": delegation},
			}}}),
		},
		{
			name: "revocation snapshot",
			message: commonWireMessage(MessageAnnounce, nil, nil, nil, nil, &Announce{Zones: []ZoneDigest{digest}, Snapshots: []ZoneSnapshot{{
				Zone:        "catofes.",
				Authority:   authority,
				Revocations: map[zone.ZonePath]*zone.DelegationRevocation{"node-b.catofes.": revocation},
			}}}),
		},
	}

	for _, tc := range cases {
		size, err := WireEncodeSize(tc.message)
		if err != nil {
			t.Fatalf("%s WireEncodeSize: %v", tc.name, err)
		}
		t.Logf("%s wire size: %d bytes, headroom: %d bytes", tc.name, size, DefaultDatagramBudget-size)
		if size > DefaultDatagramBudget {
			t.Fatalf("%s wire size = %d bytes, exceeds %d-byte datagram budget", tc.name, size, DefaultDatagramBudget)
		}
	}
}

func commonWireMessage(messageType MessageType, ping *Ping, pong *Pong, fetchZone *FetchZone, fetchRecord *FetchRecord, announce *Announce) *Message {
	return &Message{
		Version:     WireVersion,
		Type:        messageType,
		PeerID:      "node-a.catofes.",
		Nonce:       123456789,
		Timestamp:   1717171717,
		Ping:        ping,
		Pong:        pong,
		FetchZone:   fetchZone,
		FetchRecord: fetchRecord,
		Announce:    announce,
	}
}

func sampleWireAuthority(path zone.ZonePath) *zone.ZoneAuthority {
	return &zone.ZoneAuthority{
		Zone:      path,
		Epoch:     1,
		Threshold: 1,
		Keys: []zone.AuthorizedKey{{
			Key: make(ed25519.PublicKey, ed25519.PublicKeySize),
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermWrite, zone.PermDelegate},
			}},
		}},
	}
}

func sampleWireDelegation(path zone.ZonePath) *zone.Delegation {
	return &zone.Delegation{
		ZoneName:       path,
		Scope:          zone.DelegationScopeDirectChild,
		AuthorityEpoch: 1,
		AuthorityHash:  make([]byte, 32),
		Authority:      *sampleWireAuthority(path),
		SignedBy:       make(ed25519.PublicKey, ed25519.PublicKeySize),
		Signature:      make([]byte, ed25519.SignatureSize),
	}
}

func sampleWireRevocation(path zone.ZonePath) *zone.DelegationRevocation {
	return &zone.DelegationRevocation{
		ChildZone:             path,
		ParentZone:            "catofes.",
		RevokedAuthorityEpoch: 1,
		RevokedAuthorityHash:  make([]byte, 32),
		Reason:                "key rotation",
		RevokedAt:             1717171717,
		SignedBy:              make(ed25519.PublicKey, ed25519.PublicKeySize),
		Signature:             make([]byte, ed25519.SignatureSize),
	}
}

func sampleWireRecord(key string, value []byte) *zone.Record {
	return &zone.Record{
		Zone:      "node-a.catofes.",
		Key:       key,
		Type:      "test.record",
		Value:     value,
		ValueHash: make([]byte, 32),
		Version:   1,
		Timestamp: 1717171717,
		SignedBy:  make(ed25519.PublicKey, ed25519.PublicKeySize),
		Signature: make([]byte, ed25519.SignatureSize),
	}
}
