package gossip

import "testing"

func TestRoutePacketHitsActiveSession(t *testing.T) {
	session := NewSyncSession("peer-a")
	sessions := map[string]*SyncSession{"peer-a": session}
	packet := &Packet{Message: &Message{Type: MessagePing, PeerID: "peer-a"}}

	event := RoutePacket(packet, sessions)
	active, ok := event.(*PacketEvent)
	if !ok {
		t.Fatalf("event = %T, want *PacketEvent", event)
	}
	if active.Session != session || active.Packet != packet {
		t.Fatalf("active event = %#v", active)
	}
}

func TestRoutePacketMissBecomesUnsolicited(t *testing.T) {
	packet := &Packet{Message: &Message{Type: MessagePing, PeerID: "peer-a"}}
	event := RoutePacket(packet, nil)
	unsolicited, ok := event.(*UnsolicitedPacketEvent)
	if !ok {
		t.Fatalf("event = %T, want *UnsolicitedPacketEvent", event)
	}
	if unsolicited.Packet != packet {
		t.Fatalf("packet = %#v, want %#v", unsolicited.Packet, packet)
	}
}

func TestRoutePacketNilMessageIsUnsolicited(t *testing.T) {
	event := RoutePacket(&Packet{}, map[string]*SyncSession{})
	if _, ok := event.(*UnsolicitedPacketEvent); !ok {
		t.Fatalf("event = %T, want *UnsolicitedPacketEvent", event)
	}
}

func TestRoutePacketNilPacketIsUnsolicited(t *testing.T) {
	event := RoutePacket(nil, map[string]*SyncSession{})
	unsolicited, ok := event.(*UnsolicitedPacketEvent)
	if !ok || unsolicited.Packet != nil {
		t.Fatalf("event = %#v, want nil-packet unsolicited event", event)
	}
}

func TestRoutePacketIgnoresNilSessionEntry(t *testing.T) {
	packet := &Packet{Message: &Message{Type: MessagePing, PeerID: "peer-a"}}
	event := RoutePacket(packet, map[string]*SyncSession{"peer-a": nil})
	if _, ok := event.(*UnsolicitedPacketEvent); !ok {
		t.Fatalf("event = %T, want *UnsolicitedPacketEvent", event)
	}
}
