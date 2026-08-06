package main

import (
	"testing"

	"github.com/HiggsNet/photon/pkg/core/gossip"
)

func TestRoutePacketHitsActiveSession(t *testing.T) {
	session := NewSyncSession("peer-a")
	sessions := map[string]*SyncSession{"peer-a": session}

	packet := &gossip.Packet{
		Message: &gossip.Message{Type: gossip.MessagePing, PeerID: "peer-a"},
	}

	ev := routePacket(packet, sessions)
	pe, ok := ev.(*PacketEvent)
	if !ok {
		t.Fatalf("expected PacketEvent, got %T", ev)
	}
	if pe.Session != session {
		t.Fatal("packet routed to wrong session")
	}
	if pe.Packet != packet {
		t.Fatal("packet mismatch")
	}
}

func TestRoutePacketMissBecomesUnsolicited(t *testing.T) {
	sessions := map[string]*SyncSession{}
	packet := &gossip.Packet{
		Message: &gossip.Message{Type: gossip.MessagePing, PeerID: "peer-a"},
	}

	ev := routePacket(packet, sessions)
	ue, ok := ev.(*UnsolicitedPacketEvent)
	if !ok {
		t.Fatalf("expected UnsolicitedPacketEvent, got %T", ev)
	}
	if ue.Packet != packet {
		t.Fatal("packet mismatch")
	}
}

func TestRoutePacketNilMessage(t *testing.T) {
	ev := routePacket(&gossip.Packet{Message: nil}, map[string]*SyncSession{})
	if _, ok := ev.(*UnsolicitedPacketEvent); !ok {
		t.Fatalf("expected UnsolicitedPacketEvent for nil message, got %T", ev)
	}
}

func TestRoutePacketNilPacket(t *testing.T) {
	ev := routePacket(nil, map[string]*SyncSession{})
	if _, ok := ev.(*UnsolicitedPacketEvent); !ok {
		t.Fatalf("expected UnsolicitedPacketEvent for nil packet, got %T", ev)
	}
}
