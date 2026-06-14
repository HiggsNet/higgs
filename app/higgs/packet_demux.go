package main

import (
	"github.com/Catofes/higgs/pkg/core/gossip"
)

// routePacket demuxes an inbound packet to either an active SyncSession or the
// unsolicited packet handler path. It is intentionally stateless and does not
// interpret message type; that happens inside SyncSession.OnEvent.
func routePacket(packet *gossip.Packet, sessions map[string]*SyncSession) SyncEvent {
	if packet == nil || packet.Message == nil {
		return &UnsolicitedPacketEvent{Packet: packet}
	}
	if session, ok := sessions[packet.Message.PeerID]; ok && session != nil {
		return &PacketEvent{Session: session, Packet: packet}
	}
	return &UnsolicitedPacketEvent{Packet: packet}
}

// PacketEvent is delivered when a UDP packet matches an active sync session.
type PacketEvent struct {
	Session *SyncSession
	Packet  *gossip.Packet
}

func (*PacketEvent) isSyncEvent() {}

// UnsolicitedPacketEvent is delivered when a UDP packet does not match any
// active sync session; it is handled by the general packet path.
type UnsolicitedPacketEvent struct {
	Packet *gossip.Packet
}

func (*UnsolicitedPacketEvent) isSyncEvent() {}
