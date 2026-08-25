package main

import (
	"github.com/HiggsNet/photon/pkg/core/gossip"
)

// Compatibility aliases keep Linux daemon call sites stable while the actual
// classifier and event types live in the shared gossip package.
type PacketEvent = gossip.PacketEvent
type UnsolicitedPacketEvent = gossip.UnsolicitedPacketEvent

func routePacket(packet *gossip.Packet, sessions map[string]*SyncSession) SyncEvent {
	return gossip.RoutePacket(packet, sessions)
}
