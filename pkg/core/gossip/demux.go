package gossip

// RoutePacket classifies an inbound packet as belonging to an active
// per-peer sync session or to the read-only/unsolicited responder path. It is
// stateless and does not interpret message type.
func RoutePacket(packet *Packet, sessions map[string]*SyncSession) SyncEvent {
	if packet == nil || packet.Message == nil {
		return &UnsolicitedPacketEvent{Packet: packet}
	}
	if session, ok := sessions[packet.Message.PeerID]; ok && session != nil {
		return &PacketEvent{Session: session, Packet: packet}
	}
	return &UnsolicitedPacketEvent{Packet: packet}
}

// PacketEvent is delivered when a packet matches an active sync session.
// SyncSession does not consume this event directly; a platform executor
// translates the message into the appropriate protocol event or response.
type PacketEvent struct {
	Session *SyncSession
	Packet  *Packet
}

func (*PacketEvent) SyncEventMarker() {}

// UnsolicitedPacketEvent is delivered when no active session matches. The
// platform executor may service read-only requests or use announcements as a
// hint to start a session.
type UnsolicitedPacketEvent struct {
	Packet *Packet
}

func (*UnsolicitedPacketEvent) SyncEventMarker() {}
