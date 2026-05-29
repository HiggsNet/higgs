package gossip

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"
)

var (
	ErrUnknownPeer     = errors.New("unknown gossip peer")
	ErrMessageTooLarge = errors.New("gossip message too large")
)

type Clock func() time.Time

type Config struct {
	PeerID          string
	ListenAddr      string
	KnownPeers      map[string]*net.UDPAddr
	MaxMessageBytes int
	Replay          *ReplayWindow
	Quotas          *PeerQuotas
	Clock           Clock
}

type Transport struct {
	conn            *net.UDPConn
	peerID          string
	knownPeers      map[string]*net.UDPAddr
	maxMessageBytes int
	replay          *ReplayWindow
	quotas          *PeerQuotas
	clock           Clock
}

type Packet struct {
	Message *Message
	Addr    *net.UDPAddr
}

func Listen(config Config) (*Transport, error) {
	if config.PeerID == "" {
		return nil, errors.New("local gossip peer id is empty")
	}
	listenAddr := config.ListenAddr
	if listenAddr == "" {
		listenAddr = fmt.Sprintf(":%d", DefaultPort)
	}
	addr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, err
	}
	maxMessageBytes := config.MaxMessageBytes
	if maxMessageBytes <= 0 {
		maxMessageBytes = DefaultMaxMessage
	}
	clock := config.Clock
	if clock == nil {
		clock = time.Now
	}
	replay := config.Replay
	if replay == nil {
		replay = NewReplayWindow(0)
	}
	return &Transport{
		conn:            conn,
		peerID:          config.PeerID,
		knownPeers:      copyPeers(config.KnownPeers),
		maxMessageBytes: maxMessageBytes,
		replay:          replay,
		quotas:          config.Quotas,
		clock:           clock,
	}, nil
}

func (t *Transport) Close() error {
	if t == nil || t.conn == nil {
		return nil
	}
	return t.conn.Close()
}

func (t *Transport) LocalAddr() *net.UDPAddr {
	if t == nil || t.conn == nil {
		return nil
	}
	addr, _ := t.conn.LocalAddr().(*net.UDPAddr)
	return addr
}

func (t *Transport) SetReadDeadline(deadline time.Time) error {
	if t == nil || t.conn == nil {
		return nil
	}
	return t.conn.SetReadDeadline(deadline)
}

func (t *Transport) Send(peerID string, message *Message) error {
	addr := t.knownPeers[peerID]
	if addr == nil {
		return ErrUnknownPeer
	}
	if message == nil {
		return errors.New("gossip message is nil")
	}
	message.PeerID = t.peerID
	if message.Nonce == 0 {
		nonce, err := randomNonce()
		if err != nil {
			return err
		}
		message.Nonce = nonce
	}
	if message.Timestamp == 0 {
		message.Timestamp = t.clock().Unix()
	}
	data, err := MarshalMessage(message)
	if err != nil {
		return err
	}
	if len(data) > t.maxMessageBytes {
		return ErrMessageTooLarge
	}
	if t.quotas != nil {
		if err := t.quotas.Allow(peerID, int64(len(data)), objectCost(message), t.clock()); err != nil {
			return err
		}
	}
	_, err = t.conn.WriteToUDP(data, addr)
	return err
}

func (t *Transport) Receive() (*Packet, error) {
	buf := make([]byte, t.maxMessageBytes+1)
	n, addr, err := t.conn.ReadFromUDP(buf)
	if err != nil {
		return nil, err
	}
	if n > t.maxMessageBytes {
		return nil, ErrMessageTooLarge
	}
	message, err := UnmarshalMessage(buf[:n])
	if err != nil {
		return nil, err
	}
	if err := t.validatePeer(message.PeerID, addr); err != nil {
		return nil, err
	}
	if t.quotas != nil {
		if err := t.quotas.Allow(message.PeerID, int64(n), objectCost(message), t.clock()); err != nil {
			return nil, err
		}
	}
	if err := t.replay.Check(message.PeerID, message.Nonce, message.Timestamp, t.clock()); err != nil {
		return nil, err
	}
	return &Packet{Message: message, Addr: addr}, nil
}

func (t *Transport) validatePeer(peerID string, addr *net.UDPAddr) error {
	known := t.knownPeers[peerID]
	if known == nil {
		return ErrUnknownPeer
	}
	if !known.IP.Equal(addr.IP) || known.Port != addr.Port {
		return ErrUnknownPeer
	}
	return nil
}

func objectCost(message *Message) int64 {
	switch {
	case message == nil:
		return 0
	case message.Ping != nil:
		return int64(len(message.Ping.Zones))
	case message.Pong != nil:
		return int64(len(message.Pong.FetchZones))
	case message.Announce != nil:
		return int64(len(message.Announce.Zones))
	case message.FetchZone != nil, message.FetchRecord != nil:
		return 1
	default:
		return 1
	}
}

func copyPeers(peers map[string]*net.UDPAddr) map[string]*net.UDPAddr {
	out := make(map[string]*net.UDPAddr, len(peers))
	for id, addr := range peers {
		if addr == nil {
			continue
		}
		copied := *addr
		out[id] = &copied
	}
	return out
}

func randomNonce() (uint64, error) {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return 0, err
	}
	nonce := binary.BigEndian.Uint64(buf[:])
	if nonce == 0 {
		nonce = 1
	}
	return nonce, nil
}
