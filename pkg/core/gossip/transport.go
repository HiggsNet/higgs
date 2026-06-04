package gossip

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	ErrUnknownPeer     = errors.New("unknown gossip peer")
	ErrAddrMismatch    = errors.New("gossip peer address mismatch")
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
	Log             func(Event)
}

type Transport struct {
	conn            *net.UDPConn
	peerID          string
	knownPeers      map[string]struct{} // inbound allowlist
	knownMu         sync.RWMutex
	outboundAddrs   map[string][]*net.UDPAddr // addresses used for Send
	outboundMu      sync.RWMutex
	lastSeenAddrs   map[string]*net.UDPAddr // fallback addresses from recent inbound packets
	lastSeenMu      sync.RWMutex
	observedPaths   map[string]observedPath // verified short-lived inbound UDP paths
	observedMu      sync.RWMutex
	maxMessageBytes int
	replay          *ReplayWindow
	quotas          *PeerQuotas
	clock           Clock
	log             func(Event)
}

type Packet struct {
	Message *Message
	Addr    *net.UDPAddr
	Bytes   int
}

type Event struct {
	Direction string
	PeerID    string
	Type      MessageType
	Addr      string
	Bytes     int
	Zones     int
	Records   int
	Duration  time.Duration
	Error     string
	Reason    string
}

type observedPath struct {
	Addr        *net.UDPAddr
	Until       time.Time
	PreferFirst bool
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
	conn, err := listenUDP(addr)
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
	t := &Transport{
		conn:            conn,
		peerID:          config.PeerID,
		maxMessageBytes: maxMessageBytes,
		replay:          replay,
		quotas:          config.Quotas,
		clock:           clock,
		log:             config.Log,
	}
	if len(config.KnownPeers) > 0 {
		t.SetPeers(config.KnownPeers)
	}
	return t, nil
}

// MaxMessageBytes returns the configured datagram size limit.
func (t *Transport) MaxMessageBytes() int {
	if t == nil {
		return DefaultDatagramBudget
	}
	return t.maxMessageBytes
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
	start := t.now()
	event := Event{Direction: "send", PeerID: peerID}
	if message != nil {
		event.Type = message.Type
		event.Zones, event.Records = MessageObjectCounts(message)
	}

	t.outboundMu.RLock()
	addrs := appendUDPAddrCopies(nil, t.outboundAddrs[peerID]...)
	t.outboundMu.RUnlock()

	t.observedMu.RLock()
	if observed := t.observedPaths[peerID]; observed.Addr != nil && (observed.Until.IsZero() || t.now().Before(observed.Until)) {
		if observed.PreferFirst {
			addrs = appendUDPAddrCopies([]*net.UDPAddr{observed.Addr}, addrs...)
		} else {
			addrs = appendUDPAddrCopies(addrs, observed.Addr)
		}
	}
	t.observedMu.RUnlock()

	if len(addrs) == 0 {
		t.lastSeenMu.RLock()
		if lastAddr := t.lastSeenAddrs[peerID]; lastAddr != nil {
			addrs = appendUDPAddrCopies(addrs, lastAddr)
		}
		t.lastSeenMu.RUnlock()
	}

	if len(addrs) == 0 {
		t.logEvent(event, ErrUnknownPeer, start)
		return ErrUnknownPeer
	}

	if message == nil {
		err := errors.New("gossip message is nil")
		t.logEvent(event, err, start)
		return err
	}
	message.PeerID = t.peerID
	if message.Nonce == 0 {
		nonce, err := randomNonce()
		if err != nil {
			t.logEvent(event, err, start)
			return err
		}
		message.Nonce = nonce
	}
	if message.Timestamp == 0 {
		message.Timestamp = t.now().Unix()
	}
	data, err := MarshalMessage(message)
	if err != nil {
		t.logEvent(event, err, start)
		return err
	}
	event.Bytes = len(data)
	if len(data) > t.maxMessageBytes {
		t.logEvent(event, ErrMessageTooLarge, start)
		return ErrMessageTooLarge
	}
	if t.quotas != nil {
		if err := t.quotas.Allow(peerID, int64(len(data)), objectCost(message), t.now()); err != nil {
			t.logEvent(event, err, start)
			return err
		}
	}

	var lastErr error
	for _, addr := range addrs {
		event.Addr = addr.String()
		_, lastErr = t.conn.WriteToUDP(data, addr)
		if lastErr == nil {
			t.logEvent(event, nil, start)
			return nil
		}
	}
	t.logEvent(event, lastErr, start)
	return lastErr
}

func (t *Transport) Receive() (*Packet, error) {
	start := t.now()
	buf := make([]byte, t.maxMessageBytes+1)
	n, addr, err := t.conn.ReadFromUDP(buf)
	if err != nil {
		t.logEvent(Event{Direction: "recv", Addr: udpAddrString(addr)}, err, start)
		return nil, err
	}
	event := Event{Direction: "recv", Addr: udpAddrString(addr), Bytes: n}
	if n > t.maxMessageBytes {
		t.logEvent(event, ErrMessageTooLarge, start)
		return nil, ErrMessageTooLarge
	}
	message, err := UnmarshalMessage(buf[:n])
	if err != nil {
		t.logEvent(event, err, start)
		return nil, err
	}
	event.PeerID = message.PeerID
	event.Type = message.Type
	event.Zones, event.Records = MessageObjectCounts(message)
	if err := t.validatePeer(message.PeerID); err != nil {
		t.logEvent(event, err, start)
		return nil, err
	}
	if t.quotas != nil {
		if err := t.quotas.Allow(message.PeerID, int64(n), objectCost(message), t.now()); err != nil {
			t.logEvent(event, err, start)
			return nil, err
		}
	}
	if err := t.replay.Check(message.PeerID, message.Nonce, message.Timestamp, t.now()); err != nil {
		t.logEvent(event, err, start)
		return nil, err
	}
	t.lastSeenMu.Lock()
	if t.lastSeenAddrs == nil {
		t.lastSeenAddrs = make(map[string]*net.UDPAddr)
	}
	copied := *addr
	t.lastSeenAddrs[message.PeerID] = &copied
	t.lastSeenMu.Unlock()
	t.logEvent(event, nil, start)
	return &Packet{Message: message, Addr: addr, Bytes: n}, nil
}

// validatePeer only checks whether the peer_id is known.
// Address binding has been removed; identity is established by upper-layer
// cryptographic verification (VerifyChain / VerifyRecord).
func (t *Transport) validatePeer(peerID string) error {
	t.knownMu.RLock()
	defer t.knownMu.RUnlock()
	if _, ok := t.knownPeers[peerID]; !ok {
		return ErrUnknownPeer
	}
	return nil
}

func (t *Transport) logEvent(event Event, err error, start time.Time) {
	if t == nil || t.log == nil {
		return
	}
	event.Duration = t.now().Sub(start)
	if err != nil {
		event.Error = err.Error()
		event.Reason = RejectReason(err)
	}
	t.log(event)
}

func udpAddrString(addr *net.UDPAddr) string {
	if addr == nil {
		return ""
	}
	return addr.String()
}

func RejectReason(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrUnknownPeer):
		return "unknown_peer"
	case errors.Is(err, ErrAddrMismatch):
		return "addr_mismatch"
	case errors.Is(err, ErrMessageTooLarge):
		return "message_too_large"
	case errors.Is(err, ErrQuotaExceeded):
		return "quota"
	case strings.Contains(err.Error(), "replay"):
		return "replay"
	case strings.Contains(err.Error(), "unsupported gossip wire version"):
		return "unsupported_wire_version"
	case errors.Is(err, ErrUnsupportedCodec):
		return "unsupported_codec"
	default:
		return "invalid_message"
	}
}

func MessageObjectCounts(message *Message) (zones int, records int) {
	switch {
	case message == nil:
		return 0, 0
	case message.Ping != nil:
		return len(message.Ping.Zones), 0
	case message.Pong != nil:
		return len(message.Pong.Zones) + len(message.Pong.FetchZones), 0
	case message.FetchZone != nil:
		return 1, 0
	case message.FetchRecord != nil:
		return 1, 1
	case message.Announce != nil:
		records = len(message.Announce.Records)
		for _, snapshot := range message.Announce.Snapshots {
			records += len(snapshot.Records)
			for _, history := range snapshot.RecordHistory {
				records += len(history)
			}
		}
		return len(message.Announce.Zones) + len(message.Announce.Snapshots), records
	default:
		return 0, 0
	}
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

// PeerAddr returns the preferred (first) outbound address for a peer.
func (t *Transport) PeerAddr(peerID string) *net.UDPAddr {
	t.outboundMu.RLock()
	defer t.outboundMu.RUnlock()
	addrs := t.outboundAddrs[peerID]
	if len(addrs) == 0 {
		return nil
	}
	copied := *addrs[0]
	return &copied
}

// SetObservedPeerAddr stores a verified, short-lived inbound UDP path for a
// peer. It does not change the inbound allowlist and is intended for NAT
// mappings observed after upper-layer verification.
func (t *Transport) SetObservedPeerAddr(peerID string, addr *net.UDPAddr, until time.Time, preferFirst bool) {
	if t == nil || peerID == "" || addr == nil {
		return
	}
	copied := *addr
	t.observedMu.Lock()
	if t.observedPaths == nil {
		t.observedPaths = make(map[string]observedPath)
	}
	t.observedPaths[peerID] = observedPath{Addr: &copied, Until: until, PreferFirst: preferFirst}
	t.observedMu.Unlock()
}

func (t *Transport) RemoveObservedPeerAddr(peerID string) {
	if t == nil || peerID == "" {
		return
	}
	t.observedMu.Lock()
	delete(t.observedPaths, peerID)
	t.observedMu.Unlock()
}

func (t *Transport) ObservedPeerAddr(peerID string) *net.UDPAddr {
	if t == nil || peerID == "" {
		return nil
	}
	t.observedMu.RLock()
	defer t.observedMu.RUnlock()
	observed := t.observedPaths[peerID]
	if observed.Addr == nil || (!observed.Until.IsZero() && !t.now().Before(observed.Until)) {
		return nil
	}
	copied := *observed.Addr
	return &copied
}

// AddKnownPeerID adds a peer ID to the inbound allowlist without
// registering any outbound address. Used for zone-identity-based admission.
func (t *Transport) AddKnownPeerID(peerID string) {
	t.knownMu.Lock()
	if t.knownPeers == nil {
		t.knownPeers = make(map[string]struct{})
	}
	t.knownPeers[peerID] = struct{}{}
	t.knownMu.Unlock()
}

// AddPeer registers a peer in the inbound allowlist and adds an address
// to its outbound address book. Duplicate addresses are ignored.
func (t *Transport) AddPeer(peerID string, addr *net.UDPAddr) {
	if addr == nil {
		return
	}
	t.knownMu.Lock()
	if t.knownPeers == nil {
		t.knownPeers = make(map[string]struct{})
	}
	t.knownPeers[peerID] = struct{}{}
	t.knownMu.Unlock()

	t.outboundMu.Lock()
	if t.outboundAddrs == nil {
		t.outboundAddrs = make(map[string][]*net.UDPAddr)
	}
	for _, existing := range t.outboundAddrs[peerID] {
		if existing.IP.Equal(addr.IP) && existing.Port == addr.Port {
			t.outboundMu.Unlock()
			return
		}
	}
	copied := *addr
	t.outboundAddrs[peerID] = append(t.outboundAddrs[peerID], &copied)
	t.outboundMu.Unlock()
}

// SetPeerAddrs replaces the entire outbound address list for a peer.
func (t *Transport) SetPeerAddrs(peerID string, addrs []*net.UDPAddr) {
	if len(addrs) == 0 {
		return
	}
	t.knownMu.Lock()
	if t.knownPeers == nil {
		t.knownPeers = make(map[string]struct{})
	}
	t.knownPeers[peerID] = struct{}{}
	t.knownMu.Unlock()

	filtered := make([]*net.UDPAddr, 0, len(addrs))
	for _, a := range addrs {
		if a != nil {
			copied := *a
			filtered = append(filtered, &copied)
		}
	}
	t.outboundMu.Lock()
	if t.outboundAddrs == nil {
		t.outboundAddrs = make(map[string][]*net.UDPAddr)
	}
	t.outboundAddrs[peerID] = filtered
	t.outboundMu.Unlock()
}

// RemovePeerAddrs removes outbound addresses for a peer while leaving the
// inbound allowlist intact.
func (t *Transport) RemovePeerAddrs(peerID string) {
	t.outboundMu.Lock()
	delete(t.outboundAddrs, peerID)
	t.outboundMu.Unlock()
}

func (t *Transport) RemovePeer(peerID string) {
	t.knownMu.Lock()
	delete(t.knownPeers, peerID)
	t.knownMu.Unlock()

	t.outboundMu.Lock()
	delete(t.outboundAddrs, peerID)
	t.outboundMu.Unlock()

	t.observedMu.Lock()
	delete(t.observedPaths, peerID)
	t.observedMu.Unlock()
}

// SetPeers initializes both the inbound allowlist and the outbound address
// book from a single-address-per-peer map (used for bootstrap config).
func (t *Transport) SetPeers(peers map[string]*net.UDPAddr) {
	t.knownMu.Lock()
	t.knownPeers = make(map[string]struct{}, len(peers))
	for id := range peers {
		t.knownPeers[id] = struct{}{}
	}
	t.knownMu.Unlock()

	t.outboundMu.Lock()
	t.outboundAddrs = make(map[string][]*net.UDPAddr, len(peers))
	for id, addr := range peers {
		if addr == nil {
			continue
		}
		copied := *addr
		t.outboundAddrs[id] = []*net.UDPAddr{&copied}
	}
	t.outboundMu.Unlock()
}

func (t *Transport) KnownPeerIDs() []string {
	t.knownMu.RLock()
	defer t.knownMu.RUnlock()
	out := make([]string, 0, len(t.knownPeers))
	for id := range t.knownPeers {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

func (t *Transport) now() time.Time {
	if t != nil && t.clock != nil {
		return t.clock()
	}
	return time.Now()
}

func appendUDPAddrCopies(addrs []*net.UDPAddr, more ...*net.UDPAddr) []*net.UDPAddr {
	for _, addr := range more {
		if addr == nil {
			continue
		}
		duplicate := false
		for _, existing := range addrs {
			if existing != nil && existing.IP.Equal(addr.IP) && existing.Port == addr.Port {
				duplicate = true
				break
			}
		}
		if duplicate {
			continue
		}
		copied := *addr
		addrs = append(addrs, &copied)
	}
	return addrs
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
