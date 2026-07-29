package gossip

import (
	"errors"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/vmihailenco/msgpack/v5"
)

func TestAddKnownPeerID(t *testing.T) {
	transport, err := Listen(Config{
		PeerID:     "test-local",
		ListenAddr: "127.0.0.1:0",
	})
	if err != nil {
		skipRestrictedSocket(t, err)
		t.Fatalf("Listen: %v", err)
	}
	defer transport.Close()

	transport.AddKnownPeerID("peer-a")

	found := false
	for _, id := range transport.KnownPeerIDs() {
		if id == "peer-a" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("KnownPeerIDs() does not contain peer-a")
	}

	if transport.PeerAddr("peer-a") != nil {
		t.Fatalf("PeerAddr(peer-a) should be nil when only AddKnownPeerID is used")
	}
}

func TestAddKnownPeerIDDoesNotAffectAddPeer(t *testing.T) {
	transport, err := Listen(Config{
		PeerID:     "test-local",
		ListenAddr: "127.0.0.1:0",
	})
	if err != nil {
		skipRestrictedSocket(t, err)
		t.Fatalf("Listen: %v", err)
	}
	defer transport.Close()

	transport.AddKnownPeerID("peer-a")
	transport.AddPeer("peer-b", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234})

	ids := transport.KnownPeerIDs()
	if len(ids) != 2 {
		t.Fatalf("KnownPeerIDs() = %v, want 2 entries", ids)
	}

	if transport.PeerAddr("peer-a") != nil {
		t.Fatalf("PeerAddr(peer-a) should be nil")
	}
	if transport.PeerAddr("peer-b") == nil {
		t.Fatalf("PeerAddr(peer-b) should not be nil")
	}
}

func TestRemovePeerAddrsKeepsKnownPeerID(t *testing.T) {
	transport := &Transport{}
	transport.SetPeerAddrs("peer-a", []*net.UDPAddr{{IP: net.ParseIP("127.0.0.1"), Port: 1234}})

	transport.RemovePeerAddrs("peer-a")

	if addr := transport.PeerAddr("peer-a"); addr != nil {
		t.Fatalf("PeerAddr(peer-a) = %v, want nil", addr)
	}
	if err := transport.validatePeer("peer-a"); err != nil {
		t.Fatalf("validatePeer(peer-a): %v", err)
	}
}

func TestObservedPeerAddrExpiresAndIsRemovedWithPeer(t *testing.T) {
	now := time.Unix(100, 0)
	transport := &Transport{clock: func() time.Time { return now }}
	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234}

	transport.SetObservedPeerAddr("peer-a", addr, now.Add(time.Minute), true)
	if got := transport.ObservedPeerAddr("peer-a"); got == nil || got.String() != "127.0.0.1:1234" {
		t.Fatalf("ObservedPeerAddr = %v, want 127.0.0.1:1234", got)
	}
	transport.SetObservedPeerPaths("peer-a", []ObservedPath{
		{Addr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 2000}, Until: now.Add(time.Minute)},
		{Addr: addr, Until: now.Add(30 * time.Second)},
	}, true)
	if got := transport.ObservedPeerAddrs("peer-a"); len(got) != 2 || got[0].String() != "127.0.0.1:2000" || got[1].String() != "127.0.0.1:1234" {
		t.Fatalf("ObservedPeerAddrs = %v, want primary plus grace", got)
	}

	now = now.Add(45 * time.Second)
	if got := transport.ObservedPeerAddrs("peer-a"); len(got) != 1 || got[0].String() != "127.0.0.1:2000" {
		t.Fatalf("ObservedPeerAddrs after grace expiry = %v, want only primary", got)
	}

	now = now.Add(2 * time.Minute)
	if got := transport.ObservedPeerAddr("peer-a"); got != nil {
		t.Fatalf("ObservedPeerAddr after expiry = %v, want nil", got)
	}

	now = time.Unix(100, 0)
	transport.SetObservedPeerAddr("peer-a", addr, now.Add(time.Minute), true)
	transport.RemovePeer("peer-a")
	if got := transport.ObservedPeerAddr("peer-a"); got != nil {
		t.Fatalf("ObservedPeerAddr after RemovePeer = %v, want nil", got)
	}
}

func TestListenAllowsUDPPortReuse(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("SO_REUSEPORT behavior is only enabled on linux")
	}

	first, err := Listen(Config{
		PeerID:     "node-a",
		ListenAddr: "127.0.0.1:0",
	})
	if err != nil {
		skipRestrictedSocket(t, err)
		t.Fatalf("Listen(first): %v", err)
	}
	defer first.Close()

	second, err := Listen(Config{
		PeerID:     "node-b",
		ListenAddr: first.LocalAddr().String(),
	})
	if err != nil {
		skipRestrictedSocket(t, err)
		t.Fatalf("Listen(second on %s): %v", first.LocalAddr(), err)
	}
	defer second.Close()
}

func TestReceiveRejectsMessageTooLarge(t *testing.T) {
	transport, err := Listen(Config{
		PeerID:          "node-b",
		ListenAddr:      "127.0.0.1:0",
		MaxMessageBytes: 8,
	})
	if err != nil {
		skipRestrictedSocket(t, err)
		t.Fatalf("Listen: %v", err)
	}
	defer transport.Close()

	sender, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		skipRestrictedSocket(t, err)
		t.Fatalf("ListenUDP(sender): %v", err)
	}
	defer sender.Close()

	if _, err := sender.WriteToUDP([]byte("0123456789"), transport.LocalAddr()); err != nil {
		t.Fatalf("WriteToUDP: %v", err)
	}
	if _, err := transport.Receive(); !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("Receive = %v, want ErrMessageTooLarge", err)
	}
}

func TestReceiveRejectsQuotaExceeded(t *testing.T) {
	now := time.Unix(1000, 0)
	var event Event
	transport, err := Listen(Config{
		PeerID:     "node-b",
		ListenAddr: "127.0.0.1:0",
		KnownPeers: map[string]*net.UDPAddr{
			"node-a": nil,
		},
		Quotas: NewPeerQuotas(QuotaConfig{
			ByteRate:    1,
			ByteBurst:   1,
			ObjectRate:  1,
			ObjectBurst: 1,
		}),
		Clock: func() time.Time { return now },
		Log: func(e Event) {
			event = e
		},
	})
	if err != nil {
		skipRestrictedSocket(t, err)
		t.Fatalf("Listen: %v", err)
	}
	defer transport.Close()

	if err := sendRawMessage(transport.LocalAddr(), &Message{
		Version:   WireVersion,
		Type:      MessagePing,
		PeerID:    "node-a",
		Nonce:     1,
		Timestamp: now.Unix(),
		Ping:      &Ping{},
	}); err != nil {
		t.Fatalf("sendRawMessage: %v", err)
	}
	if _, err := transport.Receive(); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("Receive = %v, want ErrQuotaExceeded", err)
	}
	if event.Reason != "quota" || event.QuotaRequestedBytes == 0 || event.QuotaAvailableBytes != 1 || event.QuotaObjectBurst != 1 {
		t.Fatalf("quota event = %#v, want reason and quota diagnostics", event)
	}
}

func TestReceiveRejectsReplay(t *testing.T) {
	now := time.Unix(1000, 0)
	transport, err := Listen(Config{
		PeerID:     "node-b",
		ListenAddr: "127.0.0.1:0",
		KnownPeers: map[string]*net.UDPAddr{
			"node-a": nil,
		},
		Replay: NewReplayWindow(time.Minute),
		Clock:  func() time.Time { return now },
	})
	if err != nil {
		skipRestrictedSocket(t, err)
		t.Fatalf("Listen: %v", err)
	}
	defer transport.Close()

	message := &Message{
		Version:   WireVersion,
		Type:      MessagePing,
		PeerID:    "node-a",
		Nonce:     7,
		Timestamp: now.Unix(),
		Ping:      &Ping{},
	}
	if err := sendRawMessage(transport.LocalAddr(), message); err != nil {
		t.Fatalf("sendRawMessage(first): %v", err)
	}
	if packet, err := transport.Receive(); err != nil || packet.Message.Nonce != 7 {
		t.Fatalf("Receive(first) = packet %#v, err %v; want nonce 7", packet, err)
	}
	if err := sendRawMessage(transport.LocalAddr(), message); err != nil {
		t.Fatalf("sendRawMessage(second): %v", err)
	}
	if _, err := transport.Receive(); !errors.Is(err, ErrReplay) {
		t.Fatalf("Receive(second) = %v, want ErrReplay", err)
	}
}

func TestReceiveRejectsUnsupportedWireVersion(t *testing.T) {
	now := time.Unix(1000, 0)
	transport, err := Listen(Config{
		PeerID:     "node-b",
		ListenAddr: "127.0.0.1:0",
		KnownPeers: map[string]*net.UDPAddr{
			"node-a": nil,
		},
		Clock: func() time.Time { return now },
	})
	if err != nil {
		skipRestrictedSocket(t, err)
		t.Fatalf("Listen: %v", err)
	}
	defer transport.Close()

	data, err := rawWireMessage(&Message{
		Version:   WireVersion + 1,
		Type:      MessagePing,
		PeerID:    "node-a",
		Nonce:     1,
		Timestamp: now.Unix(),
		Ping:      &Ping{},
	})
	if err != nil {
		t.Fatalf("rawWireMessage: %v", err)
	}
	if err := sendRawBytes(transport.LocalAddr(), data); err != nil {
		t.Fatalf("sendRawBytes: %v", err)
	}
	if _, err := transport.Receive(); RejectReason(err) != "unsupported_wire_version" {
		t.Fatalf("Receive = %v, reason %q; want unsupported_wire_version", err, RejectReason(err))
	}
}

func TestRejectReasonCoversAddrMismatch(t *testing.T) {
	if got := RejectReason(ErrAddrMismatch); got != "addr_mismatch" {
		t.Fatalf("RejectReason(ErrAddrMismatch) = %q, want addr_mismatch", got)
	}
}

func sendRawMessage(addr *net.UDPAddr, message *Message) error {
	data, err := MarshalMessage(message)
	if err != nil {
		return err
	}
	return sendRawBytes(addr, data)
}

func sendRawBytes(addr *net.UDPAddr, data []byte) error {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.WriteToUDP(data, addr)
	return err
}

func rawWireMessage(message *Message) ([]byte, error) {
	payload, err := msgpack.Marshal(message)
	if err != nil {
		return nil, err
	}
	data := append([]byte(nil), wireMagicMsgpack...)
	data = append(data, payload...)
	return data, nil
}

func TestReceiveTimeoutIsNotLogged(t *testing.T) {
	var logged bool
	transport, err := Listen(Config{
		PeerID:     "test-local",
		ListenAddr: "127.0.0.1:0",
		Log: func(event Event) {
			logged = true
		},
	})
	if err != nil {
		skipRestrictedSocket(t, err)
		t.Fatalf("Listen: %v", err)
	}
	defer transport.Close()

	if err := transport.SetReadDeadline(time.Now().Add(10 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	if _, err := transport.Receive(); err == nil {
		t.Fatalf("Receive should have timed out")
	}
	if logged {
		t.Fatalf("timeout error was logged, want no log")
	}
}

func TestSendPrefersSuccessfulAddrAndDeprioritizesBackoff(t *testing.T) {
	now := time.Unix(1000, 0)
	transport := &Transport{
		clock:           func() time.Time { return now },
		maxMessageBytes: DefaultMaxMessage,
	}
	transport.SetPeerAddrs("peer-a", []*net.UDPAddr{
		{IP: net.ParseIP("203.0.113.10"), Port: 1234},
		{IP: net.ParseIP("127.0.0.1"), Port: 1234},
	})

	// Initially both addresses are unknown; order is preserved.
	addrs := transport.sendAddrsFor("peer-a")
	if len(addrs) != 2 {
		t.Fatalf("sendAddrsFor = %d addrs, want 2", len(addrs))
	}

	// Mark the public address as failing.
	transport.RecordAddrFailure("peer-a", &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 1234})
	transport.RecordAddrFailure("peer-a", &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 1234})

	addrs = transport.sendAddrsFor("peer-a")
	if addrs[0].IP.String() != "127.0.0.1" {
		t.Fatalf("first addr after backoff = %v, want 127.0.0.1", addrs[0])
	}

	// Mark loopback as successful; it should stay at the front.
	transport.RecordAddrSuccess("peer-a", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234})
	addrs = transport.sendAddrsFor("peer-a")
	if addrs[0].IP.String() != "127.0.0.1" {
		t.Fatalf("first addr after success = %v, want 127.0.0.1", addrs[0])
	}

	// After the backoff expires, the public address moves back up.
	now = now.Add(addrFailureBackoffMax).Add(time.Second)
	addrs = transport.sendAddrsFor("peer-a")
	if addrs[0].IP.String() != "127.0.0.1" {
		t.Fatalf("first addr after backoff expiry should still prefer successful addr")
	}
}

func TestSendOrdersByReachabilityRank(t *testing.T) {
	now := time.Unix(1000, 0)
	transport := &Transport{
		clock:           func() time.Time { return now },
		maxMessageBytes: DefaultMaxMessage,
	}
	transport.SetPeerAddrs("peer-a", []*net.UDPAddr{
		{IP: net.ParseIP("127.0.0.1"), Port: 1000},
		{IP: net.ParseIP("127.0.0.1"), Port: 1001},
		{IP: net.ParseIP("127.0.0.1"), Port: 1002},
	})

	addrs := transport.sendAddrsFor("peer-a")
	if len(addrs) != 3 {
		t.Fatalf("sendAddrsFor = %d addrs, want 3", len(addrs))
	}

	// Mark the second address as recently successful; it should move to front.
	transport.RecordAddrSuccess("peer-a", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1001})
	addrs = transport.sendAddrsFor("peer-a")
	if addrs[0].Port != 1001 {
		t.Fatalf("first addr = %v, want port 1001", addrs[0])
	}
}

func TestReceiveRecordsAddrSuccess(t *testing.T) {
	now := time.Unix(1000, 0)
	transport, err := Listen(Config{
		PeerID:     "node-b",
		ListenAddr: "127.0.0.1:0",
		KnownPeers: map[string]*net.UDPAddr{
			"node-a": nil,
		},
		Clock: func() time.Time { return now },
	})
	if err != nil {
		skipRestrictedSocket(t, err)
		t.Fatalf("Listen: %v", err)
	}
	defer transport.Close()

	message := &Message{
		Version:   WireVersion,
		Type:      MessagePing,
		PeerID:    "node-a",
		Nonce:     1,
		Timestamp: now.Unix(),
		Ping:      &Ping{},
	}
	if err := sendRawMessage(transport.LocalAddr(), message); err != nil {
		t.Fatalf("sendRawMessage: %v", err)
	}
	packet, err := transport.Receive()
	if err != nil {
		t.Fatalf("Receive: %v", err)
	}
	if transport.AddrFailureCount("node-a", packet.Addr) != 0 {
		t.Fatalf("failure count after receive = %d, want 0", transport.AddrFailureCount("node-a", packet.Addr))
	}
}

func TestLastSendAddr(t *testing.T) {
	transportA, err := Listen(Config{PeerID: "node-a", ListenAddr: "127.0.0.1:0"})
	if err != nil {
		skipRestrictedSocket(t, err)
		t.Fatalf("Listen: %v", err)
	}
	defer transportA.Close()
	transportB, err := Listen(Config{PeerID: "node-b", ListenAddr: "127.0.0.1:0"})
	if err != nil {
		skipRestrictedSocket(t, err)
		t.Fatalf("Listen: %v", err)
	}
	defer transportB.Close()

	transportA.SetPeerAddrs("node-b", []*net.UDPAddr{transportB.LocalAddr()})
	if err := transportA.Send("node-b", &Message{Type: MessagePing, Ping: &Ping{}}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if got := transportA.LastSendAddr("node-b"); got == nil || got.String() != transportB.LocalAddr().String() {
		t.Fatalf("LastSendAddr = %v, want %v", got, transportB.LocalAddr())
	}
}

func TestRemovePeerClearsAddrState(t *testing.T) {
	transport := &Transport{clock: time.Now}
	transport.SetPeerAddrs("peer-a", []*net.UDPAddr{{IP: net.ParseIP("127.0.0.1"), Port: 1234}})
	transport.RecordAddrSuccess("peer-a", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234})
	transport.RemovePeer("peer-a")
	if transport.LastSendAddr("peer-a") != nil {
		t.Fatalf("LastSendAddr after RemovePeer should be nil")
	}
}
