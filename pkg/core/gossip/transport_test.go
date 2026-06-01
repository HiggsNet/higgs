package gossip

import (
	"net"
	"testing"
)

func TestAddKnownPeerID(t *testing.T) {
	transport, err := Listen(Config{
		PeerID:     "test-local",
		ListenAddr: "127.0.0.1:0",
	})
	if err != nil {
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
