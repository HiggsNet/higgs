package host

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
)

type memoryGossipDatagram struct {
	mu     sync.Mutex
	writes [][]byte
	addr   *net.UDPAddr
}

func (datagram *memoryGossipDatagram) ReadDatagram([]byte) (int, *net.UDPAddr, error) {
	return 0, nil, net.ErrClosed
}

func (datagram *memoryGossipDatagram) WriteDatagram(payload []byte, _ *net.UDPAddr) (int, error) {
	datagram.mu.Lock()
	datagram.writes = append(datagram.writes, append([]byte(nil), payload...))
	datagram.mu.Unlock()
	return len(payload), nil
}

func (datagram *memoryGossipDatagram) LocalAddr() *net.UDPAddr { return datagram.addr }
func (*memoryGossipDatagram) SetReadDeadline(time.Time) error  { return nil }
func (*memoryGossipDatagram) Close() error                     { return nil }

func (datagram *memoryGossipDatagram) writeCount() int {
	datagram.mu.Lock()
	defer datagram.mu.Unlock()
	return len(datagram.writes)
}

func bindMemoryGossipTransport(t *testing.T, runtime *Runtime, peerIDs ...string) (*gossip.Transport, *memoryGossipDatagram) {
	t.Helper()
	datagram := &memoryGossipDatagram{addr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 33434}}
	known := make(map[string]*net.UDPAddr, len(peerIDs))
	for _, peerID := range peerIDs {
		known[peerID] = &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 33435}
	}
	transport, err := gossip.NewTransport(gossip.Config{PeerID: "local.catofes.", KnownPeers: known}, datagram)
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.BindGossipTransport(transport); err != nil {
		t.Fatal(err)
	}
	return transport, datagram
}
