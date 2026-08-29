package photonwindows

import (
	"errors"
	"net"
	"sync"
	"time"
)

const memoryGossipQueueSize = 64

type memoryGossipFrame struct {
	payload []byte
	from    *net.UDPAddr
}

// memoryGossipDatagram is test-only packet I/O. It implements gossip.DatagramIO
// without introducing a product runtime or a platform capability registry.
type memoryGossipDatagram struct {
	local   *net.UDPAddr
	inbound chan memoryGossipFrame
	done    chan struct{}
	once    sync.Once
	peer    *memoryGossipDatagram
}

func newMemoryGossipDatagramPair() (*memoryGossipDatagram, *memoryGossipDatagram) {
	left := &memoryGossipDatagram{
		local:   &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 41001},
		inbound: make(chan memoryGossipFrame, memoryGossipQueueSize),
		done:    make(chan struct{}),
	}
	right := &memoryGossipDatagram{
		local:   &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 41002},
		inbound: make(chan memoryGossipFrame, memoryGossipQueueSize),
		done:    make(chan struct{}),
	}
	left.peer = right
	right.peer = left
	return left, right
}

func (datagram *memoryGossipDatagram) ReadDatagram(buffer []byte) (int, *net.UDPAddr, error) {
	select {
	case frame := <-datagram.inbound:
		if len(buffer) < len(frame.payload) {
			return 0, nil, errors.New("memory gossip read buffer is too small")
		}
		return copy(buffer, frame.payload), cloneMemoryUDPAddr(frame.from), nil
	case <-datagram.done:
		return 0, nil, net.ErrClosed
	}
}

func (datagram *memoryGossipDatagram) WriteDatagram(payload []byte, addr *net.UDPAddr) (int, error) {
	if datagram == nil || datagram.peer == nil || addr == nil {
		return 0, errors.New("memory gossip destination is missing")
	}
	peer := datagram.peer
	if datagram.closed() || peer.closed() || !memoryUDPAddrEqual(addr, peer.local) {
		return 0, net.ErrClosed
	}
	frame := memoryGossipFrame{payload: append([]byte(nil), payload...), from: cloneMemoryUDPAddr(datagram.local)}
	select {
	case peer.inbound <- frame:
		return len(payload), nil
	case <-datagram.done:
		return 0, net.ErrClosed
	case <-peer.done:
		return 0, net.ErrClosed
	}
}

func (datagram *memoryGossipDatagram) LocalAddr() *net.UDPAddr {
	if datagram == nil {
		return nil
	}
	return cloneMemoryUDPAddr(datagram.local)
}

func (*memoryGossipDatagram) SetReadDeadline(time.Time) error { return nil }

func (datagram *memoryGossipDatagram) Close() error {
	if datagram != nil {
		datagram.once.Do(func() { close(datagram.done) })
	}
	return nil
}

func (datagram *memoryGossipDatagram) closed() bool {
	if datagram == nil {
		return true
	}
	select {
	case <-datagram.done:
		return true
	default:
		return false
	}
}

func cloneMemoryUDPAddr(addr *net.UDPAddr) *net.UDPAddr {
	if addr == nil {
		return nil
	}
	return &net.UDPAddr{IP: append(net.IP(nil), addr.IP...), Port: addr.Port, Zone: addr.Zone}
}

func memoryUDPAddrEqual(left, right *net.UDPAddr) bool {
	return left != nil && right != nil && left.Port == right.Port && left.Zone == right.Zone && left.IP.Equal(right.IP)
}
