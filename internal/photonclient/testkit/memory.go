package testkit

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"sync"

	"github.com/HiggsNet/photon/internal/photonclient"
)

const defaultQueueSize = 64

// MemoryTunnel is an in-memory L3 tunnel. Inject sends a host packet to the
// portable core; ReceiveWritten observes a packet written back to the host.
type MemoryTunnel struct {
	metadata photonclient.TunnelMetadata
	toCore   chan []byte
	fromCore chan []byte
	done     chan struct{}
	once     sync.Once
}

func NewMemoryTunnel(name string, mtu int) *MemoryTunnel {
	return &MemoryTunnel{
		metadata: photonclient.TunnelMetadata{Name: name, MTU: mtu, NetworkID: "memory"},
		toCore:   make(chan []byte, defaultQueueSize),
		fromCore: make(chan []byte, defaultQueueSize),
		done:     make(chan struct{}),
	}
}

func (t *MemoryTunnel) Metadata() photonclient.TunnelMetadata { return t.metadata }

func (t *MemoryTunnel) ReadBatch(ctx context.Context, buffers [][]byte, sizes []int) (int, error) {
	if len(buffers) == 0 {
		return 0, nil
	}
	if len(sizes) < len(buffers) {
		return 0, errors.New("memory tunnel sizes shorter than buffers")
	}
	packet, err := receiveBytes(ctx, t.done, t.toCore)
	if err != nil {
		return 0, err
	}
	if len(buffers[0]) < len(packet) {
		return 0, io.ErrShortBuffer
	}
	copy(buffers[0], packet)
	sizes[0] = len(packet)
	n := 1
	for n < len(buffers) {
		select {
		case packet = <-t.toCore:
			if len(buffers[n]) < len(packet) {
				return n, io.ErrShortBuffer
			}
			copy(buffers[n], packet)
			sizes[n] = len(packet)
			n++
		default:
			return n, nil
		}
	}
	return n, nil
}

func (t *MemoryTunnel) WriteBatch(ctx context.Context, packets [][]byte) (int, error) {
	for index, packet := range packets {
		if err := sendBytes(ctx, t.done, t.fromCore, packet); err != nil {
			return index, err
		}
	}
	return len(packets), nil
}

func (t *MemoryTunnel) Inject(ctx context.Context, packet []byte) error {
	return sendBytes(ctx, t.done, t.toCore, packet)
}

func (t *MemoryTunnel) ReceiveWritten(ctx context.Context) ([]byte, error) {
	return receiveBytes(ctx, t.done, t.fromCore)
}

func (t *MemoryTunnel) Close() error {
	t.once.Do(func() { close(t.done) })
	return nil
}

func (t *MemoryTunnel) Closed() bool { return isClosed(t.done) }

// MemoryDatagram is an in-memory shared UDP transport.
type MemoryDatagram struct {
	toCore   chan photonclient.Datagram
	fromCore chan photonclient.Datagram
	done     chan struct{}
	once     sync.Once

	mu      sync.Mutex
	network photonclient.NetworkHandle
}

func NewMemoryDatagram() *MemoryDatagram {
	return &MemoryDatagram{
		toCore:   make(chan photonclient.Datagram, defaultQueueSize),
		fromCore: make(chan photonclient.Datagram, defaultQueueSize),
		done:     make(chan struct{}),
	}
}

func (d *MemoryDatagram) Send(ctx context.Context, peer photonclient.PeerEndpoint, packets [][]byte) error {
	for _, packet := range packets {
		if d.Closed() {
			return net.ErrClosed
		}
		datagram := photonclient.Datagram{Peer: peer, Payload: append([]byte(nil), packet...)}
		select {
		case d.fromCore <- datagram:
		case <-ctx.Done():
			return ctx.Err()
		case <-d.done:
			return net.ErrClosed
		}
	}
	return nil
}

func (d *MemoryDatagram) Receive(ctx context.Context) (photonclient.Datagram, error) {
	if d.Closed() {
		return photonclient.Datagram{}, net.ErrClosed
	}
	select {
	case datagram := <-d.toCore:
		datagram.Payload = append([]byte(nil), datagram.Payload...)
		return datagram, nil
	case <-ctx.Done():
		return photonclient.Datagram{}, ctx.Err()
	case <-d.done:
		return photonclient.Datagram{}, net.ErrClosed
	}
}

func (d *MemoryDatagram) Rebind(ctx context.Context, network photonclient.NetworkHandle) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-d.done:
		return net.ErrClosed
	default:
	}
	d.mu.Lock()
	d.network = network
	d.mu.Unlock()
	return nil
}

func (d *MemoryDatagram) Inject(ctx context.Context, datagram photonclient.Datagram) error {
	if d.Closed() {
		return net.ErrClosed
	}
	datagram.Payload = append([]byte(nil), datagram.Payload...)
	select {
	case d.toCore <- datagram:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-d.done:
		return net.ErrClosed
	}
}

func (d *MemoryDatagram) ReceiveSent(ctx context.Context) (photonclient.Datagram, error) {
	if d.Closed() {
		return photonclient.Datagram{}, net.ErrClosed
	}
	select {
	case datagram := <-d.fromCore:
		datagram.Payload = append([]byte(nil), datagram.Payload...)
		return datagram, nil
	case <-ctx.Done():
		return photonclient.Datagram{}, ctx.Err()
	case <-d.done:
		return photonclient.Datagram{}, net.ErrClosed
	}
}

func (d *MemoryDatagram) Network() photonclient.NetworkHandle {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.network
}

func (d *MemoryDatagram) Close() error {
	d.once.Do(func() { close(d.done) })
	return nil
}

func (d *MemoryDatagram) Closed() bool { return isClosed(d.done) }

// MemoryNetworkObserver is an event-driven observer for tests.
type MemoryNetworkObserver struct {
	mu      sync.Mutex
	current photonclient.NetworkChange
	changes chan photonclient.NetworkChange
	done    chan struct{}
	closed  bool
	once    sync.Once
}

func NewMemoryNetworkObserver(current photonclient.NetworkChange) *MemoryNetworkObserver {
	return &MemoryNetworkObserver{
		current: current,
		changes: make(chan photonclient.NetworkChange, defaultQueueSize),
		done:    make(chan struct{}),
	}
}

func (o *MemoryNetworkObserver) Current(ctx context.Context) (photonclient.NetworkChange, error) {
	select {
	case <-ctx.Done():
		return photonclient.NetworkChange{}, ctx.Err()
	case <-o.done:
		return photonclient.NetworkChange{}, net.ErrClosed
	default:
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.current, nil
}

func (o *MemoryNetworkObserver) Changes() <-chan photonclient.NetworkChange { return o.changes }

func (o *MemoryNetworkObserver) Publish(change photonclient.NetworkChange) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return net.ErrClosed
	}
	o.current = change
	select {
	case o.changes <- change:
		return nil
	default:
		return errors.New("memory network observer queue is full")
	}
}

func (o *MemoryNetworkObserver) Close() error {
	o.once.Do(func() {
		o.mu.Lock()
		o.closed = true
		close(o.done)
		close(o.changes)
		o.mu.Unlock()
	})
	return nil
}

func (o *MemoryNetworkObserver) Closed() bool { return isClosed(o.done) }

// MemoryStateSource publishes already-verified snapshots in tests.
type MemoryStateSource struct {
	mu       sync.Mutex
	snapshot photonclient.StateSnapshot
	changes  chan uint64
	done     chan struct{}
	closed   bool
	once     sync.Once
}

func NewMemoryStateSource(snapshot photonclient.StateSnapshot) *MemoryStateSource {
	return &MemoryStateSource{
		snapshot: snapshot,
		changes:  make(chan uint64, defaultQueueSize),
		done:     make(chan struct{}),
	}
}

func (s *MemoryStateSource) Snapshot(ctx context.Context) (photonclient.StateSnapshot, error) {
	select {
	case <-ctx.Done():
		return photonclient.StateSnapshot{}, ctx.Err()
	case <-s.done:
		return photonclient.StateSnapshot{}, net.ErrClosed
	default:
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.snapshot, nil
}

func (s *MemoryStateSource) Changes() <-chan uint64 { return s.changes }

func (s *MemoryStateSource) Publish(snapshot photonclient.StateSnapshot) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return net.ErrClosed
	}
	s.snapshot = snapshot
	select {
	case s.changes <- snapshot.Revision:
		return nil
	default:
		return errors.New("memory state source queue is full")
	}
}

func (s *MemoryStateSource) Close() error {
	s.once.Do(func() {
		s.mu.Lock()
		s.closed = true
		close(s.done)
		close(s.changes)
		s.mu.Unlock()
	})
	return nil
}

func (s *MemoryStateSource) Closed() bool { return isClosed(s.done) }

// MemoryKeyStore keeps generated Ed25519 signers in memory for tests.
type MemoryKeyStore struct {
	mu      sync.Mutex
	signers map[string]crypto.Signer
}

func NewMemoryKeyStore() *MemoryKeyStore {
	return &MemoryKeyStore{signers: make(map[string]crypto.Signer)}
}

func (s *MemoryKeyStore) LoadOrCreateSigner(ctx context.Context, keyID string) (crypto.Signer, error) {
	if keyID == "" {
		return nil, errors.New("memory key ID is empty")
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if signer := s.signers[keyID]; signer != nil {
		return signer, nil
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	s.signers[keyID] = privateKey
	return privateKey, nil
}

func receiveBytes(ctx context.Context, done <-chan struct{}, input <-chan []byte) ([]byte, error) {
	if isClosed(done) {
		return nil, net.ErrClosed
	}
	select {
	case packet := <-input:
		return append([]byte(nil), packet...), nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-done:
		return nil, net.ErrClosed
	}
}

func sendBytes(ctx context.Context, done <-chan struct{}, output chan<- []byte, packet []byte) error {
	if isClosed(done) {
		return net.ErrClosed
	}
	copyOfPacket := append([]byte(nil), packet...)
	select {
	case output <- copyOfPacket:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-done:
		return net.ErrClosed
	}
}

func isClosed(done <-chan struct{}) bool {
	select {
	case <-done:
		return true
	default:
		return false
	}
}
