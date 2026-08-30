package host

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
)

type datagramReceiveResult struct {
	packet *gossip.Packet
	err    error
}

type fakeDatagramReceiver struct {
	results chan datagramReceiveResult
	closed  chan struct{}
	once    sync.Once
	closes  atomic.Int32
}

func newFakeDatagramReceiver() *fakeDatagramReceiver {
	return &fakeDatagramReceiver{
		results: make(chan datagramReceiveResult, 8),
		closed:  make(chan struct{}),
	}
}

func (receiver *fakeDatagramReceiver) Receive() (*gossip.Packet, error) {
	select {
	case result := <-receiver.results:
		return result.packet, result.err
	case <-receiver.closed:
		return nil, net.ErrClosed
	}
}

func (receiver *fakeDatagramReceiver) Close() error {
	receiver.once.Do(func() {
		receiver.closes.Add(1)
		close(receiver.closed)
	})
	return nil
}

type datagramTimeoutError struct{}

func (datagramTimeoutError) Error() string   { return "test timeout" }
func (datagramTimeoutError) Timeout() bool   { return true }
func (datagramTimeoutError) Temporary() bool { return true }

func TestRuntimeGossipDatagramReceiverForwardsPackets(t *testing.T) {
	runtime := NewRuntime(NewClock(nil), DefaultEventBuffer, nil, GossipRuntimeConfig{})
	receiver := newFakeDatagramReceiver()
	if err := runtime.startGossipDatagramReceiver(t.Context(), receiver, nil); err != nil {
		t.Fatalf("startGossipDatagramReceiver: %v", err)
	}
	defer runtime.Stop()
	want := &gossip.Packet{Message: &gossip.Message{Type: gossip.MessagePing}}
	receiver.results <- datagramReceiveResult{packet: want}
	select {
	case event := <-runtime.Events():
		received, ok := event.(GossipPacketReceived)
		got := received.Packet
		if !ok || got != want {
			t.Fatalf("packet = %#v, want %#v", got, want)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for packet")
	}
}

func TestRuntimeGossipDatagramReceiverReportsErrorAndContinues(t *testing.T) {
	runtime := NewRuntime(NewClock(nil), DefaultEventBuffer, nil, GossipRuntimeConfig{})
	receiver := newFakeDatagramReceiver()
	warnings := make(chan error, 1)
	if err := runtime.startGossipDatagramReceiver(t.Context(), receiver, func(err error) { warnings <- err }); err != nil {
		t.Fatalf("startGossipDatagramReceiver: %v", err)
	}
	defer runtime.Stop()
	wantErr := errors.New("receive failed")
	receiver.results <- datagramReceiveResult{err: wantErr}
	wantPacket := &gossip.Packet{Message: &gossip.Message{Type: gossip.MessagePong}}
	receiver.results <- datagramReceiveResult{packet: wantPacket}
	select {
	case got := <-warnings:
		if !errors.Is(got, wantErr) {
			t.Fatalf("warning = %v, want %v", got, wantErr)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for warning")
	}
	select {
	case event := <-runtime.Events():
		received, ok := event.(GossipPacketReceived)
		got := received.Packet
		if !ok || got != wantPacket {
			t.Fatalf("packet = %#v, want %#v", got, wantPacket)
		}
	case <-time.After(time.Second):
		t.Fatal("receiver did not continue after error")
	}
}

func TestRuntimeStopClosesGossipDatagramReceiver(t *testing.T) {
	runtime := NewRuntime(NewClock(nil), DefaultEventBuffer, nil, GossipRuntimeConfig{})
	receiver := newFakeDatagramReceiver()
	var warnings atomic.Int32
	if err := runtime.startGossipDatagramReceiver(context.Background(), receiver, func(error) { warnings.Add(1) }); err != nil {
		t.Fatalf("startGossipDatagramReceiver: %v", err)
	}
	receiver.results <- datagramReceiveResult{err: datagramTimeoutError{}}
	runtime.Stop()
	runtime.Stop()
	if got := warnings.Load(); got != 0 {
		t.Fatalf("warnings = %d, want 0", got)
	}
	if got := receiver.closes.Load(); got != 1 {
		t.Fatalf("Close calls = %d, want 1", got)
	}
}

func TestRuntimeGossipDatagramReceiverContextCancellationClosesReceiver(t *testing.T) {
	runtime := NewRuntime(NewClock(nil), DefaultEventBuffer, nil, GossipRuntimeConfig{})
	receiver := newFakeDatagramReceiver()
	ctx, cancel := context.WithCancel(context.Background())
	if err := runtime.startGossipDatagramReceiver(ctx, receiver, nil); err != nil {
		t.Fatalf("startGossipDatagramReceiver: %v", err)
	}
	cancel()
	select {
	case <-receiver.closed:
	case <-time.After(time.Second):
		t.Fatal("receiver did not close after context cancellation")
	}
	runtime.Stop()
	if got := receiver.closes.Load(); got != 1 {
		t.Fatalf("Close calls = %d, want 1", got)
	}
}

func TestRuntimeGossipDatagramReceiverRejectsNilAndSecondStart(t *testing.T) {
	runtime := NewRuntime(NewClock(nil), DefaultEventBuffer, nil, GossipRuntimeConfig{})
	defer runtime.Stop()
	if err := runtime.startGossipDatagramReceiver(t.Context(), nil, nil); !errors.Is(err, ErrDatagramReceiverRequired) {
		t.Fatalf("nil receiver error = %v, want %v", err, ErrDatagramReceiverRequired)
	}
	receiver := newFakeDatagramReceiver()
	if err := runtime.startGossipDatagramReceiver(t.Context(), receiver, nil); err != nil {
		t.Fatalf("first start: %v", err)
	}
	if err := runtime.startGossipDatagramReceiver(t.Context(), newFakeDatagramReceiver(), nil); !errors.Is(err, ErrDatagramReceiverStarted) {
		t.Fatalf("second start error = %v, want %v", err, ErrDatagramReceiverStarted)
	}
}
