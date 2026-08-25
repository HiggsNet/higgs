package gossip

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type receiveResult struct {
	packet *Packet
	err    error
}

type fakePacketReceiver struct {
	results chan receiveResult
	closed  chan struct{}
	once    sync.Once
	closes  atomic.Int32
}

func newFakePacketReceiver() *fakePacketReceiver {
	return &fakePacketReceiver{
		results: make(chan receiveResult, 8),
		closed:  make(chan struct{}),
	}
}

func (r *fakePacketReceiver) Receive() (*Packet, error) {
	select {
	case result := <-r.results:
		return result.packet, result.err
	case <-r.closed:
		return nil, net.ErrClosed
	}
}

func (r *fakePacketReceiver) Close() error {
	r.once.Do(func() {
		r.closes.Add(1)
		close(r.closed)
	})
	return nil
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "test timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func TestStartPacketReceiverForwardsPackets(t *testing.T) {
	receiver := newFakePacketReceiver()
	packets, stop := StartPacketReceiver(t.Context(), receiver, 1, nil)
	defer stop()
	want := &Packet{Message: &Message{Type: MessagePing}}
	receiver.results <- receiveResult{packet: want}
	select {
	case got := <-packets:
		if got != want {
			t.Fatalf("packet = %#v, want %#v", got, want)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for packet")
	}
}

func TestStartPacketReceiverReportsErrorAndContinues(t *testing.T) {
	receiver := newFakePacketReceiver()
	warnings := make(chan error, 1)
	packets, stop := StartPacketReceiver(t.Context(), receiver, 1, func(err error) { warnings <- err })
	defer stop()
	wantErr := errors.New("receive failed")
	receiver.results <- receiveResult{err: wantErr}
	wantPacket := &Packet{Message: &Message{Type: MessagePong}}
	receiver.results <- receiveResult{packet: wantPacket}
	select {
	case got := <-warnings:
		if !errors.Is(got, wantErr) {
			t.Fatalf("warning = %v, want %v", got, wantErr)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for warning")
	}
	select {
	case got := <-packets:
		if got != wantPacket {
			t.Fatalf("packet = %#v, want %#v", got, wantPacket)
		}
	case <-time.After(time.Second):
		t.Fatal("receiver did not continue after error")
	}
}

func TestStartPacketReceiverSuppressesTimeoutAndClose(t *testing.T) {
	receiver := newFakePacketReceiver()
	var warnings atomic.Int32
	packets, stop := StartPacketReceiver(context.Background(), receiver, 1, func(error) { warnings.Add(1) })
	receiver.results <- receiveResult{err: timeoutError{}}
	stop()
	stop()
	select {
	case _, ok := <-packets:
		if ok {
			t.Fatal("packet channel remains open after stop")
		}
	case <-time.After(time.Second):
		t.Fatal("receiver did not stop after Close")
	}
	if got := warnings.Load(); got != 0 {
		t.Fatalf("warnings = %d, want 0", got)
	}
	if got := receiver.closes.Load(); got != 1 {
		t.Fatalf("Close calls = %d, want 1", got)
	}
}

func TestStartPacketReceiverNilReceiverFailsClosed(t *testing.T) {
	warnings := make(chan error, 1)
	packets, stop := StartPacketReceiver(t.Context(), nil, 0, func(err error) { warnings <- err })
	defer stop()
	select {
	case err := <-warnings:
		if err == nil {
			t.Fatal("nil receiver warning is nil")
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for nil receiver warning")
	}
	if _, ok := <-packets; ok {
		t.Fatal("nil receiver packet channel remains open")
	}
}
