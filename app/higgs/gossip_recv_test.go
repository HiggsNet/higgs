package main

import (
	"testing"
	"time"

	"github.com/Catofes/higgs/pkg/core/gossip"
)

func TestGossipPacketReceiverForwardsPackets(t *testing.T) {
	transportA, err := gossip.Listen(gossip.Config{
		PeerID:     "test-a",
		ListenAddr: "127.0.0.1:0",
	})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer transportA.Close()

	transportB, err := gossip.Listen(gossip.Config{
		PeerID:     "test-b",
		ListenAddr: "127.0.0.1:0",
	})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer transportB.Close()

	transportA.AddPeer("test-b", transportB.LocalAddr())
	transportB.AddPeer("test-a", transportA.LocalAddr())

	ctx := t.Context()

	packetCh, stopRecv := startGossipPacketReceiver(ctx, transportB, nil)
	defer stopRecv()

	msg := &gossip.Message{Type: gossip.MessagePing, Ping: &gossip.Ping{}}
	if err := transportA.Send("test-b", msg); err != nil {
		t.Fatalf("Send: %v", err)
	}

	select {
	case packet := <-packetCh:
		if packet == nil {
			t.Fatalf("received nil packet")
		}
		if packet.Message.Type != gossip.MessagePing {
			t.Fatalf("got message type %v, want Ping", packet.Message.Type)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("timeout waiting for packet")
	}
}

func TestGossipPacketReceiverTimeoutNotLogged(t *testing.T) {
	transport, err := gossip.Listen(gossip.Config{
		PeerID:     "test-local",
		ListenAddr: "127.0.0.1:0",
	})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer transport.Close()

	var warned bool
	ctx := t.Context()

	packetCh, stopRecv := startGossipPacketReceiver(ctx, transport, func(_, _ string, _ map[string]any) {
		warned = true
	})
	defer stopRecv()

	// Force a short read deadline so the receiver sees a timeout.
	if err := transport.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}

	select {
	case <-packetCh:
		t.Fatalf("unexpected packet")
	case <-time.After(200 * time.Millisecond):
	}

	if warned {
		t.Fatalf("timeout error was logged, want no log")
	}
}

func TestGossipPacketReceiverStopsOnClose(t *testing.T) {
	transport, err := gossip.Listen(gossip.Config{
		PeerID:     "test-local",
		ListenAddr: "127.0.0.1:0",
	})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}

	ctx := t.Context()

	packetCh, stopRecv := startGossipPacketReceiver(ctx, transport, nil)
	stopRecv()

	select {
	case _, ok := <-packetCh:
		if ok {
			t.Fatalf("packet channel should be closed")
		}
		// channel closed, goroutine exited
	case <-time.After(5 * time.Second):
		t.Fatalf("receiver goroutine did not exit after stop")
	}
}

func TestGossipPacketReceiverNetErrClosedNotLogged(t *testing.T) {
	transport, err := gossip.Listen(gossip.Config{
		PeerID:     "test-local",
		ListenAddr: "127.0.0.1:0",
	})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}

	var warned bool
	ctx := t.Context()

	packetCh, stopRecv := startGossipPacketReceiver(ctx, transport, func(_, _ string, _ map[string]any) {
		warned = true
	})
	defer stopRecv()

	stopRecv()

	select {
	case <-packetCh:
	case <-time.After(5 * time.Second):
		t.Fatalf("receiver goroutine did not exit")
	}

	if warned {
		t.Fatalf("closed transport error was logged, want no log")
	}
}

func TestNextTimerWait(t *testing.T) {
	now := time.Unix(1000, 0)
	d := &DaemonService{
		Sync: &SyncRuntime{
			App: &Runtime{Clock: func() time.Time { return now }},
		},
	}

	wait := d.nextTimerWait(now.Add(time.Second), now.Add(2*time.Second))
	if wait != time.Second {
		t.Fatalf("nextTimerWait = %v, want 1s", wait)
	}

	wait = d.nextTimerWait(now.Add(-time.Second), now.Add(time.Second))
	if wait != 0 {
		t.Fatalf("nextTimerWait for due deadline = %v, want 0", wait)
	}

	wait = d.nextTimerWait(time.Time{}, time.Time{})
	if wait != 24*time.Hour {
		t.Fatalf("nextTimerWait with no deadlines = %v, want 24h", wait)
	}
}
