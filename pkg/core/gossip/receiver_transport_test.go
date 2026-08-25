package gossip

import (
	"testing"
	"time"
)

func TestPacketReceiverTransportForwardsPackets(t *testing.T) {
	transportA, err := Listen(Config{PeerID: "test-a", ListenAddr: "127.0.0.1:0"})
	if err != nil {
		skipRestrictedSocket(t, err)
		t.Fatalf("Listen(A): %v", err)
	}
	defer transportA.Close()

	transportB, err := Listen(Config{PeerID: "test-b", ListenAddr: "127.0.0.1:0"})
	if err != nil {
		skipRestrictedSocket(t, err)
		t.Fatalf("Listen(B): %v", err)
	}
	defer transportB.Close()

	transportA.AddPeer("test-b", transportB.LocalAddr())
	transportB.AddPeer("test-a", transportA.LocalAddr())
	packets, stop := StartPacketReceiver(t.Context(), transportB, DefaultPacketReceiveBuffer, nil)
	defer stop()

	if err := transportA.Send("test-b", &Message{Type: MessagePing, Ping: &Ping{}}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	select {
	case packet := <-packets:
		if packet == nil || packet.Message == nil || packet.Message.Type != MessagePing {
			t.Fatalf("packet = %#v, want PING", packet)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for packet")
	}
}

func TestPacketReceiverTransportTimeoutIsSuppressed(t *testing.T) {
	transport, err := Listen(Config{PeerID: "test-local", ListenAddr: "127.0.0.1:0"})
	if err != nil {
		skipRestrictedSocket(t, err)
		t.Fatalf("Listen: %v", err)
	}
	defer transport.Close()

	warnings := make(chan error, 1)
	packets, stop := StartPacketReceiver(t.Context(), transport, DefaultPacketReceiveBuffer, func(err error) {
		warnings <- err
	})
	defer stop()
	if err := transport.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}

	select {
	case packet := <-packets:
		t.Fatalf("unexpected packet: %#v", packet)
	case err := <-warnings:
		t.Fatalf("timeout reported as warning: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestPacketReceiverTransportStopClosesChannel(t *testing.T) {
	transport, err := Listen(Config{PeerID: "test-local", ListenAddr: "127.0.0.1:0"})
	if err != nil {
		skipRestrictedSocket(t, err)
		t.Fatalf("Listen: %v", err)
	}
	packets, stop := StartPacketReceiver(t.Context(), transport, DefaultPacketReceiveBuffer, nil)
	stop()

	select {
	case _, ok := <-packets:
		if ok {
			t.Fatal("packet channel remains open after stop")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("receiver did not stop after transport close")
	}
}

func TestPacketReceiverTransportCloseIsSuppressed(t *testing.T) {
	transport, err := Listen(Config{PeerID: "test-local", ListenAddr: "127.0.0.1:0"})
	if err != nil {
		skipRestrictedSocket(t, err)
		t.Fatalf("Listen: %v", err)
	}
	warnings := make(chan error, 1)
	packets, stop := StartPacketReceiver(t.Context(), transport, DefaultPacketReceiveBuffer, func(err error) {
		warnings <- err
	})
	stop()

	select {
	case _, ok := <-packets:
		if ok {
			t.Fatal("packet channel remains open after stop")
		}
	case err := <-warnings:
		t.Fatalf("closed transport reported as warning: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("receiver did not stop")
	}
}
