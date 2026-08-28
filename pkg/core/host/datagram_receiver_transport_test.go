package host_test

import (
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	"github.com/HiggsNet/photon/pkg/core/host"
)

func TestRuntimeDatagramReceiverAcceptsGossipTransport(t *testing.T) {
	transportA, err := gossip.Listen(gossip.Config{PeerID: "test-a", ListenAddr: "127.0.0.1:0"})
	if err != nil {
		t.Skipf("UDP sockets are unavailable: %v", err)
	}
	defer transportA.Close()
	transportB, err := gossip.Listen(gossip.Config{PeerID: "test-b", ListenAddr: "127.0.0.1:0"})
	if err != nil {
		t.Skipf("UDP sockets are unavailable: %v", err)
	}

	transportA.AddPeer("test-b", transportB.LocalAddr())
	transportB.AddPeer("test-a", transportA.LocalAddr())
	runtime := host.NewRuntime(host.NewClock(nil), host.DefaultEventBuffer)
	if err := runtime.StartGossipDatagramReceiver(t.Context(), transportB, nil); err != nil {
		t.Fatalf("StartGossipDatagramReceiver: %v", err)
	}
	defer runtime.Stop()
	if err := transportA.Send("test-b", &gossip.Message{Type: gossip.MessagePing, Ping: &gossip.Ping{}}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	select {
	case event := <-runtime.Events():
		received, ok := event.(host.GossipPacketReceived)
		packet := received.Packet
		if !ok || packet == nil || packet.Message == nil || packet.Message.Type != gossip.MessagePing {
			t.Fatalf("packet = %#v, want PING", packet)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for packet")
	}
}
