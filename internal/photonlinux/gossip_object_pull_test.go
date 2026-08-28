package photonlinux

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
)

func TestGossipObjectPullClientExchange(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("TCP sockets are unavailable: %v", err)
	}
	defer listener.Close()
	serverDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()
		serverDone <- gossip.ServeObjectPull(conn, func(request *gossip.ObjectPullRequest) *gossip.ObjectPullResponse {
			return &gossip.ObjectPullResponse{OK: request != nil && request.Type == gossip.ObjectPullZone}
		})
	}()
	client := GossipObjectPullClient{DialTimeout: time.Second, IOTimeout: time.Second}
	response, err := client.Exchange(t.Context(), listener.Addr().String(), &gossip.ObjectPullRequest{Type: gossip.ObjectPullZone, Zone: "node-a."})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if !response.OK {
		t.Fatalf("response = %#v, want OK", response)
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("ServeObjectPull: %v", err)
	}
}

func TestGossipObjectPullClientHonorsExpiredContext(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := (GossipObjectPullClient{}).Exchange(ctx, "127.0.0.1:1", &gossip.ObjectPullRequest{
		Type: gossip.ObjectPullZone, Zone: "node-a.",
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Exchange error = %v, want context.Canceled", err)
	}
}
