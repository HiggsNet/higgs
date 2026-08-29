package host

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

type blockingObjectPullClient struct{ entered chan struct{} }

func (client *blockingObjectPullClient) Exchange(ctx context.Context, _ string, _ *gossip.ObjectPullRequest) (*gossip.ObjectPullResponse, error) {
	select {
	case client.entered <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestGossipObjectPullWorkersProvideBoundedBackpressureAndStop(t *testing.T) {
	runtime := NewRuntime(nil, 4, nil, GossipRuntimeConfig{})
	client := &blockingObjectPullClient{entered: make(chan struct{}, 1)}
	executor := NewGossipObjectPullExecutor(GossipObjectPullExecutorConfig{
		Client: client,
		Discovery: func() GossipDiscoveryInput {
			return GossipDiscoveryInput{
				Network: zone.NewNetworkState(),
				Bootstrap: map[string]*net.UDPAddr{
					"peer-a": {IP: net.ParseIP("127.0.0.1"), Port: 1},
					"peer-b": {IP: net.ParseIP("127.0.0.1"), Port: 2},
				},
			}
		},
	})
	if err := runtime.StartGossipObjectPullWorkers(t.Context(), executor, 1, 1); err != nil {
		t.Fatal(err)
	}
	first := gossip.StartObjectPullAction{PeerID: "peer-a", Zone: "a.catofes."}
	if err := runtime.SubmitGossipObjectPull(first); err != nil {
		t.Fatal(err)
	}
	<-client.entered
	if err := runtime.SubmitGossipObjectPull(gossip.StartObjectPullAction{PeerID: "peer-b", Zone: "b.catofes."}); err != nil {
		t.Fatal(err)
	}
	if err := runtime.SubmitGossipObjectPull(gossip.StartObjectPullAction{PeerID: "peer-c", Zone: "c.catofes."}); !errors.Is(err, ErrGossipObjectPullQueueFull) {
		t.Fatalf("third submit error = %v, want %v", err, ErrGossipObjectPullQueueFull)
	}
	if got := runtime.PendingGossipObjectPullCount(); got != 2 {
		t.Fatalf("pending = %d, want 2", got)
	}
	runtime.Stop()
	if got := runtime.PendingGossipObjectPullCount(); got != 0 {
		t.Fatalf("pending after stop = %d, want 0", got)
	}
	if err := runtime.SubmitGossipObjectPull(first); !errors.Is(err, ErrRuntimeStopped) {
		t.Fatalf("submit after stop = %v, want %v", err, ErrRuntimeStopped)
	}
}
