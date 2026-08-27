package host

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

type failingDiscoveryWriter struct{ err error }

func (writer failingDiscoveryWriter) UpdatePeerCheckpoints(context.Context, map[string]corestate.PeerCheckpointPatch) (corestate.CommitResult, error) {
	return corestate.CommitResult{}, writer.err
}

func TestRuntimeDiscoveryDoesNotPublishAddressBookBeforeCheckpoint(t *testing.T) {
	wantErr := errors.New("checkpoint failed")
	now := time.Unix(1000, 0)
	transport := &gossip.Transport{}
	input := GossipDiscoveryInput{
		Network:   zone.NewNetworkState(),
		Bootstrap: map[string]*net.UDPAddr{"peer-a": {IP: net.ParseIP("192.0.2.1"), Port: 33434}},
		Peers: map[string]corestate.PeerCheckpoint{"peer-a": {
			ObservedEndpoint:  "198.51.100.1:33434",
			ObservedUntilUnix: now.Add(-time.Minute).Unix(),
		}},
	}
	runtime := NewRuntime(nil, 1)
	defer runtime.Stop()
	if err := runtime.RefreshGossipDiscovery(context.Background(), input, now, failingDiscoveryWriter{err: wantErr}, transport); !errors.Is(err, wantErr) {
		t.Fatalf("RefreshGossipDiscovery error = %v", err)
	}
	if addr := transport.PeerAddr("peer-a"); addr != nil {
		t.Fatalf("address book published before checkpoint: %v", addr)
	}
}

func TestDiscoveryAddressOrderAndRecentFallback(t *testing.T) {
	now := time.Unix(1000, 0)
	bootstrap := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 33434}
	entries := []gossip.EndpointEntry{
		{Address: "203.0.113.10", Port: 33434, Source: "reflector"},
		{Address: "198.51.100.2", Port: 33434, Source: "advertise"},
	}
	peer := corestate.PeerCheckpoint{LastSyncUnix: now.Add(-time.Minute).Unix(), DiscoveredEndpoint: "192.0.2.9:33434"}
	addrs := buildDiscoveryAddresses(entries, bootstrap, peer, 10*time.Minute, []string{"bootstrap", "advertise", "reflector", "recent"}, now)
	want := []string{"127.0.0.1:33434", "198.51.100.2:33434", "203.0.113.10:33434", "192.0.2.9:33434"}
	if len(addrs) != len(want) {
		t.Fatalf("addresses = %v", addrs)
	}
	for i := range want {
		if addrs[i].String() != want[i] {
			t.Fatalf("address[%d] = %s, want %s", i, addrs[i], want[i])
		}
	}
}
