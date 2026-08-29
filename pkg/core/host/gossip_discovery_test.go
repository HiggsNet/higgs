package host

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

type failingDiscoveryWriter struct {
	err  error
	view corestate.View
}

func (writer failingDiscoveryWriter) ReadView() corestate.View { return writer.view }

func (writer failingDiscoveryWriter) ApplyRemoteBatch(context.Context, string, []corestate.RemoteSnapshot, time.Time) (corestate.RemoteBatchResult, error) {
	return corestate.RemoteBatchResult{}, nil
}

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
	runtime := NewRuntime(nil, 1, failingDiscoveryWriter{err: wantErr, view: corestate.View{
		State:  &corestate.VerifiedState{Network: input.Network},
		Gossip: &corestate.GossipCheckpoint{Peers: input.Peers},
	}}, GossipRuntimeConfig{Discovery: GossipDiscoveryConfig{Bootstrap: input.Bootstrap}})
	defer runtime.Stop()
	if err := runtime.RefreshGossipDiscovery(context.Background(), nil, now, transport); !errors.Is(err, wantErr) {
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

func TestFilterGossipCatalogPageUsesCommonManagedAndRejectedState(t *testing.T) {
	now := time.Unix(1000, 0)
	input := GossipDiscoveryInput{
		ManagedZone: "local.catofes.",
		Network:     zone.NewNetworkState(),
		Peers: map[string]corestate.PeerCheckpoint{"peer-a": {RejectedObjects: map[zone.ZonePath]corestate.RejectedObject{
			"rejected.catofes.": {RootHash: []byte("rejected-root"), UntilUnix: now.Add(time.Minute).Unix()},
		}}},
	}
	page := &corestate.CatalogPage{Entries: []corestate.ZoneDigest{
		{Zone: "local.catofes.", RootHash: []byte("local-root")},
		{Zone: "rejected.catofes.", RootHash: []byte("rejected-root")},
		{Zone: "accepted.catofes.", RootHash: []byte("accepted-root")},
	}}
	_, filtered := FilterGossipCatalogPage(input, "peer-a", page, now)
	if len(filtered.Entries) != 1 || filtered.Entries[0].Zone != "accepted.catofes." {
		t.Fatalf("filtered entries = %#v", filtered.Entries)
	}
	if len(page.Entries) != 3 {
		t.Fatal("catalog filter mutated source page")
	}
}

func TestResolveGossipObjectPullAddressUsesBootstrap(t *testing.T) {
	input := GossipDiscoveryInput{Bootstrap: map[string]*net.UDPAddr{
		"peer-a": {IP: net.ParseIP("192.0.2.10"), Port: 33434},
	}}
	if got := ResolveGossipObjectPullAddress(input, "peer-a", time.Unix(1000, 0)); got != "192.0.2.10:33434" {
		t.Fatalf("object-pull address = %q", got)
	}
	if got := ResolveGossipObjectPullAddress(input, "unknown", time.Unix(1000, 0)); got != "" {
		t.Fatalf("unknown object-pull address = %q", got)
	}
}

func TestGossipOutboundPeersCombinesCommonSources(t *testing.T) {
	now := time.Unix(1000, 0)
	network := zone.NewNetworkState()
	path := zone.ZonePath("signed.catofes.")
	payload, err := json.Marshal(gossip.EndpointRecord{Endpoints: []gossip.EndpointEntry{{
		Address: "203.0.113.1", Port: 33434, LastObserved: now.Unix(),
	}}})
	if err != nil {
		t.Fatal(err)
	}
	peerZone := zone.NewZoneState(path, &zone.ZoneAuthority{Zone: path, Epoch: 1, Threshold: 1})
	peerZone.Records[gossip.EndpointRecordKeyUDP] = &zone.Record{Zone: path, Key: gossip.EndpointRecordKeyUDP, Value: payload, Timestamp: now.Unix()}
	network.Zones[path] = peerZone
	input := GossipDiscoveryInput{
		LocalPeerID:    "local.catofes.",
		ManagedZone:    "local.catofes.",
		Network:        network,
		Bootstrap:      map[string]*net.UDPAddr{"bootstrap.catofes.": {IP: net.ParseIP("192.0.2.1"), Port: 33434}},
		BootstrapPeers: []string{"bootstrap.catofes."},
		Peers: map[string]corestate.PeerCheckpoint{
			"observed.catofes.": {ObservedEndpoint: "198.51.100.1:33434", ObservedUntilUnix: now.Add(time.Minute).Unix()},
		},
	}
	// An observed path is admitted only when its authority chain is present in
	// verified state; the signed endpoint peer and bootstrap remain eligible.
	got := GossipOutboundPeers(input, now)
	if len(got) != 2 || got[0] != "bootstrap.catofes." || got[1] != "signed.catofes." {
		t.Fatalf("outbound peers = %v", got)
	}
}

func TestShouldRelayGossipUpdate(t *testing.T) {
	now := time.Unix(1000, 0)
	if allowed, reason := ShouldRelayGossipUpdate(corestate.PeerCheckpoint{}, "source", "source", "root", now); allowed || reason != "source_peer" {
		t.Fatalf("source decision = %v %q", allowed, reason)
	}
	checkpoint := corestate.PeerCheckpoint{BackoffUntilUnix: now.Add(time.Minute).Unix()}
	if allowed, reason := ShouldRelayGossipUpdate(checkpoint, "peer", "source", "root", now); allowed || reason != "backoff" {
		t.Fatalf("backoff decision = %v %q", allowed, reason)
	}
	checkpoint = corestate.PeerCheckpoint{LastRelayCatalogRootHex: "root"}
	if allowed, reason := ShouldRelayGossipUpdate(checkpoint, "peer", "source", "root", now); allowed || reason != "relay_root_unchanged" {
		t.Fatalf("root decision = %v %q", allowed, reason)
	}
	if allowed, reason := ShouldRelayGossipUpdate(corestate.PeerCheckpoint{}, "peer", "source", "root", now); !allowed || reason != "" {
		t.Fatalf("allowed decision = %v %q", allowed, reason)
	}
}
