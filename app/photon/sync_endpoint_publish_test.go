package main

import (
	"net"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
)

func TestPublishEndpointRecordInStateRefreshAndGrace(t *testing.T) {
	state, config := buildTestNetworkState(t)
	state.ManagedZone = "node-b.catofes."
	config.PeerID = string(state.ManagedZone)
	config.ListenAddr = "127.0.0.1:33434"
	config.EndpointTTL = time.Hour
	config.EndpointRefresh = 30 * time.Minute
	config.EndpointGrace = 10 * time.Minute
	address := "198.51.100.10"
	oldCollect := collectSyncLocalEndpoints
	collectSyncLocalEndpoints = func(port uint16, _ []string, _ []string, _ time.Duration, _ bool) ([]gossip.LocalEndpoint, error) {
		return []gossip.LocalEndpoint{{IP: net.ParseIP(address), Port: port, Scope: "global", Source: gossip.SourceReflector}}, nil
	}
	t.Cleanup(func() { collectSyncLocalEndpoints = oldCollect })
	config.Reflectors = []string{"https://reflector.example"}
	now := time.Unix(1000, 0)
	sr := newSyncRuntime(config, nil, &Runtime{Clock: func() time.Time { return now }})

	changed, err := sr.publishEndpointRecordInState(state)
	if err != nil || !changed {
		t.Fatalf("initial publish = changed:%t err:%v", changed, err)
	}
	first := endpointRecordFromState(t, state, state.ManagedZone)
	if len(first.Endpoints) != 1 || first.Endpoints[0].Address != address {
		t.Fatalf("initial endpoints = %#v", first.Endpoints)
	}

	now = now.Add(time.Minute)
	address = "198.51.100.20"
	changed, err = sr.publishEndpointRecordInState(state)
	if err != nil || !changed {
		t.Fatalf("changed publish = changed:%t err:%v", changed, err)
	}
	updated := endpointRecordFromState(t, state, state.ManagedZone)
	if len(updated.Endpoints) < 2 || updated.Endpoints[0].Address != address || updated.Endpoints[1].Address != "198.51.100.10" {
		t.Fatalf("updated endpoints = %#v, want new endpoint plus grace", updated.Endpoints)
	}

	now = time.Unix(1300, 0)
	changed, err = sr.publishEndpointRecordInState(state)
	if err != nil || changed {
		t.Fatalf("early refresh = changed:%t err:%v", changed, err)
	}
	now = time.Unix(2800, 0)
	changed, err = sr.publishEndpointRecordInState(state)
	if err != nil || !changed {
		t.Fatalf("due refresh = changed:%t err:%v", changed, err)
	}
}

func TestPublishEndpointRecordInStateDisablesAndSkipsRoot(t *testing.T) {
	state, config := buildTestNetworkState(t)
	state.ManagedZone = "node-b.catofes."
	config.PeerID = string(state.ManagedZone)
	config.DisableEndpointPublish = true
	now := time.Unix(1000, 0)
	record := &zone.Record{Zone: state.ManagedZone, Key: gossip.EndpointRecordKeyUDP, Type: "sync.endpoint", Value: endpointRecordBytes([]gossip.LocalEndpoint{{IP: net.ParseIP("192.0.2.1"), Port: 33434}}, now), Version: 1, Timestamp: now.Unix()}
	if err := photoncrypto.SignRecord(record, state.ZonePrivateKey); err != nil {
		t.Fatalf("SignRecord: %v", err)
	}
	if err := state.Network.PutAt(record, now); err != nil {
		t.Fatalf("PutAt: %v", err)
	}
	sr := newSyncRuntime(config, nil, &Runtime{Clock: func() time.Time { return now }})
	changed, err := sr.publishEndpointRecordInState(state)
	if err != nil || !changed {
		t.Fatalf("disable publish = changed:%t err:%v", changed, err)
	}
	if got := endpointRecordFromState(t, state, state.ManagedZone); len(got.Endpoints) != 0 {
		t.Fatalf("disabled endpoints = %#v, want empty", got.Endpoints)
	}
	state.ManagedZone = zone.RootZone
	changed, err = sr.publishEndpointRecordInState(state)
	if err != nil || changed {
		t.Fatalf("root publish = changed:%t err:%v", changed, err)
	}
}
