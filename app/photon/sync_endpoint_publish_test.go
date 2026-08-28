package main

import (
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
)

func TestEndpointProtocolIntentRefreshAndGrace(t *testing.T) {
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

	intent, err := sr.endpointProtocolIntent(verifiedStateForTest(state))
	if err != nil || intent == nil {
		t.Fatalf("initial plan = intent:%+v err:%v", intent, err)
	}
	first := endpointRecordFromIntent(t, intent)
	if len(first.Endpoints) != 1 || first.Endpoints[0].Address != address {
		t.Fatalf("initial endpoints = %#v", first.Endpoints)
	}
	applyEndpointIntentForTest(t, state, intent, now)

	now = now.Add(time.Minute)
	address = "198.51.100.20"
	intent, err = sr.endpointProtocolIntent(verifiedStateForTest(state))
	if err != nil || intent == nil {
		t.Fatalf("changed plan = intent:%+v err:%v", intent, err)
	}
	updated := endpointRecordFromIntent(t, intent)
	if len(updated.Endpoints) < 2 || updated.Endpoints[0].Address != address || updated.Endpoints[1].Address != "198.51.100.10" {
		t.Fatalf("updated endpoints = %#v, want new endpoint plus grace", updated.Endpoints)
	}
	applyEndpointIntentForTest(t, state, intent, now)

	now = time.Unix(1300, 0)
	intent, err = sr.endpointProtocolIntent(verifiedStateForTest(state))
	if err != nil || intent != nil {
		t.Fatalf("early refresh = intent:%+v err:%v", intent, err)
	}
	now = time.Unix(2800, 0)
	intent, err = sr.endpointProtocolIntent(verifiedStateForTest(state))
	if err != nil || intent == nil {
		t.Fatalf("due refresh = intent:%+v err:%v", intent, err)
	}
}

func TestEndpointProtocolIntentDisablesAndSkipsRoot(t *testing.T) {
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
	intent, err := sr.endpointProtocolIntent(verifiedStateForTest(state))
	if err != nil || intent == nil {
		t.Fatalf("disable plan = intent:%+v err:%v", intent, err)
	}
	if got := endpointRecordFromIntent(t, intent); len(got.Endpoints) != 0 {
		t.Fatalf("disabled endpoints = %#v, want empty", got.Endpoints)
	}
	state.ManagedZone = zone.RootZone
	intent, err = sr.endpointProtocolIntent(verifiedStateForTest(state))
	if err != nil || intent != nil {
		t.Fatalf("root plan = intent:%+v err:%v", intent, err)
	}
}

func endpointRecordFromIntent(t *testing.T, intent *corestate.PutProtocolRecordIntent) gossip.EndpointRecord {
	t.Helper()
	var record gossip.EndpointRecord
	if err := json.Unmarshal(intent.Value, &record); err != nil {
		t.Fatalf("decode endpoint intent: %v", err)
	}
	return record
}

func applyEndpointIntentForTest(t *testing.T, state *stateFile, intent *corestate.PutProtocolRecordIntent, now time.Time) {
	t.Helper()
	record, err := buildSignedRecordAt(state, intent.Zone, intent.Key, intent.Value, intent.Type, now)
	if err != nil {
		t.Fatalf("build endpoint record: %v", err)
	}
	if err := state.Network.PutAt(record, now); err != nil {
		t.Fatalf("put endpoint record: %v", err)
	}
}
