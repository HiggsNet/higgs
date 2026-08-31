package host

import (
	"crypto/ed25519"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
)

func TestPlanGossipEndpointIntentRefreshAndGrace(t *testing.T) {
	now := time.Unix(1000, 0)
	managed := zone.ZonePath("peer.catofes.")
	network, privateKey := signedDiscoveryNetwork(t, managed, true, nil, now)
	verified := &corestate.VerifiedState{ManagedZone: managed, Network: network, IdentityPrivateKey: privateKey}
	input := GossipEndpointIntentInput{
		Verified: verified, Now: now, TTL: time.Hour, Grace: 10 * time.Minute, Refresh: 30 * time.Minute,
		Endpoints: []gossip.LocalEndpoint{{IP: net.ParseIP("198.51.100.10"), Port: 33434, Scope: "global", Source: gossip.SourceReflector}},
	}

	intent, err := PlanGossipEndpointIntent(input)
	if err != nil || intent == nil {
		t.Fatalf("initial intent/error = %#v/%v", intent, err)
	}
	first := decodeEndpointIntent(t, intent)
	if len(first.Endpoints) != 1 || first.Endpoints[0].Address != "198.51.100.10" {
		t.Fatalf("initial endpoints = %#v", first.Endpoints)
	}
	installEndpointIntent(t, verified.Network, privateKey, intent, now)

	input.Now = now.Add(time.Minute)
	input.Endpoints[0].IP = net.ParseIP("198.51.100.20")
	intent, err = PlanGossipEndpointIntent(input)
	if err != nil || intent == nil {
		t.Fatalf("changed intent/error = %#v/%v", intent, err)
	}
	updated := decodeEndpointIntent(t, intent)
	if len(updated.Endpoints) != 2 || updated.Endpoints[0].Address != "198.51.100.20" || updated.Endpoints[1].Address != "198.51.100.10" {
		t.Fatalf("grace endpoints = %#v", updated.Endpoints)
	}
	installEndpointIntent(t, verified.Network, privateKey, intent, input.Now)

	input.Now = now.Add(5 * time.Minute)
	if intent, err = PlanGossipEndpointIntent(input); err != nil || intent != nil {
		t.Fatalf("early refresh intent/error = %#v/%v", intent, err)
	}
	input.Now = now.Add(31 * time.Minute)
	if intent, err = PlanGossipEndpointIntent(input); err != nil || intent == nil {
		t.Fatalf("due refresh intent/error = %#v/%v", intent, err)
	}
}

func TestPlanGossipEndpointIntentDisableAndIdentityAdmission(t *testing.T) {
	now := time.Unix(1000, 0)
	managed := zone.ZonePath("peer.catofes.")
	network, privateKey := signedDiscoveryNetwork(t, managed, true, nil, now)
	verified := &corestate.VerifiedState{ManagedZone: managed, Network: network, IdentityPrivateKey: privateKey}
	seed, err := PlanGossipEndpointIntent(GossipEndpointIntentInput{
		Verified: verified, Now: now, TTL: time.Hour,
		Endpoints: []gossip.LocalEndpoint{{IP: net.ParseIP("192.0.2.1"), Port: 33434, Source: gossip.SourceAdvertise}},
	})
	if err != nil || seed == nil {
		t.Fatalf("seed intent/error = %#v/%v", seed, err)
	}
	installEndpointIntent(t, network, privateKey, seed, now)

	clear, err := PlanGossipEndpointIntent(GossipEndpointIntentInput{Verified: verified, Disabled: true, Now: now.Add(time.Minute), TTL: time.Hour})
	if err != nil || clear == nil || len(decodeEndpointIntent(t, clear).Endpoints) != 0 {
		t.Fatalf("clear intent/error = %#v/%v", clear, err)
	}
	installEndpointIntent(t, network, privateKey, clear, now.Add(time.Minute))
	if noop, err := PlanGossipEndpointIntent(GossipEndpointIntentInput{Verified: verified, Disabled: true, Now: now.Add(2 * time.Minute), TTL: time.Hour}); err != nil || noop != nil {
		t.Fatalf("disabled no-op/error = %#v/%v", noop, err)
	}

	verified.ManagedZone = zone.RootZone
	if intent, err := PlanGossipEndpointIntent(GossipEndpointIntentInput{Verified: verified, Now: now}); err != nil || intent != nil {
		t.Fatalf("root intent/error = %#v/%v", intent, err)
	}
	verified.ManagedZone = managed
	verified.IdentityPrivateKey = nil
	if intent, err := PlanGossipEndpointIntent(GossipEndpointIntentInput{Verified: verified, Now: now}); err != nil || intent != nil {
		t.Fatalf("unadmitted identity intent/error = %#v/%v", intent, err)
	}
}

func decodeEndpointIntent(t *testing.T, intent *corestate.PutProtocolRecordIntent) gossip.EndpointRecord {
	t.Helper()
	var record gossip.EndpointRecord
	if err := json.Unmarshal(intent.Value, &record); err != nil {
		t.Fatal(err)
	}
	return record
}

func installEndpointIntent(t *testing.T, network *zone.NetworkState, privateKey ed25519.PrivateKey, intent *corestate.PutProtocolRecordIntent, now time.Time) {
	t.Helper()
	record := &zone.Record{Zone: intent.Zone, Key: intent.Key, Type: intent.Type, Value: append([]byte(nil), intent.Value...), Version: 1, Timestamp: now.Unix()}
	if existing := network.Zones[intent.Zone].Records[intent.Key]; existing != nil {
		record.Version = existing.Version + 1
		record.PrevHash = photoncrypto.RecordHash(existing)
	}
	if err := photoncrypto.SignRecord(record, privateKey); err != nil {
		t.Fatal(err)
	}
	network.Zones[intent.Zone].Records[intent.Key] = record
}
