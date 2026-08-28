package main

import (
	"testing"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/routing"
	photonservice "github.com/HiggsNet/photon/pkg/service"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func TestGenericRecordPutRejectsDaemonOwnedKeysAndTypes(t *testing.T) {
	tests := []struct {
		name       string
		key        string
		recordType string
		wantError  bool
	}{
		{name: "ordinary application record", key: "apps/example", recordType: "application.example.v1"},
		{name: "ipam pool key", key: routing.RecordKeyPrefixIPAMPools + "10.0.0.0_8", recordType: "application.example.v1", wantError: true},
		{name: "ipam assignment key", key: routing.RecordKeyPrefixIPAMAssignments + "10.0.0.0_8", recordType: "application.example.v1", wantError: true},
		{name: "route key", key: routing.RecordKeyPrefixRoutes + "10.0.0.0_8", recordType: "application.example.v1", wantError: true},
		{name: "service key", key: photonservice.RecordKeyPrefix + "socks5", recordType: "application.example.v1", wantError: true},
		{name: "routing key", key: routing.RecordKeyRoutingNetns, recordType: "application.example.v1", wantError: true},
		{name: "ipsec key", key: ipsec.RecordKeyPorts, recordType: "application.example.v1", wantError: true},
		{name: "sync key", key: gossip.EndpointRecordKeyUDP, recordType: "application.example.v1", wantError: true},
		{name: "reserved type outside namespace", key: "apps/example", recordType: routing.RecordTypeIPAMPool, wantError: true},
		{name: "service type outside namespace", key: "apps/example", recordType: photonservice.RecordTypeSOCKS5, wantError: true},
		{name: "endpoint type outside namespace", key: "apps/example", recordType: "sync.endpoint", wantError: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateGenericRecordPut(tt.key, tt.recordType)
			if (err != nil) != tt.wantError {
				t.Fatalf("validateGenericRecordPut(%q, %q) error = %v, wantError=%t", tt.key, tt.recordType, err, tt.wantError)
			}
		})
	}
}

func TestLookupRecordDetail(t *testing.T) {
	rt, managed := buildRouteTestRuntime(t)
	if err := putRecordDirect(rt, managed, "site/name", []byte(`{"name":"pek"}`), "policy.json"); err != nil {
		t.Fatalf("putRecordDirect: %v", err)
	}
	state, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}

	record, err := lookupRecordDetailFromNetwork(state.Network, managed, "site/name", 0)
	if err != nil {
		t.Fatalf("lookupRecordDetail: %v", err)
	}
	if record.Zone != string(managed) || record.Key != "site/name" || record.Type != "policy.json" {
		t.Fatalf("record detail = %#v", record)
	}
	if record.Value != `{"name":"pek"}` || record.ValueJSON == nil || record.RecordHash == "" {
		t.Fatalf("record detail missing value fields: %#v", record)
	}
	if len(record.RecordHistory) != 0 {
		t.Fatalf("record_history should be omitted by default: %#v", record)
	}

	if err := putRecordDirect(rt, managed, "site/name", []byte(`{"name":"pek-2"}`), "policy.json"); err != nil {
		t.Fatalf("putRecordDirect second version: %v", err)
	}
	if err := putRecordDirect(rt, managed, "site/name", []byte(`{"name":"pek-3"}`), "policy.json"); err != nil {
		t.Fatalf("putRecordDirect third version: %v", err)
	}
	state, err = rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState after history writes: %v", err)
	}
	record, err = lookupRecordDetailFromNetwork(state.Network, managed, "site/name", 2)
	if err != nil {
		t.Fatalf("lookupRecordDetail with history: %v", err)
	}
	history := record.RecordHistory
	if len(history) != 2 {
		t.Fatalf("history len = %d, want 2", len(history))
	}
	if history[0].Version != 2 || history[1].Version != 1 {
		t.Fatalf("history versions = %#v, want latest history first", history)
	}

	if _, err := lookupRecordDetailFromNetwork(state.Network, managed, "missing", 0); err == nil {
		t.Fatal("lookupRecordDetail missing record error = nil")
	}
	if _, err := lookupRecordDetailFromNetwork(state.Network, zone.ZonePath("missing."), "site/name", 0); err == nil {
		t.Fatal("lookupRecordDetail missing zone error = nil")
	}
	if _, err := lookupRecordDetailFromNetwork(state.Network, managed, "site/name", -1); err == nil {
		t.Fatal("lookupRecordDetail negative history error = nil")
	}
}
