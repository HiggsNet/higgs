package main

import (
	"encoding/json"
	"testing"

	"github.com/Catofes/higgs/pkg/core/zone"
	"github.com/Catofes/higgs/pkg/routing"
	higgsservice "github.com/Catofes/higgs/pkg/service"
)

func TestPublishAndWithdrawSOCKS5Service(t *testing.T) {
	rt, managed := buildRouteTestRuntime(t)
	state, err := rt.LoadState()
	if err != nil {
		t.Fatal(err)
	}
	putServiceIPAMRecord(t, state.Network.Zones[zone.RootZone], "ipam/pools/fd42::_16", routing.RecordTypeIPAMPool, routing.IPAMPoolRecord{
		Version: 1, Prefix: "fd42::/16", DelegatedTo: zone.RootZone, Active: true,
	})
	putServiceIPAMRecord(t, state.Network.Zones[zone.RootZone], "ipam/assignments/fd42:1::_64", routing.RecordTypeIPAMAssignment, routing.IPAMAssignmentRecord{
		Version: 1, Prefix: "fd42:1::/64", AssignedTo: managed, Active: true,
	})
	if err := rt.SaveState(state); err != nil {
		t.Fatal(err)
	}
	if err := publishSOCKS5ServiceWithRuntime(rt, "egress-cn", "cn-east", "fd42:1::20", 3128); err != nil {
		t.Fatalf("publish: %v", err)
	}
	state, _ = rt.LoadState()
	record := state.Network.Zones[managed].Records["services/egress-cn"]
	parsed, err := higgsservice.ParseSOCKS5Record(record)
	if err != nil || !parsed.IsActive() || record.Version != 1 {
		t.Fatalf("published record = %#v, parsed = %#v, error = %v", record, parsed, err)
	}
	if err := withdrawSOCKS5ServiceWithRuntime(rt, "egress-cn"); err != nil {
		t.Fatalf("withdraw: %v", err)
	}
	state, _ = rt.LoadState()
	record = state.Network.Zones[managed].Records["services/egress-cn"]
	parsed, err = higgsservice.ParseSOCKS5Record(record)
	if err != nil || parsed.IsActive() || record.Version != 2 {
		t.Fatalf("withdrawn record = %#v, parsed = %#v, error = %v", record, parsed, err)
	}
}

func TestPublishSOCKS5ServiceRejectsUnownedAddress(t *testing.T) {
	rt, _ := buildRouteTestRuntime(t)
	if err := publishSOCKS5ServiceWithRuntime(rt, "egress", "cn", "fd42:1::20", 3128); err == nil {
		t.Fatal("expected unowned address error")
	}
}

func putServiceIPAMRecord(t *testing.T, state *zone.ZoneState, key, recordType string, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	state.Records[key] = &zone.Record{Zone: state.Path, Key: key, Type: recordType, Value: data}
}
