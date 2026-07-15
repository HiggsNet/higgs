package main

import (
	"crypto/ed25519"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/Catofes/higgs/pkg/core/zone"
	"github.com/Catofes/higgs/pkg/routing"
	"github.com/Catofes/higgs/pkg/transport/ipsec"
)

func TestBuildServiceValidationReport(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	managed := zone.ZonePath("node-a.catofes.")
	ns := zone.NewNetworkState()
	ns.Zones[zone.RootZone] = zone.NewZoneState(zone.RootZone, nil)
	ns.Zones[managed] = zone.NewZoneState(managed, &zone.ZoneAuthority{
		Zone: managed, Epoch: 1, Threshold: 1,
		Keys: []zone.AuthorizedKey{{Key: pub, Capabilities: []zone.Capability{{Permissions: []zone.Permission{zone.PermWriteService}}}}},
	})
	addServiceTestRecord(t, ns.Zones[zone.RootZone], "ipam/pools/fd42::_16", routing.RecordTypeIPAMPool, routing.IPAMPoolRecord{
		Version: 1, Prefix: "fd42::/16", DelegatedTo: zone.RootZone, Active: true,
	})
	addServiceTestRecord(t, ns.Zones[zone.RootZone], "ipam/assignments/fd42:1::_64", routing.RecordTypeIPAMAssignment, routing.IPAMAssignmentRecord{
		Version: 1, Prefix: "fd42:1::/64", AssignedTo: managed, Active: true,
	})
	config := defaultAppConfig()
	config.Services = []serviceConfig{{
		ID: "egress", Type: "socks5", Region: "cn-east", NetNS: "default",
		Address: netip.MustParseAddr("fd42:1::20"), Port: 1080, AllowZones: []zone.ZonePath{"clients.catofes."},
	}}
	config.Netns = netnsConfig{Default: "default", Names: map[string]ipsec.NetNSSpec{"default": {Kind: ipsec.NetNSName, Name: "h2", Create: true}}}
	rt := &Runtime{Config: config, Clock: func() time.Time { return time.Unix(123, 0) }}
	state := &stateFile{ManagedZone: managed, ZonePrivateKey: priv, Network: ns}

	report, err := buildServiceValidationReport(rt, state, "egress")
	if err != nil {
		t.Fatalf("buildServiceValidationReport: %v", err)
	}
	if len(report.Services) != 1 || report.Services[0].AssignmentPrefix != "fd42:1::/64" {
		t.Fatalf("report = %#v", report)
	}
	if report.Services[0].RecordKey != "services/egress" || report.Services[0].RecordType != "service.socks5.v1" {
		t.Fatalf("record projection = %#v", report.Services[0])
	}

	ns.Zones[managed].Authority.Keys[0].Capabilities[0].Permissions = []zone.Permission{zone.PermWriteRoute}
	if _, err := buildServiceValidationReport(rt, state, "egress"); err == nil || !strings.Contains(err.Error(), "write authorization") {
		t.Fatalf("missing capability error = %v", err)
	}
}

func addServiceTestRecord(t *testing.T, state *zone.ZoneState, key, recordType string, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	state.Records[key] = &zone.Record{Zone: state.Path, Key: key, Type: recordType, Value: data}
}
