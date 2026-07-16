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
	higgsservice "github.com/Catofes/higgs/pkg/service"
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
	ipv6Plan, err := parseServiceNetworkDescriptor("auto;::/112;::100/120;::1", 6)
	if err != nil {
		t.Fatalf("parseServiceNetworkDescriptor: %v", err)
	}
	config.Services = servicesConfig{
		Networks: []serviceNetworkConfig{{
			ID: "svcnet", Name: "higgs-services", Driver: "bridge", RoutingInstance: "main",
			IPv6: &ipv6Plan,
		}},
		Instances: []serviceInstanceConfig{{
			ID: "egress", Type: "socks5", Region: "cn-east", Network: "svcnet",
			Address: serviceAddressSpec{Raw: "::20", Addr: netip.MustParseAddr("::20"), Relative: true}, Port: 1080, AllowZones: mustServiceZoneSelectors(t, "clients.catofes.", "*.partners.catofes."),
		}},
	}
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
	if report.Services[0].Network != "svcnet" || report.Services[0].DockerNetwork != "higgs-services" || report.Services[0].NetworkSubnet != "fd42:1::/112" {
		t.Fatalf("network projection = %#v", report.Services[0])
	}
	if got := strings.Join(report.Services[0].AllowZones, ","); got != "clients.catofes.,*.partners.catofes." {
		t.Fatalf("allow_zones = %q", got)
	}

	ns.Zones[managed].Authority.Keys[0].Capabilities[0].Permissions = []zone.Permission{zone.PermWriteRoute}
	if _, err := buildServiceValidationReport(rt, state, "egress"); err == nil || !strings.Contains(err.Error(), "write authorization") {
		t.Fatalf("missing capability error = %v", err)
	}
}

func TestResolveServiceNetworkAutoRequiresUniqueAssignment(t *testing.T) {
	owner := zone.ZonePath("node-a.catofes.")
	plan, err := parseServiceNetworkDescriptor("auto;::/112;::100/120;::1", 6)
	if err != nil {
		t.Fatalf("parseServiceNetworkDescriptor: %v", err)
	}
	ars := &routing.AuthorizedRouteSet{AllAssignments: []*routing.AssignmentEntry{
		{Prefix: netip.MustParsePrefix("fd42:1::/64"), AssignedTo: owner},
		{Prefix: netip.MustParsePrefix("fd42:2::/64"), AssignedTo: owner},
	}}
	if _, _, err := resolveServiceNetworkPlan(plan, owner, ars); err == nil || !strings.Contains(err.Error(), "auto is ambiguous") {
		t.Fatalf("ambiguity error = %v", err)
	}
	plan, err = parseServiceNetworkDescriptor("assignment:fd42:2::/64;::/112;::100/120;::1", 6)
	if err != nil {
		t.Fatalf("parse explicit descriptor: %v", err)
	}
	resolved, assignment, err := resolveServiceNetworkPlan(plan, owner, ars)
	if err != nil {
		t.Fatalf("resolve explicit plan: %v", err)
	}
	if resolved.Subnet.String() != "fd42:2::/112" || assignment.Prefix.String() != "fd42:2::/64" {
		t.Fatalf("resolved = %#v, assignment = %#v", resolved, assignment)
	}
}

func TestResolveServiceInstanceAddressRejectsDynamicRange(t *testing.T) {
	network := resolvedServiceNetwork{IPv6: &serviceNetworkIPAMConfig{
		Subnet: netip.MustParsePrefix("fd42:1::/112"), IPRange: netip.MustParsePrefix("fd42:1::100/120"), Gateway: netip.MustParseAddr("fd42:1::1"),
	}}
	inside := serviceAddressSpec{Raw: "::120", Addr: netip.MustParseAddr("::120"), Relative: true}
	if _, _, _, err := resolveServiceInstanceAddress(inside, network); err == nil || !strings.Contains(err.Error(), "dynamic range") {
		t.Fatalf("dynamic range error = %v", err)
	}
	static := serviceAddressSpec{Raw: "::20", Addr: netip.MustParseAddr("::20"), Relative: true}
	addr, _, _, err := resolveServiceInstanceAddress(static, network)
	if err != nil || addr.String() != "fd42:1::20" {
		t.Fatalf("static address = %s, error = %v", addr, err)
	}
}

func mustServiceZoneSelectors(t *testing.T, values ...string) []higgsservice.ZoneSelector {
	t.Helper()
	out := make([]higgsservice.ZoneSelector, 0, len(values))
	for _, value := range values {
		selector, err := higgsservice.ParseZoneSelector(value)
		if err != nil {
			t.Fatalf("ParseZoneSelector(%q): %v", value, err)
		}
		out = append(out, selector)
	}
	return out
}

func addServiceTestRecord(t *testing.T, state *zone.ZoneState, key, recordType string, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	state.Records[key] = &zone.Record{Zone: state.Path, Key: key, Type: recordType, Value: data}
}
