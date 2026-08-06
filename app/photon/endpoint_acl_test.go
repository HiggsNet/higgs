package main

import (
	"net/netip"
	"testing"

	"github.com/Catofes/photon/pkg/core/zone"
	"github.com/Catofes/photon/pkg/routing"
)

func TestResolveEndpointServicesTracksAuthorizedZoneRoutes(t *testing.T) {
	ars := &routing.AuthorizedRouteSet{Announced: map[zone.ZonePath]map[netip.Prefix]*routing.RouteEntry{
		"node-a.catofes.": {netip.MustParsePrefix("fd10:1::/64"): {}},
		"node-b.other.":   {netip.MustParsePrefix("10.2.0.0/24"): {}},
	}}
	services, err := resolveEndpointServices(map[string]endpointACL{
		"socks5": {Name: "socks5", Destination: "fd42::20", Protocol: "tcp", Port: 3128, Selectors: []string{"*.catofes."}},
	}, ars)
	if err != nil {
		t.Fatalf("resolveEndpointServices: %v", err)
	}
	if len(services) != 1 || len(services[0].Sources) != 1 || services[0].Sources[0].String() != "fd10:1::/64" {
		t.Fatalf("resolved services = %+v", services)
	}
}

func TestResolveEndpointServicesEmptyMatchIsFailClosedInput(t *testing.T) {
	services, err := resolveEndpointServices(map[string]endpointACL{
		"socks5": {Name: "socks5", Destination: "fd42::20", Protocol: "tcp", Port: 3128, Selectors: []string{"missing.catofes."}},
	}, &routing.AuthorizedRouteSet{Announced: map[zone.ZonePath]map[netip.Prefix]*routing.RouteEntry{}})
	if err != nil {
		t.Fatalf("resolveEndpointServices: %v", err)
	}
	if len(services) != 1 || len(services[0].Sources) != 0 {
		t.Fatalf("resolved services = %+v", services)
	}
}

func TestResolveEndpointServicesIPScope(t *testing.T) {
	services, err := resolveEndpointServices(map[string]endpointACL{
		"socks5": {
			Name: "socks5", Destination: "fd42::20", Scope: endpointACLScopeIP,
			Selectors: []string{"*.catofes."},
		},
	}, &routing.AuthorizedRouteSet{Announced: map[zone.ZonePath]map[netip.Prefix]*routing.RouteEntry{
		"node-a.catofes.": {netip.MustParsePrefix("fd10:1::/64"): {}},
	}})
	if err != nil {
		t.Fatalf("resolveEndpointServices: %v", err)
	}
	if len(services) != 1 || services[0].Proto != "" || services[0].Port != 0 {
		t.Fatalf("IP-scope services = %+v", services)
	}
}

func TestValidateEndpointACLScopes(t *testing.T) {
	legacy, err := validateEndpointACL(endpointACL{
		Name: "legacy", Destination: "fd42::20", Protocol: "tcp", Port: 3128,
		Selectors: []string{"*.catofes."},
	})
	if err != nil || legacy.Scope != endpointACLScopePort {
		t.Fatalf("legacy ACL = %+v, %v", legacy, err)
	}
	if _, err := validateEndpointACL(endpointACL{
		Name: "bad", Destination: "fd42::20", Scope: endpointACLScopeIP, Protocol: "udp",
		Selectors: []string{"*.catofes."},
	}); err == nil {
		t.Fatal("IP-scope ACL accepted a protocol")
	}
}
