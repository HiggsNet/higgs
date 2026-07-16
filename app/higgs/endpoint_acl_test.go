package main

import (
	"net/netip"
	"testing"

	"github.com/Catofes/higgs/pkg/core/zone"
	"github.com/Catofes/higgs/pkg/routing"
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
