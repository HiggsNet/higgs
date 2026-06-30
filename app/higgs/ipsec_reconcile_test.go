package main

import (
	"testing"

	"github.com/Catofes/higgs/internal/inspect"
	"github.com/Catofes/higgs/pkg/transport/ipsec"
)

func TestDebugIPsecPortsPreferContactAndRuntimeEndpoints(t *testing.T) {
	spec := &ipsec.TransportLinkSpec{
		Generation: 3,
		ContactPoints: []ipsec.ContactPoint{
			{Generation: 3, IKEPort: 30004, NATTPort: 33403},
			{Generation: 2, IKEPort: 30002, NATTPort: 33401},
		},
	}

	if got := debugPortGenerationSummary(spec, inspect.LinkRotation{RemoteGeneration: 1, StagedGeneration: 2}); got != "3/1/2" {
		t.Fatalf("port generation summary = %q", got)
	}
	if got := debugPortSummary(spec, "198.51.100.20:4500", "198.51.100.20:33403", 2); got != "4500/33403/33403/33401" {
		t.Fatalf("port summary = %q", got)
	}
	if got := debugRemotePort(spec, "198.51.100.20:4500"); got != "33403" {
		t.Fatalf("remote port = %q", got)
	}
	if got := debugStagedPort(spec, 2); got != "33401" {
		t.Fatalf("staged port = %q", got)
	}
	if got := debugEndpointPort("[2001:db8::1]:4500"); got != "4500" {
		t.Fatalf("endpoint port = %q", got)
	}
}

func TestIPsecQualityAddrPortMatchesOnlySamePortGeneration(t *testing.T) {
	current := ipsec.PortAdvertisement{
		Generation: 3,
		IKE:        ipsec.PortBinding{Advertised: 30004},
		NATT:       ipsec.PortBinding{Advertised: 33403},
		Current:    true,
	}
	previous := ipsec.PortAdvertisement{
		Generation: 1,
		IKE:        ipsec.PortBinding{Advertised: 500},
		NATT:       ipsec.PortBinding{Advertised: 4500},
		Current:    false,
	}

	if !ipsecQualityAddrPortMatches(33403, current) {
		t.Fatalf("current NAT-T port did not match current generation")
	}
	if ipsecQualityAddrPortMatches(33403, previous) {
		t.Fatalf("current NAT-T port matched previous generation")
	}
	if ipsecQualityAddrPortMatches(0, current) {
		t.Fatalf("zero port matched IPsec contact quality")
	}
}
