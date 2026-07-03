package main

import (
	"net/netip"
	"testing"
	"time"

	"github.com/Catofes/higgs/internal/inspect"
	"github.com/Catofes/higgs/pkg/health"
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
	if got := debugPortGenerationSummary(nil, inspect.LinkRotation{RemoteGeneration: 3}); got != "-/3/0" {
		t.Fatalf("missing spec port generation summary = %q", got)
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

func TestXFRMLinkStateMatchesCandidateRequiresLocalTunnelAddress(t *testing.T) {
	spec := ipsec.TransportLinkSpec{
		InterfaceName:   "hgs1",
		LocalTunnelAddr: netip.MustParseAddr("fe80::1234"),
	}
	state := ipsec.XFRMLinkState{
		NamespaceExists: true,
		InterfaceExists: true,
		Addresses:       []netip.Prefix{netip.MustParsePrefix("fe80::9999/64")},
	}
	if xfrmLinkStateMatchesCandidate(state, spec) {
		t.Fatalf("candidate matched with wrong interface address")
	}
	state.Addresses = []netip.Prefix{netip.MustParsePrefix("fe80::1234/64")}
	if !xfrmLinkStateMatchesCandidate(state, spec) {
		t.Fatalf("candidate did not match expected interface address")
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

func TestDaemonIPsecRotateCutoverReadyUsesHealthManager(t *testing.T) {
	now := time.Unix(1717171717, 0)
	manager := health.NewManager(health.DefaultProbeConfig(), health.DefaultHysteresisConfig(), nil)
	manager.SetTargets([]health.ProbeTarget{{
		ProbeID:         "link-1#staged",
		InstanceID:      "link-1",
		InterfaceName:   "hgsstage",
		PeerTunnelAddr:  netip.MustParseAddr("fe80::2"),
		LocalTunnelAddr: netip.MustParseAddr("fe80::1"),
		State:           ipsec.LinkStateUp,
		Staged:          true,
		ProbeRole:       "staged",
	}}, now)

	got := (&DaemonService{health: manager}).ipsecRotateCutoverReady()
	if ready, ok := got["link-1"]; !ok || ready {
		t.Fatalf("cutover readiness = %#v, want link-1=false while staged health is unknown", got)
	}
	if got := (&DaemonService{}).ipsecRotateCutoverReady(); got != nil {
		t.Fatalf("nil health readiness = %#v, want nil", got)
	}
}
