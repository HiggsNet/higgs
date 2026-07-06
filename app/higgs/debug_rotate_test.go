package main

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"

	"github.com/Catofes/higgs/internal/inspect"
	inspecttext "github.com/Catofes/higgs/internal/inspect/text"
	"github.com/Catofes/higgs/pkg/transport/ipsec"
)

func TestRotateRuntimeCurrentPrefersActiveRuntimeOverPlannedSpec(t *testing.T) {
	link := inspect.LinkView{
		ID:              "link-1",
		LinkID:          "link-1",
		TransportID:     "ipsec-526e55bae2e1",
		ChildSAName:     "ipsec-526e55bae2e1-child",
		InterfaceName:   "hgs1be3f390",
		XFRMIfID:        467923856,
		Endpoint:        "123.57.143.66:30002",
		LocalTunnelAddr: "fe80::24c7:24ac:32e9:cd45%hgs1be3f390 netns=higgstesth2",
		PeerTunnelAddr:  "fe80::abdb:3c51:6e24:8655%hgs1be3f390 netns=higgstesth2",
		Rotation: inspect.LinkRotation{
			RemoteGeneration: 1,
			StagedGeneration: 2,
		},
	}
	spec := &ipsec.TransportLinkSpec{
		Generation:      2,
		TransportID:     "ipsec-f46fb3d71fe8-r2",
		InterfaceName:   "hgs28e3c6e5",
		XFRMIfID:        686016229,
		LocalTunnelAddr: netip.MustParseAddr("fe80::5ff8:918b:338e:35e6"),
		PeerTunnelAddr:  netip.MustParseAddr("fe80::ec14:d563:b479:44ed"),
		NetNS:           "higgstesth2",
		ContactPoints:   []ipsec.ContactPoint{{Address: "123.57.143.66", NATTPort: 30003, Generation: 2}},
	}

	got := rotateRuntimeCurrent(link, spec)
	if got.Port != "30002" || got.Endpoint != "123.57.143.66:30002" {
		t.Fatalf("current endpoint/port = %q/%q, want active runtime 123.57.143.66:30002/30002", got.Endpoint, got.Port)
	}
	if got.LocalTunnelAddr != link.LocalTunnelAddr || got.PeerTunnelAddr != link.PeerTunnelAddr {
		t.Fatalf("current tunnels = %q/%q, want active runtime tunnels", got.LocalTunnelAddr, got.PeerTunnelAddr)
	}
}

func TestDebugLinksPlannerShowsActiveRuntimeTunnel(t *testing.T) {
	var out bytes.Buffer
	link := inspect.LinkView{
		ID:              "link-1",
		PeerZone:        "venus-aliyun-pek.catofes.",
		GroupID:         "ipsec-main",
		LinkID:          "link-1",
		PathKey:         "family:ipv4",
		TransportID:     "ipsec-526e55bae2e1",
		DesiredSpecHash: "actual-hash",
		ActualState:     "up",
		Endpoint:        "123.57.143.66:30002",
		InterfaceName:   "hgs1be3f390",
		XFRMIfID:        467923856,
		LocalTunnelAddr: "fe80::old-local%hgs1be3f390 netns=higgstesth2",
		PeerTunnelAddr:  "fe80::old-peer%hgs1be3f390 netns=higgstesth2",
		Desired: &inspect.DesiredLink{
			TransportID:     "ipsec-f46fb3d71fe8-r2",
			DesiredSpecHash: "desired-hash",
			LocalTunnelAddr: "fe80::new-local%hgs28e3c6e5 netns=higgstesth2",
			PeerTunnelAddr:  "fe80::new-peer%hgs28e3c6e5 netns=higgstesth2",
		},
	}

	if err := inspecttext.WriteLinksDebug(&out, inspecttext.LinksDebugView{
		Inspection: inspect.LinkInspection{
			Summary: inspect.LinkSummary{LinkInstances: 1},
			Links:   []inspect.LinkView{link},
		},
	}); err != nil {
		t.Fatalf("WriteLinksDebug: %v", err)
	}
	output := out.String()
	for _, want := range []string{
		"    runtime_id: ipsec-526e55bae2e1",
		"    endpoint: 123.57.143.66:30002",
		"    interface: hgs1be3f390(467923856)",
		"    local_tunnel: fe80::old-local%hgs1be3f390 netns=higgstesth2",
		"    peer_tunnel: fe80::old-peer%hgs1be3f390 netns=higgstesth2",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("debug links output missing %q:\n%s", want, output)
		}
	}
	if strings.Contains(output, "fe80::new-local%hgs28e3c6e5") || strings.Contains(output, "fe80::new-peer%hgs28e3c6e5") {
		t.Fatalf("debug links planner mixed desired tunnel into active runtime block:\n%s", output)
	}
}

func TestRotateRuntimeStagedUsesPersistedRuntimeAndMatchingSA(t *testing.T) {
	link := inspect.LinkView{
		ID:     "link-1",
		LinkID: "link-1",
		Rotation: inspect.LinkRotation{
			StagedGeneration:      2,
			StagedIKEName:         "ipsec-f46fb3d71fe8-r2",
			StagedChildSAName:     "ipsec-f46fb3d71fe8-r2-child",
			StagedInterfaceName:   "hgs28e3c6e5",
			StagedXFRMIfID:        686016229,
			StagedLocalTunnelAddr: "fe80::5ff8:918b:338e:35e6%hgs28e3c6e5 netns=higgstesth2",
			StagedPeerTunnelAddr:  "fe80::ec14:d563:b479:44ed%hgs28e3c6e5 netns=higgstesth2",
		},
	}
	sas := []linkSAState{{
		Name:           "ipsec-f46fb3d71fe8-r2",
		ChildSA:        "ipsec-f46fb3d71fe8-r2-child-24",
		XFRMIfID:       686016229,
		RemoteEndpoint: "123.57.143.66:30003",
		Established:    true,
	}}

	got := rotateRuntimeStaged(link, nil, sas)
	if got.Endpoint != "123.57.143.66:30003" || got.Port != "30003" {
		t.Fatalf("staged endpoint/port = %q/%q, want 123.57.143.66:30003/30003", got.Endpoint, got.Port)
	}
	if got.LocalTunnelAddr != "fe80::5ff8:918b:338e:35e6%hgs28e3c6e5 netns=higgstesth2" {
		t.Fatalf("local tunnel = %q, want persisted staged local tunnel", got.LocalTunnelAddr)
	}
	if got.PeerTunnelAddr != "fe80::ec14:d563:b479:44ed%hgs28e3c6e5 netns=higgstesth2" {
		t.Fatalf("peer tunnel = %q, want persisted staged peer tunnel", got.PeerTunnelAddr)
	}
}
