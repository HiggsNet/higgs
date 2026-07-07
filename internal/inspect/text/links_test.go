package text

import (
	"strings"
	"testing"

	"github.com/Catofes/higgs/internal/inspect"
)

func TestWriteLinksDebugFiltersAndPrintsRuntimeFields(t *testing.T) {
	view := inspect.LinksDebugView{
		Inspection: inspect.LinkInspection{
			Summary: inspect.LinkSummary{
				LastRunUnix:   1700000000,
				DesiredLinks:  1,
				ActualSAs:     1,
				LinkInstances: 1,
			},
			Links: []inspect.LinkView{{
				ID:              "link-1",
				PeerZone:        "node-b.catofes.",
				GroupID:         "main",
				ActualState:     "up",
				Endpoint:        "198.51.100.10:4500",
				InterfaceName:   "hgs123",
				XFRMIfID:        123,
				LocalTunnelAddr: "fe80::1%hgs123",
				PeerTunnelAddr:  "fe80::2%hgs123",
				DesiredSpecHash: "abcdef1234567890",
				Routing: inspect.LinkRouting{
					BirdState:      "running",
					BirdNeighbors:  "2",
					BirdBestRoutes: "4",
				},
				ActualSA: &inspect.LinkSA{
					ChildSA:        "child-a",
					Established:    true,
					LocalEndpoint:  "192.0.2.1:4500",
					RemoteEndpoint: "198.51.100.10:4500",
					ReqID:          55,
				},
			}},
		},
		ReplannedDesired:  1,
		DesiredPlanSource: "live",
		Filter:            "node-b",
	}
	var buf strings.Builder
	if err := WriteLinksDebug(&buf, view); err != nil {
		t.Fatalf("WriteLinksDebug: %v", err)
	}
	output := buf.String()
	for _, want := range []string{
		"last_run: 2023-11-14T22:13:20Z",
		"desired_links: 1",
		"planned_desired_links: 1",
		"desired_source: live",
		"filter: node-b",
		"matched_links: 1",
		"link link-1",
		"peer: node-b.catofes.",
		"interface: hgs123(123)",
		"sa_state: established",
		"reqid: 55",
		"bird_state: running",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("output missing %q:\n%s", want, output)
		}
	}
}

func TestWriteLinksDebugShowsActiveRuntimeTunnel(t *testing.T) {
	var out strings.Builder
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

	if err := WriteLinksDebug(&out, inspect.LinksDebugView{
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
