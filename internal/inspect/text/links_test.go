package text

import (
	"strings"
	"testing"

	"github.com/Catofes/higgs/internal/inspect"
)

func TestWriteLinksDebugFiltersAndPrintsRuntimeFields(t *testing.T) {
	view := LinksDebugView{
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
