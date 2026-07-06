package inspect

import (
	"testing"

	"github.com/Catofes/higgs/pkg/transport/ipsec"
)

func TestBuildRotateDebugBuildsRuntimeAndMatchingSAs(t *testing.T) {
	view := BuildRotateDebug(RotateDebugInput{
		Inspection: LinkInspection{
			Summary: LinkSummary{LastRunUnix: 1700000000, LinkInstances: 2},
			Links: []LinkView{
				{ID: "link-a", PeerZone: "node-a.catofes."},
				{
					ID:              "link-b",
					PeerZone:        "node-b.catofes.",
					LinkID:          "link-b",
					PathKey:         "family:ipv4",
					TransportID:     "ipsec-current",
					ChildSAName:     "ipsec-current-child",
					InterfaceName:   "hgsold",
					XFRMIfID:        1001,
					Endpoint:        "198.51.100.10:30002",
					LocalTunnelAddr: "fe80::1%hgsold",
					PeerTunnelAddr:  "fe80::2%hgsold",
					Rotation: LinkRotation{
						RemoteGeneration:      1,
						StagedGeneration:      2,
						StagedIKEName:         "ipsec-current-r2",
						StagedChildSAName:     "ipsec-current-r2-child",
						StagedInterfaceName:   "hgsnew",
						StagedXFRMIfID:        2002,
						StagedLocalTunnelAddr: "fe80::3%hgsnew",
						StagedPeerTunnelAddr:  "fe80::4%hgsnew",
					},
				},
			},
		},
		PlannedSpecs: map[string]ipsec.TransportLinkSpec{
			"link-b": {
				Generation:    2,
				LinkID:        "link-b",
				TransportID:   "ipsec-current-r2",
				InterfaceName: "hgsnew",
				XFRMIfID:      2002,
				ContactPoints: []ipsec.ContactPoint{{
					Address:    "198.51.100.10",
					NATTPort:   30003,
					Generation: 2,
				}},
			},
		},
		ReplannedDesired:  2,
		DesiredPlanSource: "planned",
		Filter:            "node-b",
		StoredLabel:       "stored_sas",
		LiveLabel:         "live_sas",
		StoredSAs: []LinkSA{{
			Name:           "ipsec-current",
			ChildSA:        "ipsec-current-child",
			XFRMIfID:       1001,
			RemoteEndpoint: "198.51.100.10:30002",
			Established:    true,
		}},
		LiveSAs: []LinkSA{{
			Name:           "ipsec-current-r2",
			ChildSA:        "ipsec-current-r2-child",
			XFRMIfID:       2002,
			RemoteEndpoint: "198.51.100.10:30003",
			Established:    true,
		}},
	})

	if view.LinkInstances != 2 || view.PlannedDesired != 2 || view.Filter != "node-b" || len(view.Links) != 1 {
		t.Fatalf("rotate view header/filter = %+v", view)
	}
	link := view.Links[0]
	if link.Link.ID != "link-b" || link.Current.RuntimeID != "ipsec-current" || link.Current.Port != "30002" {
		t.Fatalf("current runtime = %+v", link.Current)
	}
	if !link.HasStaged || link.Staged.RuntimeID != "ipsec-current-r2" || link.Staged.Port != "30003" {
		t.Fatalf("staged runtime = has=%v %+v", link.HasStaged, link.Staged)
	}
	if len(link.StoredMatchingSAs) != 1 || len(link.LiveMatchingSAs) != 1 {
		t.Fatalf("matching SAs = stored=%+v live=%+v", link.StoredMatchingSAs, link.LiveMatchingSAs)
	}
	if link.PortGenerationSummary != "2/1/2" || link.PortSummary != "4500/30003/30002/30003" {
		t.Fatalf("ports = generation=%q summary=%q", link.PortGenerationSummary, link.PortSummary)
	}
}
