package main

import (
	"testing"

	"github.com/Catofes/higgs/internal/inspect"
)

func TestFilterLinkViewsMatchesPeerAndRuntimeFields(t *testing.T) {
	links := []inspect.LinkView{
		{
			ID:            "ipsec-main/node-a.catofes.",
			PeerZone:      "node-a.catofes.",
			LinkID:        "link-a",
			TransportID:   "ipsec-current",
			InterfaceName: "hgs11111111",
		},
		{
			ID:            "ipsec-main/node-b.catofes.",
			PeerZone:      "node-b.catofes.",
			LinkID:        "link-b",
			TransportID:   "ipsec-staged-r2",
			InterfaceName: "hgs22222222",
		},
	}

	if got := filterLinkViews(links, "node-b.catofes."); len(got) != 1 || got[0].PeerZone != "node-b.catofes." {
		t.Fatalf("filter by peer = %+v, want node-b only", got)
	}
	if got := filterLinkViews(links, "ipsec-staged"); len(got) != 1 || got[0].TransportID != "ipsec-staged-r2" {
		t.Fatalf("filter by runtime = %+v, want staged runtime", got)
	}
	if got := filterLinkViews(links, "missing"); len(got) != 0 {
		t.Fatalf("filter missing = %+v, want no links", got)
	}
}

func TestRotateSAMatchesCurrentAndStagedRuntime(t *testing.T) {
	link := inspect.LinkView{
		ID:          "ipsec-main/node-a.catofes.",
		PathKey:     "family:ipv4",
		TransportID: "ipsec-current",
		XFRMIfID:    1001,
		Rotation: inspect.LinkRotation{
			StagedIKEName:  "ipsec-current-r2",
			StagedXFRMIfID: 2002,
		},
	}

	if !rotateSAMatchesLink(link, linkSAState{Name: "ipsec-current", XFRMIfID: 1001}) {
		t.Fatalf("current SA did not match link")
	}
	if !rotateSAMatchesLink(link, linkSAState{Name: "ipsec-current-r2", XFRMIfID: 2002}) {
		t.Fatalf("staged SA did not match link")
	}
	if rotateSAMatchesLink(link, linkSAState{Name: "ipsec-current", XFRMIfID: 1001, RemoteEndpoint: "[2001:db8::20]:4500"}) {
		t.Fatalf("wrong-family SA matched link")
	}
	if rotateSAMatchesLink(link, linkSAState{Name: "ipsec-other", XFRMIfID: 3003}) {
		t.Fatalf("unrelated SA matched link")
	}
}
