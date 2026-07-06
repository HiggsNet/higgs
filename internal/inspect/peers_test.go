package inspect

import "testing"

func TestBuildPeerEndpointsMergesAndSortsSources(t *testing.T) {
	got := BuildPeerEndpoints(PeerEndpointInput{
		BootstrapAddr:  "192.0.2.10:33434",
		SelectedAddr:   "203.0.113.20:33434",
		ObservedAddr:   "198.51.100.9:33434",
		ObservedSource: "verified_packet",
		Signed: []PeerSignedEndpoint{{
			Address:      "203.0.113.20",
			Port:         33434,
			Scope:        "global",
			Source:       "advertise",
			Priority:     100,
			LastObserved: 900,
		}},
		Grace: []PeerGraceEndpoint{{Addr: "198.51.100.8:33434"}},
	})
	if len(got) != 5 {
		t.Fatalf("len = %d, want 5: %+v", len(got), got)
	}
	if got[0].Addr != "203.0.113.20:33434" || !got[0].Selected {
		t.Fatalf("first endpoint = %+v, want selected signed endpoint", got[0])
	}
	var sawBootstrap, sawObserved, sawGrace bool
	for _, ep := range got {
		switch {
		case ep.Addr == "192.0.2.10:33434" && ep.Source == "bootstrap":
			sawBootstrap = true
		case ep.Addr == "198.51.100.9:33434" && ep.Source == "verified_packet":
			sawObserved = true
		case ep.Addr == "198.51.100.8:33434" && ep.Source == "observed_grace":
			sawGrace = true
		}
	}
	if !sawBootstrap || !sawObserved || !sawGrace {
		t.Fatalf("missing endpoint sources: %+v", got)
	}
}

func TestBuildPeerEndpointsDeduplicatesByAddrAndSource(t *testing.T) {
	got := BuildPeerEndpoints(PeerEndpointInput{
		SelectedAddr: "203.0.113.20:33434",
		Signed: []PeerSignedEndpoint{
			{Address: "203.0.113.20", Port: 33434, Source: "advertise"},
			{Address: "203.0.113.20", Port: 33434, Source: "advertise"},
		},
	})
	var advertise int
	for _, ep := range got {
		if ep.Source == "advertise" {
			advertise++
			if !ep.Selected {
				t.Fatalf("deduped advertise endpoint lost selected flag: %+v", ep)
			}
		}
	}
	if advertise != 1 {
		t.Fatalf("advertise endpoints = %d, want 1: %+v", advertise, got)
	}
}
