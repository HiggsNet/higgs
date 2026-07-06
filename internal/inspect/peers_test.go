package inspect

import "testing"

func TestBuildPeerIDsMergesFiltersAndSorts(t *testing.T) {
	got := BuildPeerIDs(PeerSetInput{
		RuntimeIDs:   []string{"node-c.catofes.", "node-a.catofes.", "self.catofes."},
		BootstrapIDs: []string{"node-b.catofes.", "node-a.catofes."},
		SignedIDs:    []string{"node-d.catofes.", "self.catofes."},
		LocalIDs:     []string{"self.catofes."},
	})
	want := []string{"node-a.catofes.", "node-b.catofes.", "node-c.catofes.", "node-d.catofes."}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got[%d] = %q, want %q; all=%+v", i, got[i], want[i], got)
		}
	}
}

func TestPeerKnownExcludesLocalPeer(t *testing.T) {
	input := PeerSetInput{
		RuntimeIDs:   []string{"node-a.catofes.", "self.catofes."},
		BootstrapIDs: []string{"node-b.catofes."},
		SignedIDs:    []string{"node-c.catofes."},
		LocalIDs:     []string{"self.catofes."},
	}
	for _, peerID := range []string{"node-a.catofes.", "node-b.catofes.", "node-c.catofes."} {
		if !PeerKnown(input, peerID) {
			t.Fatalf("PeerKnown(%s) = false, want true", peerID)
		}
	}
	if PeerKnown(input, "self.catofes.") {
		t.Fatal("local peer should not be known as observable remote peer")
	}
	if PeerKnown(input, "unknown.catofes.") {
		t.Fatal("unknown peer should not be known")
	}
}

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
