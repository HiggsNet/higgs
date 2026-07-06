package inspect

import (
	"strings"
	"testing"
	"time"
)

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

func TestBuildEndpointDebugSortsDiscoveredPeersAndCopiesInputs(t *testing.T) {
	input := EndpointDebugInput{
		ReflectorError:      "timeout",
		HasPublicReflectors: true,
		LocalCandidates: []EndpointCandidateView{
			{
				Address:  "203.0.113.30",
				Port:     33434,
				Scope:    "global",
				Priority: 50,
				Source:   "reflector",
			},
			{
				Address:  "203.0.113.10",
				Port:     33434,
				Scope:    "global",
				Priority: 100,
				Source:   "advertise",
			},
			{
				Address:  "203.0.113.20",
				Port:     33434,
				Scope:    "site",
				Priority: 100,
				Source:   "interface",
			},
		},
		Discovered: map[string][]PeerSignedEndpoint{
			"node-c.catofes.": {{Address: "198.51.100.30", Port: 33434}},
			"node-b.catofes.": {
				{Address: "198.51.100.10", Port: 33434, Priority: 50, LastObserved: 300},
				{Address: "198.51.100.20", Port: 33434, Priority: 100, LastObserved: 100},
				{Address: "198.51.100.30", Port: 33434, Priority: 100, LastObserved: 200},
			},
		},
	}
	got := BuildEndpointDebug(input)
	if got.ReflectorError != "timeout" {
		t.Fatalf("ReflectorError = %q, want timeout", got.ReflectorError)
	}
	if len(got.LocalCandidates) != 3 {
		t.Fatalf("LocalCandidates = %+v", got.LocalCandidates)
	}
	if got.LocalCandidates[0].Address != "203.0.113.10" || got.LocalCandidates[1].Address != "203.0.113.20" || got.LocalCandidates[2].Address != "203.0.113.30" {
		t.Fatalf("LocalCandidates not sorted by priority/source: %+v", got.LocalCandidates)
	}
	if len(got.DiscoveredPeers) != 2 {
		t.Fatalf("DiscoveredPeers len = %d, want 2: %+v", len(got.DiscoveredPeers), got.DiscoveredPeers)
	}
	if got.DiscoveredPeers[0].PeerID != "node-b.catofes." || got.DiscoveredPeers[1].PeerID != "node-c.catofes." {
		t.Fatalf("DiscoveredPeers not sorted: %+v", got.DiscoveredPeers)
	}
	endpoints := got.DiscoveredPeers[0].Endpoints
	if len(endpoints) != 3 {
		t.Fatalf("node-b endpoints len = %d, want 3: %+v", len(endpoints), endpoints)
	}
	if endpoints[0].Address != "198.51.100.30" || endpoints[1].Address != "198.51.100.20" || endpoints[2].Address != "198.51.100.10" {
		t.Fatalf("node-b endpoints not sorted by priority/last_observed: %+v", endpoints)
	}

	input.LocalCandidates[0].Address = "mutated"
	input.Discovered["node-b.catofes."][0].Address = "mutated"
	if got.LocalCandidates[0].Address == "mutated" || got.DiscoveredPeers[0].Endpoints[0].Address == "mutated" {
		t.Fatalf("BuildEndpointDebug did not copy inputs: %+v", got)
	}
}

func TestBuildEndpointDebugSuppressesPrivateReflectorErrors(t *testing.T) {
	got := BuildEndpointDebug(EndpointDebugInput{
		ReflectorError:      "timeout",
		HasPublicReflectors: false,
	})
	if got.ReflectorError != "" {
		t.Fatalf("ReflectorError = %q, want empty", got.ReflectorError)
	}
}

func TestBuildPeerDebugFormatsRuntimeDiagnostics(t *testing.T) {
	now := time.Unix(1700000000, 0)
	got := BuildPeerDebug(PeerDebugInput{
		PeerID:                "node-b.catofes.",
		Source:                "bootstrap",
		ConfiguredAddr:        "127.0.0.1:9999",
		ResolvedAddr:          "127.0.0.1:2000",
		LastSyncUnix:          now.Add(-time.Minute).Unix(),
		BackoffUntilUnix:      now.Add(30 * time.Second).Unix(),
		DiscoveredAddr:        "127.0.0.1:2000",
		ObservedAddr:          "127.0.0.1:3000",
		ObservedUntilUnix:     now.Add(time.Hour).Unix(),
		ObservedLastSeenUnix:  now.Unix(),
		ObservedLastSyncUnix:  now.Add(-time.Minute).Unix(),
		ObservedFailureCount:  2,
		ObservedSource:        "PING",
		LastUpdateSource:      "node-c.catofes.",
		LastRelayUnix:         now.Add(-2 * time.Minute).Unix(),
		LastRelaySuppression:  "relay_throttled",
		LastRelaySuppressedAt: now.Add(-time.Minute).Unix(),
		SyncFlow: PeerSyncFlowView{
			ActivePullState: "object_pulling",
		},
		DatagramStats: PeerDatagramStatsView{
			TooLargeDropped: 2,
		},
		ObjectPullStats: PeerObjectPullStatsView{
			Attempts: 3,
		},
		Now: now,
	})

	if got.PeerID != "node-b.catofes." || got.Source != "bootstrap" || got.ResolvedAddr != "127.0.0.1:2000" {
		t.Fatalf("identity fields = %+v", got)
	}
	if got.Status != "backoff" || got.Backoff != "30s" || got.NextRetry == "-" {
		t.Fatalf("retry fields = status=%q backoff=%q next=%q", got.Status, got.Backoff, got.NextRetry)
	}
	if !strings.Contains(got.ObservedStatus, "active until=") || !strings.Contains(got.ObservedStatus, "failures=2 source=PING") {
		t.Fatalf("observed status = %q", got.ObservedStatus)
	}
	if !strings.Contains(got.RelaySuppression, "relay_throttled at=") {
		t.Fatalf("relay suppression = %q", got.RelaySuppression)
	}
	if got.SyncFlow.ActivePullState != "object_pulling" || got.DatagramStats.TooLargeDropped != 2 || got.ObjectPullStats.Attempts != 3 {
		t.Fatalf("nested diagnostics = %+v", got)
	}
}
