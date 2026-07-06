package text

import (
	"strings"
	"testing"

	"github.com/Catofes/higgs/internal/inspect"
)

func TestWriteEndpointsDebug(t *testing.T) {
	view := inspect.EndpointDebugView{
		ReflectorError: "timeout",
		LocalCandidates: []inspect.EndpointCandidateView{{
			Address:  "203.0.113.10",
			Port:     33434,
			Scope:    "global",
			Priority: 100,
			Source:   "advertise",
		}},
		DiscoveredPeers: []inspect.DiscoveredPeerEndpointsView{{
			PeerID: "node-b.catofes.",
			Endpoints: []inspect.PeerSignedEndpoint{{
				Address:      "198.51.100.20",
				Port:         33434,
				Scope:        "global",
				Priority:     100,
				Protocol:     "udp",
				Source:       "signed",
				LastObserved: 1700000000,
			}},
		}},
	}
	var buf strings.Builder
	if err := WriteEndpointsDebug(&buf, view); err != nil {
		t.Fatalf("WriteEndpointsDebug: %v", err)
	}
	output := buf.String()
	for _, want := range []string{
		"reflector_error: timeout",
		"local_candidates: 1",
		"candidate addr=203.0.113.10 port=33434 scope=global priority=100 source=advertise",
		"discovered_peers: 1",
		"peer node-b.catofes. endpoints=1",
		"endpoint addr=198.51.100.20 port=33434 scope=global priority=100 protocol=udp source=signed last_observed=2023-11-14T22:13:20Z",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("output missing %q:\n%s", want, output)
		}
	}
}
