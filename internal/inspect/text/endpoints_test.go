package text

import (
	"strings"
	"testing"

	"github.com/HiggsNet/photon/internal/inspect"
)

func TestWriteEndpointsDebug(t *testing.T) {
	view := inspect.EndpointDebugView{
		ManagedPeerID: "node-b.catofes.",
		Peers: []inspect.EndpointPeerView{{
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
		"published_peers: 1",
		"peer node-b.catofes. endpoints=1 local=true",
		"endpoint addr=198.51.100.20 port=33434 scope=global priority=100 protocol=udp source=signed last_observed=2023-11-14T22:13:20Z",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("output missing %q:\n%s", want, output)
		}
	}
}
