package http

import (
	"encoding/json"
	"testing"

	"github.com/Catofes/higgs/internal/inspect"
	higgsstate "github.com/Catofes/higgs/internal/state"
)

func TestPeersResponsePreservesObserverSchema(t *testing.T) {
	got := PeersResponse{Peers: []PeerJSON{{
		PeerID:         "node-b.catofes.",
		Source:         "bootstrap",
		ConfiguredAddr: "192.0.2.10:33434",
		PeerRuntimeJSON: PeerRuntimeJSONFromState(higgsstate.PeerRuntimeState{
			LastSyncUnix:          900,
			LastAttemptUnix:       850,
			BackoffUntilUnix:      950,
			LastRelayUnix:         920,
			FailureCount:          2,
			LastUpdateSource:      "announce",
			LastRelaySuppression:  "relay_fanout_limited",
			LastRelaySuppressedAt: 910,
			ObservedAddr:          "198.51.100.9:33434",
			ObservedSource:        "verified_packet",
			DatagramStats: &higgsstate.PeerDatagramStats{
				ChunkFallbacks: 2,
			},
		}),
		Endpoints: []inspect.PeerEndpointView{{
			Addr:     "192.0.2.10:33434",
			Source:   "bootstrap",
			Selected: true,
		}},
	}}}
	data, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	peers := decoded["peers"].([]any)
	peer := peers[0].(map[string]any)
	if peer["peer_id"] != "node-b.catofes." || peer["configured_addr"] != "192.0.2.10:33434" {
		t.Fatalf("peer fields missing: %#v", peer)
	}
	if peer["endpoints"] == nil || peer["datagram_stats"] == nil {
		t.Fatalf("endpoint/diagnostic fields missing: %#v", peer)
	}
}

func TestPeersResponseKeepsZeroValueSchemaFields(t *testing.T) {
	got := PeersResponse{Peers: []PeerJSON{{
		PeerID:          "node-b.catofes.",
		PeerRuntimeJSON: PeerRuntimeJSONFromState(higgsstate.PeerRuntimeState{}),
	}}}
	data, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	peers := decoded["peers"].([]any)
	peer := peers[0].(map[string]any)
	for _, field := range []string{"last_sync_unix", "last_attempt_unix", "backoff_until_unix", "failure_count"} {
		if _, ok := peer[field]; !ok {
			t.Fatalf("zero-value schema field %q missing: %#v", field, peer)
		}
	}
}
