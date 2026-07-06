package http

import (
	"encoding/json"
	"testing"
)

func TestHealthResponsePreservesObserverSchema(t *testing.T) {
	got := HealthResponse{
		Datasource: map[string]any{"kind": "local_spool"},
		Links: []HealthContextItem{{
			Health:          map[string]any{"instance_id": "link-1", "state": "unknown"},
			PeerZone:        "node-b.catofes.",
			GroupID:         "blue",
			InterfaceName:   "hgs0",
			Endpoint:        "198.51.100.10:4500",
			ActualState:     "up",
			LocalTunnelAddr: "fd00::1%hgs0",
			PeerTunnelAddr:  "fd00::2%hgs0",
		}},
	}
	data, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	links := decoded["links"].([]any)
	item := links[0].(map[string]any)
	if item["peer_zone"] != "node-b.catofes." || item["health"] == nil {
		t.Fatalf("health context fields missing: %#v", item)
	}
}

func TestHealthSeriesResponsePreservesObserverSchema(t *testing.T) {
	got := HealthSeriesResponse{
		Datasource: map[string]any{"kind": "local_spool"},
		LinkID:     "link-1",
		Series:     map[string]any{"metric": "rtt"},
	}
	data, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if decoded["link_id"] != "link-1" || decoded["series"] == nil {
		t.Fatalf("series response fields missing: %#v", decoded)
	}
}
