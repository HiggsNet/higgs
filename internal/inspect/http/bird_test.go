package http

import (
	"encoding/json"
	"testing"
)

func TestBirdResponsePreservesObserverSchema(t *testing.T) {
	got := BirdResponse{
		Instances:        map[string]any{"phx-main": map[string]any{"state": "running"}},
		LastRoutingError: "bird failed",
	}
	data, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if decoded["instances"] == nil || decoded["last_routing_error"] != "bird failed" {
		t.Fatalf("bird response fields missing: %#v", decoded)
	}
}
