package gossip

import (
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/Catofes/higgs/pkg/core/zone"
)

func TestLocalEndpointsToRecordWithPolicyKeepsOldEndpointDuringGrace(t *testing.T) {
	base := time.Unix(1000, 0)
	previous := LocalEndpointsToRecordWithPolicy([]LocalEndpoint{
		{IP: net.ParseIP("203.0.113.10"), Port: 33434, Scope: "global", Priority: 100, Source: SourceAdvertise},
	}, nil, base, time.Hour, 10*time.Minute)

	current := []LocalEndpoint{
		{IP: net.ParseIP("203.0.113.20"), Port: 33434, Scope: "global", Priority: 100, Source: SourceAdvertise},
	}
	record := LocalEndpointsToRecordWithPolicy(current, previous, base.Add(5*time.Minute), time.Hour, 10*time.Minute)

	if len(record.Endpoints) != 2 {
		t.Fatalf("endpoints = %d, want 2", len(record.Endpoints))
	}
	if record.Endpoints[0].Address != "203.0.113.20" {
		t.Fatalf("first endpoint = %s, want new address", record.Endpoints[0].Address)
	}
	if record.Endpoints[1].Address != "203.0.113.10" {
		t.Fatalf("second endpoint = %s, want old address", record.Endpoints[1].Address)
	}
	if record.Endpoints[1].LastObserved != base.Unix() {
		t.Fatalf("old LastObserved = %d, want %d", record.Endpoints[1].LastObserved, base.Unix())
	}
}

func TestLocalEndpointsToRecordWithPolicyDropsOldEndpointAfterGrace(t *testing.T) {
	base := time.Unix(1000, 0)
	previous := LocalEndpointsToRecordWithPolicy([]LocalEndpoint{
		{IP: net.ParseIP("203.0.113.10"), Port: 33434, Scope: "global", Priority: 100, Source: SourceAdvertise},
	}, nil, base, time.Hour, 10*time.Minute)

	record := LocalEndpointsToRecordWithPolicy([]LocalEndpoint{
		{IP: net.ParseIP("203.0.113.20"), Port: 33434, Scope: "global", Priority: 100, Source: SourceAdvertise},
	}, previous, base.Add(11*time.Minute), time.Hour, 10*time.Minute)

	if len(record.Endpoints) != 1 {
		t.Fatalf("endpoints = %d, want 1", len(record.Endpoints))
	}
	if record.Endpoints[0].Address != "203.0.113.20" {
		t.Fatalf("endpoint = %s, want new address", record.Endpoints[0].Address)
	}
}

func TestExtractPeerEndpointsAtFiltersExpiredEndpoints(t *testing.T) {
	base := time.Unix(1000, 0)
	record := EndpointRecord{
		TTL:          int64((10 * time.Minute) / time.Second),
		GraceSeconds: int64((5 * time.Minute) / time.Second),
		UpdatedAt:    base.Unix(),
		Endpoints: []EndpointEntry{
			{Address: "203.0.113.10", Port: 33434, Protocol: "udp", Priority: 100, LastObserved: base.Unix()},
			{Address: "203.0.113.20", Port: 33434, Protocol: "udp", Priority: 90, LastObserved: base.Add(-20 * time.Minute).Unix()},
		},
	}
	value, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	ns := zone.NewNetworkState()
	ns.Zones["node-a.example."] = &zone.ZoneState{
		Path: "node-a.example.",
		Records: map[string]*zone.Record{
			EndpointRecordKeyUDP: {
				Zone:      "node-a.example.",
				Key:       EndpointRecordKeyUDP,
				Value:     value,
				Timestamp: base.Unix(),
			},
		},
	}

	endpoints := ExtractPeerEndpointsAt(ns, base.Add(12*time.Minute))
	entries := endpoints["node-a.example."]
	if len(entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(entries))
	}
	if entries[0].Address != "203.0.113.10" {
		t.Fatalf("entry = %s, want unexpired address", entries[0].Address)
	}

	endpoints = ExtractPeerEndpointsAt(ns, base.Add(16*time.Minute))
	if len(endpoints["node-a.example."]) != 0 {
		t.Fatalf("expired endpoint still returned: %#v", endpoints["node-a.example."])
	}
}
