package gossip

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
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

func TestQueryPublicIPParsesTextAndJSONReflectors(t *testing.T) {
	textClient := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return httpResponse(http.StatusOK, "203.0.113.44\n"), nil
	})}

	ip, err := queryPublicIPWithClient([]string{"https://reflector.example/text"}, textClient)
	if err != nil {
		t.Fatalf("QueryPublicIP(text): %v", err)
	}
	if ip.String() != "203.0.113.44" {
		t.Fatalf("text ip = %s, want 203.0.113.44", ip)
	}

	jsonClient := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return httpResponse(http.StatusOK, `{"origin":"2001:db8::12"}`), nil
	})}

	ip, err = queryPublicIPWithClient([]string{"https://reflector.example/json"}, jsonClient)
	if err != nil {
		t.Fatalf("QueryPublicIP(json): %v", err)
	}
	if ip.String() != "2001:db8::12" {
		t.Fatalf("json ip = %s, want 2001:db8::12", ip)
	}
}

func TestParseReflectorIPHandlesDDNSGoStyleResponses(t *testing.T) {
	tests := map[string]string{
		"当前 IP：203.0.113.45  来自于：中国":               "203.0.113.45",
		"Current IP Address: 203.0.113.46":         "203.0.113.46",
		"<html><body>203.0.113.47</body></html>":   "203.0.113.47",
		`{"data":{"ip":"2001:db8::45"}}`:           "2001:db8::45",
		`callback({"public_ip":"2001:db8::46"});`:  "2001:db8::46",
		"Your IPv6 address is 2001:db8:0:1::abcd.": "2001:db8:0:1::abcd",
	}
	for body, want := range tests {
		got := parseReflectorIP([]byte(body))
		if got == nil || got.String() != want {
			t.Fatalf("parseReflectorIP(%q) = %v, want %s", body, got, want)
		}
	}
}

func TestQueryPublicIPFallsBackAcrossReflectors(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Host == "bad.example" {
			return httpResponse(http.StatusBadGateway, "nope"), nil
		}
		return httpResponse(http.StatusOK, `{"ip":"198.51.100.7"}`), nil
	})}

	ip, err := queryPublicIPWithClient([]string{"https://bad.example", "https://good.example"}, client)
	if err != nil {
		t.Fatalf("QueryPublicIP(fallback): %v", err)
	}
	if ip.String() != "198.51.100.7" {
		t.Fatalf("fallback ip = %s, want 198.51.100.7", ip)
	}
}

func TestQueryPublicIPsReturnsOneAddressPerFamily(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch req.URL.Host {
		case "v4.example":
			return httpResponse(http.StatusOK, "198.51.100.7"), nil
		case "v6.example":
			return httpResponse(http.StatusOK, "2001:db8::7"), nil
		default:
			return httpResponse(http.StatusBadGateway, "nope"), nil
		}
	})}

	ips, err := queryPublicIPsWithClient([]string{"https://bad.example", "https://v4.example", "https://v6.example"}, client)
	if err != nil {
		t.Fatalf("QueryPublicIPs: %v", err)
	}
	if len(ips) != 2 {
		t.Fatalf("ips = %v, want 2 addresses", ips)
	}
	got := make(map[string]bool)
	for _, ip := range ips {
		got[ip.String()] = true
	}
	if !got["198.51.100.7"] || !got["2001:db8::7"] {
		t.Fatalf("ips = %v, want one v4 and one v6", ips)
	}
}

func TestResolvePublicIPReflectorsExpandsAutoPreset(t *testing.T) {
	reflectors := ResolvePublicIPReflectors([]string{"https://custom.example/ip", "auto", "https://custom.example/ip", "none"})
	if len(reflectors) != len(DefaultPublicIPReflectors())+1 {
		t.Fatalf("reflectors = %d, want custom plus defaults", len(reflectors))
	}
	if reflectors[0] != "https://custom.example/ip" {
		t.Fatalf("first reflector = %q, want custom preserved", reflectors[0])
	}
}

func TestCollectLocalEndpointsWithReflectorsAddsReflectorCandidate(t *testing.T) {
	oldQuery := queryPublicIPForCollect
	queryPublicIPForCollect = func(reflectors []string, timeout time.Duration) (net.IP, error) {
		return net.ParseIP("198.51.100.9"), nil
	}
	defer func() { queryPublicIPForCollect = oldQuery }()

	endpoints, err := CollectLocalEndpointsWithReflectors(33434, nil, []string{"https://reflector.example"}, time.Second, false)
	if err != nil {
		t.Fatalf("CollectLocalEndpointsWithReflectors: %v", err)
	}
	var found bool
	for _, ep := range endpoints {
		if ep.Source == SourceReflector && ep.IP.String() == "198.51.100.9" && ep.Port == 33434 {
			found = true
		}
	}
	if !found {
		t.Fatalf("reflector endpoint not found in %#v", endpoints)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func httpResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Body:       io.NopCloser(bytes.NewBufferString(body)),
		Header:     make(http.Header),
	}
}
