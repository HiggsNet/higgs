package main

import (
	"testing"
)

func TestParseConfigYAMLEndpointDiscovery(t *testing.T) {
	config := defaultAppConfig()
	input := `
gossip:
  endpoint_discovery: loopback_only
  endpoint_source_order:
    - bootstrap
    - advertise
`
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	normalizeAppConfig(config)
	if config.EndpointDiscovery != "loopback_only" {
		t.Fatalf("EndpointDiscovery = %q, want loopback_only", config.EndpointDiscovery)
	}
	if len(config.EndpointSourceOrder) != 2 || config.EndpointSourceOrder[0] != "bootstrap" || config.EndpointSourceOrder[1] != "advertise" {
		t.Fatalf("EndpointSourceOrder = %v, want [bootstrap advertise]", config.EndpointSourceOrder)
	}
}

func TestParseConfigYAMLInvalidEndpointSourceOrderIgnored(t *testing.T) {
	config := defaultAppConfig()
	input := `
gossip:
  endpoint_source_order:
    - bootstrap
    - unknown
    - advertise
    - bootstrap
`
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	normalizeAppConfig(config)
	if len(config.EndpointSourceOrder) != 2 || config.EndpointSourceOrder[0] != "bootstrap" || config.EndpointSourceOrder[1] != "advertise" {
		t.Fatalf("EndpointSourceOrder = %v, want [bootstrap advertise]", config.EndpointSourceOrder)
	}
}
