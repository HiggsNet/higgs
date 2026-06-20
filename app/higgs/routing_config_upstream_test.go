package main

import (
	"testing"

	"github.com/Catofes/higgs/pkg/transport/ipsec"
	"gopkg.in/yaml.v3"
)

func TestParseUpstreamConfig(t *testing.T) {
	yamlInput := `
instances:
  - id: main
    netns: h2
    upstream:
      create_veth: true
      upstream_interface: hgs-2host
      downstream_interface: hgs-2higgs
      peer_netns: ""
      upstream_ipv4_ll: "169.254.0.1/30"
      downstream_ipv4_ll: "169.254.0.2/30"
      upstream_ipv6_ll: "fe80::1/64"
      downstream_ipv6_ll: "fe80::2/64"
`
	var yamlCfg routingInstancesYAML
	if err := yaml.Unmarshal([]byte(yamlInput), &yamlCfg); err != nil {
		t.Fatalf("yaml unmarshal: %v", err)
	}

	netnsCfg := netnsConfig{Names: map[string]ipsec.NetNSSpec{
		"h2": {Kind: "name", Name: "h2", Create: true},
	}}
	cfg, err := parseRoutingConfigInstances(yamlCfg.Instances, netnsCfg, "/tmp")
	if err != nil {
		t.Fatalf("parseRoutingConfigInstances: %v", err)
	}
	if len(cfg.Instances) != 1 {
		t.Fatalf("expected 1 instance, got %d", len(cfg.Instances))
	}
	inst := cfg.Instances[0]
	if inst.Upstream == nil {
		t.Fatal("upstream is nil")
	}
	if !inst.Upstream.Enabled {
		t.Error("upstream not enabled")
	}
	if inst.Upstream.Interface != "hgs-2host" {
		t.Errorf("interface = %q, want hgs-2host", inst.Upstream.Interface)
	}
	if !inst.Upstream.CreateVeth {
		t.Error("create_veth not set")
	}
	if inst.Upstream.PeerInterface != "hgs-2higgs" {
		t.Errorf("peer_interface = %q, want hgs-2higgs", inst.Upstream.PeerInterface)
	}
	if inst.Upstream.PeerNetns != "" {
		t.Errorf("peer_netns = %q, want empty", inst.Upstream.PeerNetns)
	}
	if inst.Upstream.IPv4LL != "169.254.0.1/30" {
		t.Errorf("upstream ipv4_ll = %q, want 169.254.0.1/30", inst.Upstream.IPv4LL)
	}
	if inst.Upstream.DownstreamIPv4LL != "169.254.0.2/30" {
		t.Errorf("downstream ipv4_ll = %q, want 169.254.0.2/30", inst.Upstream.DownstreamIPv4LL)
	}
	if inst.Upstream.IPv6LL != "fe80::1/64" {
		t.Errorf("upstream ipv6_ll = %q, want fe80::1/64", inst.Upstream.IPv6LL)
	}
	if inst.Upstream.DownstreamIPv6LL != "fe80::2/64" {
		t.Errorf("downstream ipv6_ll = %q, want fe80::2/64", inst.Upstream.DownstreamIPv6LL)
	}
}

func TestParseUpstreamConfigLegacyFieldAliases(t *testing.T) {
	yamlInput := `
instances:
  - id: main
    netns: h2
    upstream:
      interface: hgs-2host
      peer_interface: hgs-upstream1
      ipv4_ll: "169.254.0.1/30"
      ipv6_ll: "fe80::1/64"
`
	var yamlCfg routingInstancesYAML
	if err := yaml.Unmarshal([]byte(yamlInput), &yamlCfg); err != nil {
		t.Fatalf("yaml unmarshal: %v", err)
	}

	netnsCfg := netnsConfig{Names: map[string]ipsec.NetNSSpec{
		"h2": {Kind: "name", Name: "h2", Create: true},
	}}
	cfg, err := parseRoutingConfigInstances(yamlCfg.Instances, netnsCfg, "/tmp")
	if err != nil {
		t.Fatalf("parseRoutingConfigInstances: %v", err)
	}
	inst := cfg.Instances[0]
	if inst.Upstream.Interface != "hgs-2host" || inst.Upstream.PeerInterface != "hgs-upstream1" {
		t.Fatalf("legacy interfaces = %q/%q", inst.Upstream.Interface, inst.Upstream.PeerInterface)
	}
	if inst.Upstream.IPv4LL != "169.254.0.1/30" || inst.Upstream.IPv6LL != "fe80::1/64" {
		t.Fatalf("legacy addresses = %q/%q", inst.Upstream.IPv4LL, inst.Upstream.IPv6LL)
	}
}

func TestParseUpstreamConfigRejectsConflictingAliases(t *testing.T) {
	yamlInput := `
instances:
  - id: main
    netns: h2
    upstream:
      upstream_interface: hgs-2host
      interface: hgs-other0
`
	var yamlCfg routingInstancesYAML
	if err := yaml.Unmarshal([]byte(yamlInput), &yamlCfg); err != nil {
		t.Fatalf("yaml unmarshal: %v", err)
	}

	netnsCfg := netnsConfig{Names: map[string]ipsec.NetNSSpec{
		"h2": {Kind: "name", Name: "h2", Create: true},
	}}
	if _, err := parseRoutingConfigInstances(yamlCfg.Instances, netnsCfg, "/tmp"); err == nil {
		t.Fatal("expected conflicting alias error")
	}
}

func TestParseUpstreamConfigDisabled(t *testing.T) {
	yamlInput := `
instances:
  - id: main
    netns: h2
    upstream:
      disabled: true
`
	var yamlCfg routingInstancesYAML
	if err := yaml.Unmarshal([]byte(yamlInput), &yamlCfg); err != nil {
		t.Fatalf("yaml unmarshal: %v", err)
	}

	netnsCfg := netnsConfig{Names: map[string]ipsec.NetNSSpec{
		"h2": {Kind: "name", Name: "h2", Create: true},
	}}
	cfg, err := parseRoutingConfigInstances(yamlCfg.Instances, netnsCfg, "/tmp")
	if err != nil {
		t.Fatalf("parseRoutingConfigInstances: %v", err)
	}
	inst := cfg.Instances[0]
	if inst.Upstream == nil {
		t.Fatal("upstream is nil")
	}
	if inst.Upstream.Enabled {
		t.Error("upstream should be disabled")
	}
}

func TestParseUpstreamConfigNil(t *testing.T) {
	yamlInput := `
instances:
  - id: main
    netns: h2
`
	var yamlCfg routingInstancesYAML
	if err := yaml.Unmarshal([]byte(yamlInput), &yamlCfg); err != nil {
		t.Fatalf("yaml unmarshal: %v", err)
	}

	netnsCfg := netnsConfig{Names: map[string]ipsec.NetNSSpec{
		"h2": {Kind: "name", Name: "h2", Create: true},
	}}
	cfg, err := parseRoutingConfigInstances(yamlCfg.Instances, netnsCfg, "/tmp")
	if err != nil {
		t.Fatalf("parseRoutingConfigInstances: %v", err)
	}
	inst := cfg.Instances[0]
	if inst.Upstream != nil {
		t.Errorf("upstream should be nil, got %+v", inst.Upstream)
	}
}

func TestParseUpstreamConfigDefaults(t *testing.T) {
	yamlInput := `
instances:
  - id: main
    netns: h2
    upstream: {}
`
	var yamlCfg routingInstancesYAML
	if err := yaml.Unmarshal([]byte(yamlInput), &yamlCfg); err != nil {
		t.Fatalf("yaml unmarshal: %v", err)
	}

	netnsCfg := netnsConfig{Names: map[string]ipsec.NetNSSpec{
		"h2": {Kind: "name", Name: "h2", Create: true},
	}}
	cfg, err := parseRoutingConfigInstances(yamlCfg.Instances, netnsCfg, "/tmp")
	if err != nil {
		t.Fatalf("parseRoutingConfigInstances: %v", err)
	}
	inst := cfg.Instances[0]
	if inst.Upstream == nil || !inst.Upstream.Enabled {
		t.Fatal("upstream should be enabled")
	}
	if inst.Upstream.Interface != "hgs-2host" {
		t.Errorf("default interface = %q, want hgs-2host", inst.Upstream.Interface)
	}
	if inst.Upstream.PeerInterface != "hgs-2higgs" {
		t.Errorf("default peer_interface = %q, want hgs-2higgs", inst.Upstream.PeerInterface)
	}
}

func TestParseUpstreamConfigInvalidIPv4(t *testing.T) {
	yamlInput := `
instances:
  - id: main
    netns: h2
    upstream:
      upstream_ipv4_ll: "not-a-cidr"
`
	var yamlCfg routingInstancesYAML
	if err := yaml.Unmarshal([]byte(yamlInput), &yamlCfg); err != nil {
		t.Fatalf("yaml unmarshal: %v", err)
	}

	netnsCfg := netnsConfig{Names: map[string]ipsec.NetNSSpec{
		"h2": {Kind: "name", Name: "h2", Create: true},
	}}
	_, err := parseRoutingConfigInstances(yamlCfg.Instances, netnsCfg, "/tmp")
	if err == nil {
		t.Fatal("expected error for invalid upstream_ipv4_ll")
	}
}

func TestParseUpstreamConfigInvalidIPv6(t *testing.T) {
	yamlInput := `
instances:
  - id: main
    netns: h2
    upstream:
      downstream_ipv6_ll: "not-a-cidr"
`
	var yamlCfg routingInstancesYAML
	if err := yaml.Unmarshal([]byte(yamlInput), &yamlCfg); err != nil {
		t.Fatalf("yaml unmarshal: %v", err)
	}

	netnsCfg := netnsConfig{Names: map[string]ipsec.NetNSSpec{
		"h2": {Kind: "name", Name: "h2", Create: true},
	}}
	_, err := parseRoutingConfigInstances(yamlCfg.Instances, netnsCfg, "/tmp")
	if err == nil {
		t.Fatal("expected error for invalid downstream_ipv6_ll")
	}
}
