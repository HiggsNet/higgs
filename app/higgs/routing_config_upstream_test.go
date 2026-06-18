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
      enabled: true
      interface: hgs-upstream0
      create_veth: true
      peer_interface: hgs-upstream1
      peer_netns: ""
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
	if inst.Upstream.Interface != "hgs-upstream0" {
		t.Errorf("interface = %q, want hgs-upstream0", inst.Upstream.Interface)
	}
	if !inst.Upstream.CreateVeth {
		t.Error("create_veth not set")
	}
	if inst.Upstream.PeerInterface != "hgs-upstream1" {
		t.Errorf("peer_interface = %q, want hgs-upstream1", inst.Upstream.PeerInterface)
	}
	if inst.Upstream.PeerNetns != "" {
		t.Errorf("peer_netns = %q, want empty", inst.Upstream.PeerNetns)
	}
	if inst.Upstream.IPv4LL != "169.254.0.1/30" {
		t.Errorf("ipv4_ll = %q, want 169.254.0.1/30", inst.Upstream.IPv4LL)
	}
	if inst.Upstream.IPv6LL != "fe80::1/64" {
		t.Errorf("ipv6_ll = %q, want fe80::1/64", inst.Upstream.IPv6LL)
	}
}

func TestParseUpstreamConfigDisabled(t *testing.T) {
	yamlInput := `
instances:
  - id: main
    netns: h2
    upstream:
      enabled: false
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
    upstream:
      enabled: true
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
	if inst.Upstream.Interface != "hgs-upstream0" {
		t.Errorf("default interface = %q, want hgs-upstream0", inst.Upstream.Interface)
	}
	if inst.Upstream.PeerInterface != "hgs-upstream1" {
		t.Errorf("default peer_interface = %q, want hgs-upstream1", inst.Upstream.PeerInterface)
	}
}

func TestParseUpstreamConfigInvalidIPv4(t *testing.T) {
	yamlInput := `
instances:
  - id: main
    netns: h2
    upstream:
      enabled: true
      ipv4_ll: "not-a-cidr"
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
		t.Fatal("expected error for invalid ipv4_ll")
	}
}

func TestParseUpstreamConfigInvalidIPv6(t *testing.T) {
	yamlInput := `
instances:
  - id: main
    netns: h2
    upstream:
      enabled: true
      ipv6_ll: "not-a-cidr"
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
		t.Fatal("expected error for invalid ipv6_ll")
	}
}
