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
    netns: higgstesth2
    upstream:
      create_veth: true
      mesh:
        interface: hgs-2host
        ipv4_ll: "169.254.0.1/30"
        ipv6_ll: "fe80::1/64"
      external:
        interface: hgs-2higgs
        netns: ""
        ipv4_ll: "169.254.0.2/30"
        ipv6_ll: "fe80::2/64"
`
	var yamlCfg routingInstancesYAML
	if err := yaml.Unmarshal([]byte(yamlInput), &yamlCfg); err != nil {
		t.Fatalf("yaml unmarshal: %v", err)
	}

	netnsCfg := netnsConfig{Names: map[string]ipsec.NetNSSpec{
		"higgstesth2": {Kind: "name", Name: "higgstesth2", Create: true},
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
	if inst.Upstream.Mode != upstreamModeStatic {
		t.Errorf("mode = %q, want static", inst.Upstream.Mode)
	}
	if inst.Upstream.MeshInterface != "hgs-2host" {
		t.Errorf("mesh interface = %q, want hgs-2host", inst.Upstream.MeshInterface)
	}
	if !inst.Upstream.CreateVeth {
		t.Error("create_veth not set")
	}
	if inst.Upstream.ExternalInterface != "hgs-2higgs" {
		t.Errorf("external interface = %q, want hgs-2higgs", inst.Upstream.ExternalInterface)
	}
	if inst.Upstream.ExternalNetns != "" {
		t.Errorf("external netns = %q, want empty", inst.Upstream.ExternalNetns)
	}
	if inst.Upstream.MeshIPv4LL != "169.254.0.1/30" {
		t.Errorf("mesh ipv4_ll = %q, want 169.254.0.1/30", inst.Upstream.MeshIPv4LL)
	}
	if inst.Upstream.ExternalIPv4LL != "169.254.0.2/30" {
		t.Errorf("external ipv4_ll = %q, want 169.254.0.2/30", inst.Upstream.ExternalIPv4LL)
	}
	if inst.Upstream.MeshIPv6LL != "fe80::1/64" {
		t.Errorf("mesh ipv6_ll = %q, want fe80::1/64", inst.Upstream.MeshIPv6LL)
	}
	if inst.Upstream.ExternalIPv6LL != "fe80::2/64" {
		t.Errorf("external ipv6_ll = %q, want fe80::2/64", inst.Upstream.ExternalIPv6LL)
	}
}

func TestParseUpstreamConfigExternalMode(t *testing.T) {
	yamlInput := `
instances:
  - id: main
    netns: higgstesth2
    upstream:
      mode: external
`
	var yamlCfg routingInstancesYAML
	if err := yaml.Unmarshal([]byte(yamlInput), &yamlCfg); err != nil {
		t.Fatalf("yaml unmarshal: %v", err)
	}

	netnsCfg := netnsConfig{Names: map[string]ipsec.NetNSSpec{
		"higgstesth2": {Kind: "name", Name: "higgstesth2", Create: true},
	}}
	cfg, err := parseRoutingConfigInstances(yamlCfg.Instances, netnsCfg, "/tmp")
	if err != nil {
		t.Fatalf("parseRoutingConfigInstances: %v", err)
	}
	inst := cfg.Instances[0]
	if inst.Upstream == nil || inst.Upstream.Mode != upstreamModeExternal {
		t.Fatalf("upstream mode = %#v, want external", inst.Upstream)
	}
}

func TestParseUpstreamConfigRejectsInvalidMode(t *testing.T) {
	yamlInput := `
instances:
  - id: main
    netns: higgstesth2
    upstream:
      mode: dynamic
`
	var yamlCfg routingInstancesYAML
	if err := yaml.Unmarshal([]byte(yamlInput), &yamlCfg); err != nil {
		t.Fatalf("yaml unmarshal: %v", err)
	}

	netnsCfg := netnsConfig{Names: map[string]ipsec.NetNSSpec{
		"higgstesth2": {Kind: "name", Name: "higgstesth2", Create: true},
	}}
	if _, err := parseRoutingConfigInstances(yamlCfg.Instances, netnsCfg, "/tmp"); err == nil {
		t.Fatal("expected invalid upstream mode error")
	}
}

func TestParseUpstreamConfigDisabled(t *testing.T) {
	yamlInput := `
instances:
  - id: main
    netns: higgstesth2
    upstream:
      disabled: true
`
	var yamlCfg routingInstancesYAML
	if err := yaml.Unmarshal([]byte(yamlInput), &yamlCfg); err != nil {
		t.Fatalf("yaml unmarshal: %v", err)
	}

	netnsCfg := netnsConfig{Names: map[string]ipsec.NetNSSpec{
		"higgstesth2": {Kind: "name", Name: "higgstesth2", Create: true},
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
    netns: higgstesth2
`
	var yamlCfg routingInstancesYAML
	if err := yaml.Unmarshal([]byte(yamlInput), &yamlCfg); err != nil {
		t.Fatalf("yaml unmarshal: %v", err)
	}

	netnsCfg := netnsConfig{Names: map[string]ipsec.NetNSSpec{
		"higgstesth2": {Kind: "name", Name: "higgstesth2", Create: true},
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
    netns: higgstesth2
    upstream: {}
`
	var yamlCfg routingInstancesYAML
	if err := yaml.Unmarshal([]byte(yamlInput), &yamlCfg); err != nil {
		t.Fatalf("yaml unmarshal: %v", err)
	}

	netnsCfg := netnsConfig{Names: map[string]ipsec.NetNSSpec{
		"higgstesth2": {Kind: "name", Name: "higgstesth2", Create: true},
	}}
	cfg, err := parseRoutingConfigInstances(yamlCfg.Instances, netnsCfg, "/tmp")
	if err != nil {
		t.Fatalf("parseRoutingConfigInstances: %v", err)
	}
	inst := cfg.Instances[0]
	if inst.Upstream == nil || !inst.Upstream.Enabled {
		t.Fatal("upstream should be enabled")
	}
	if inst.Upstream.MeshInterface != "hgs-2host" {
		t.Errorf("default mesh interface = %q, want hgs-2host", inst.Upstream.MeshInterface)
	}
	if inst.Upstream.ExternalInterface != "hgs-2higgs" {
		t.Errorf("default external interface = %q, want hgs-2higgs", inst.Upstream.ExternalInterface)
	}
	if !inst.Upstream.CreateVeth {
		t.Error("default create_veth = false, want true")
	}
	if inst.Upstream.ExternalNetns != "" {
		t.Errorf("default external netns = %q, want empty host/init netns", inst.Upstream.ExternalNetns)
	}
}

func TestParseUpstreamConfigCreateVethCanBeDisabled(t *testing.T) {
	yamlInput := `
instances:
  - id: main
    netns: higgstesth2
    upstream:
      create_veth: false
`
	var yamlCfg routingInstancesYAML
	if err := yaml.Unmarshal([]byte(yamlInput), &yamlCfg); err != nil {
		t.Fatalf("yaml unmarshal: %v", err)
	}

	netnsCfg := netnsConfig{Names: map[string]ipsec.NetNSSpec{
		"higgstesth2": {Kind: "name", Name: "higgstesth2", Create: true},
	}}
	cfg, err := parseRoutingConfigInstances(yamlCfg.Instances, netnsCfg, "/tmp")
	if err != nil {
		t.Fatalf("parseRoutingConfigInstances: %v", err)
	}
	inst := cfg.Instances[0]
	if inst.Upstream == nil || !inst.Upstream.Enabled {
		t.Fatal("upstream should be enabled")
	}
	if inst.Upstream.CreateVeth {
		t.Error("create_veth = true, want explicit false")
	}
}

func TestParseUpstreamConfigInvalidIPv4(t *testing.T) {
	yamlInput := `
instances:
  - id: main
    netns: higgstesth2
    upstream:
      mesh:
        ipv4_ll: "not-a-cidr"
`
	var yamlCfg routingInstancesYAML
	if err := yaml.Unmarshal([]byte(yamlInput), &yamlCfg); err != nil {
		t.Fatalf("yaml unmarshal: %v", err)
	}

	netnsCfg := netnsConfig{Names: map[string]ipsec.NetNSSpec{
		"higgstesth2": {Kind: "name", Name: "higgstesth2", Create: true},
	}}
	_, err := parseRoutingConfigInstances(yamlCfg.Instances, netnsCfg, "/tmp")
	if err == nil {
		t.Fatal("expected error for invalid mesh.ipv4_ll")
	}
}

func TestParseUpstreamConfigInvalidIPv6(t *testing.T) {
	yamlInput := `
instances:
  - id: main
    netns: higgstesth2
    upstream:
      external:
        ipv6_ll: "not-a-cidr"
`
	var yamlCfg routingInstancesYAML
	if err := yaml.Unmarshal([]byte(yamlInput), &yamlCfg); err != nil {
		t.Fatalf("yaml unmarshal: %v", err)
	}

	netnsCfg := netnsConfig{Names: map[string]ipsec.NetNSSpec{
		"higgstesth2": {Kind: "name", Name: "higgstesth2", Create: true},
	}}
	_, err := parseRoutingConfigInstances(yamlCfg.Instances, netnsCfg, "/tmp")
	if err == nil {
		t.Fatal("expected error for invalid external.ipv6_ll")
	}
}
