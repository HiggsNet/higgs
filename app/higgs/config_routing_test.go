package main

import (
	"github.com/Catofes/higgs/pkg/transport/ipsec"
	"path/filepath"
	"testing"
)

func TestParseConfigYAMLRoutingInstances(t *testing.T) {
	config := defaultAppConfig()
	input := `
netns:
  default:
    kind: name
    name: higgstesth2
    create: true
routing:
  instances:
    - id: main
      netns: higgstesth2
      provider: bird
      mode: external
      shutdown_policy: stop
      control_socket: /run/higgs/bird-main.ctl
      pid_file: /run/higgs/bird-main.pid
      config_file: /etc/higgs/bird-main.conf
      table: "254"
      metric_base: 150
      metric_staged: 250
      metric_draining: 550
      ecmp: false
      ecmp_limit: 8
      interface_pattern: hgs*
`
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	normalizeAppConfig(config)
	if len(config.Routing.Instances) != 1 {
		t.Fatalf("Routing.Instances len = %d, want 1", len(config.Routing.Instances))
	}
	inst := config.Routing.Instances[0]
	if inst.ID != "main" {
		t.Fatalf("inst.ID = %q, want main", inst.ID)
	}
	if inst.NetNS != "higgstesth2" {
		t.Fatalf("inst.NetNS = %q, want higgstesth2", inst.NetNS)
	}
	if !inst.Enabled {
		t.Fatalf("inst.Enabled = false, want true")
	}
	if inst.Protocol != "bird" {
		t.Fatalf("inst.Protocol = %q, want bird", inst.Protocol)
	}
	if inst.Mode != ipsec.RoutingModeExternal {
		t.Fatalf("inst.Mode = %q, want external", inst.Mode)
	}
	if inst.ShutdownPolicy != routingShutdownPolicyStop {
		t.Fatalf("inst.ShutdownPolicy = %q, want stop", inst.ShutdownPolicy)
	}
	if inst.ControlSocket != "/run/higgs/bird-main.ctl" {
		t.Fatalf("inst.ControlSocket = %q", inst.ControlSocket)
	}
	if inst.PIDFile != "/run/higgs/bird-main.pid" {
		t.Fatalf("inst.PIDFile = %q", inst.PIDFile)
	}
	if inst.ConfigFile != "/etc/higgs/bird-main.conf" {
		t.Fatalf("inst.ConfigFile = %q", inst.ConfigFile)
	}
	if inst.TableID != "254" {
		t.Fatalf("inst.TableID = %q, want 254", inst.TableID)
	}
	if inst.MetricBase != 150 {
		t.Fatalf("inst.MetricBase = %d, want 150", inst.MetricBase)
	}
	if inst.MetricStaged != 250 {
		t.Fatalf("inst.MetricStaged = %d, want 250", inst.MetricStaged)
	}
	if inst.MetricDraining != 550 {
		t.Fatalf("inst.MetricDraining = %d, want 550", inst.MetricDraining)
	}
	if inst.ECMP {
		t.Fatalf("inst.ECMP = true, want false")
	}
	if inst.ECMPLimit != 8 {
		t.Fatalf("inst.ECMPLimit = %d, want 8", inst.ECMPLimit)
	}
	if inst.InterfacePat != "hgs*" {
		t.Fatalf("inst.InterfacePat = %q, want hgs*", inst.InterfacePat)
	}
}

func TestParseConfigYAMLRoutingInstancesRejectsLegacyProtocolAlias(t *testing.T) {
	config := defaultAppConfig()
	input := `
netns:
  default:
    kind: name
    name: higgstesth2
    create: true
routing:
  instances:
    - id: main
      netns: higgstesth2
      protocol: bird
`
	if err := parseConfigYAML(input, config); err == nil {
		t.Fatal("parseConfigYAML should reject routing.instances[].protocol")
	}
}

func TestParseConfigYAMLRoutingInstancesDefaults(t *testing.T) {
	config := defaultAppConfig()
	input := `
netns:
  default:
    kind: name
    name: higgstesth2
    create: true
routing:
  instances:
    - id: main
      netns: higgstesth2
`
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	normalizeAppConfig(config)
	if len(config.Routing.Instances) != 1 {
		t.Fatalf("Routing.Instances len = %d, want 1", len(config.Routing.Instances))
	}
	inst := config.Routing.Instances[0]
	if inst.Mode != ipsec.RoutingModeManaged {
		t.Fatalf("inst.Mode = %q, want managed", inst.Mode)
	}
	if inst.ShutdownPolicy != routingShutdownPolicyPersist {
		t.Fatalf("inst.ShutdownPolicy = %q, want persist", inst.ShutdownPolicy)
	}
	if inst.Protocol != "bird" {
		t.Fatalf("inst.Protocol = %q, want bird", inst.Protocol)
	}
	if inst.TableID != "main" {
		t.Fatalf("inst.TableID = %q, want main", inst.TableID)
	}
	if inst.MetricBase != 100 {
		t.Fatalf("inst.MetricBase = %d, want 100", inst.MetricBase)
	}
	if inst.MetricStaged != 200 {
		t.Fatalf("inst.MetricStaged = %d, want 200", inst.MetricStaged)
	}
	if inst.MetricDraining != 500 {
		t.Fatalf("inst.MetricDraining = %d, want 500", inst.MetricDraining)
	}
	if !inst.ECMP {
		t.Fatalf("inst.ECMP = false, want true")
	}
	if inst.ECMPLimit != 16 {
		t.Fatalf("inst.ECMPLimit = %d, want 16", inst.ECMPLimit)
	}
	if inst.InterfacePat != "hgs*" {
		t.Fatalf("inst.InterfacePat = %q, want hgs*", inst.InterfacePat)
	}
}

func TestParseConfigYAMLRoutingInstancesRejectsInvalidShutdownPolicy(t *testing.T) {
	config := defaultAppConfig()
	input := `
netns:
  default:
    kind: name
    name: higgstesth2
    create: true
routing:
  instances:
    - id: main
      netns: higgstesth2
      shutdown_policy: drain
`
	if err := parseConfigYAML(input, config); err == nil {
		t.Fatal("parseConfigYAML should reject unsupported routing.instances[].shutdown_policy")
	}
}

func TestParseConfigYAMLRoutingInstanceDefaultsToDefaultNetNS(t *testing.T) {
	config := defaultAppConfig()
	input := `
netns:
  default:
    kind: name
    name: higgstesth2
    create: true
routing:
  instances:
    - id: main
`
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	normalizeAppConfig(config)
	if len(config.Routing.Instances) != 1 {
		t.Fatalf("Routing.Instances len = %d, want 1", len(config.Routing.Instances))
	}
	inst := config.Routing.Instances[0]
	if inst.NetNS != "higgstesth2" {
		t.Fatalf("inst.NetNS = %q, want resolved default higgstesth2", inst.NetNS)
	}
	if inst.ControlSocket != filepath.Join(config.DataDir, "bird", "bird-higgstesth2.ctl") {
		t.Fatalf("inst.ControlSocket = %q, want resolved-netns-derived path", inst.ControlSocket)
	}
	if inst.PIDFile != filepath.Join(config.DataDir, "bird", "bird-higgstesth2.pid") {
		t.Fatalf("inst.PIDFile = %q, want resolved-netns-derived path", inst.PIDFile)
	}
	if inst.ConfigFile != filepath.Join(config.DataDir, "bird", "bird-higgstesth2.conf") {
		t.Fatalf("inst.ConfigFile = %q, want resolved-netns-derived path", inst.ConfigFile)
	}
}

func TestParseConfigYAMLRoutingUpstreamDefaultUsesResolvedDefaultNetNS(t *testing.T) {
	config := defaultAppConfig()
	input := `
routing:
  instances:
    - id: main
      upstream: {}
`
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	normalizeAppConfig(config)
	if len(config.Routing.Instances) != 1 {
		t.Fatalf("Routing.Instances len = %d, want 1", len(config.Routing.Instances))
	}
	inst := config.Routing.Instances[0]
	if inst.NetNS != ipsec.DefaultNetNSName {
		t.Fatalf("inst.NetNS = %q, want default netns target %q", inst.NetNS, ipsec.DefaultNetNSName)
	}
	if inst.Upstream == nil || !inst.Upstream.Enabled {
		t.Fatal("upstream should be enabled")
	}
	if !inst.Upstream.CreateVeth {
		t.Fatal("upstream create_veth should default to true")
	}
	if inst.Upstream.MeshInterface != "hgv2host" || inst.Upstream.ExternalInterface != "hgv2mesh" {
		t.Fatalf("upstream interfaces = %q/%q, want hgv2host/hgv2mesh", inst.Upstream.MeshInterface, inst.Upstream.ExternalInterface)
	}
}

func TestParseConfigYAMLRoutingInstanceDisabled(t *testing.T) {
	config := defaultAppConfig()
	input := `
netns:
  default:
    kind: name
    name: higgstesth2
    create: true
routing:
  instances:
    - id: main
      netns: higgstesth2
      disabled: true
`
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	normalizeAppConfig(config)
	if len(config.Routing.Instances) != 1 {
		t.Fatalf("Routing.Instances len = %d, want 1", len(config.Routing.Instances))
	}
	if config.Routing.Instances[0].Enabled {
		t.Fatalf("routing instance should be disabled")
	}
}

func TestParseConfigYAMLRejectsConflictingEnabledDisabled(t *testing.T) {
	config := defaultAppConfig()
	input := `
netns:
  default:
    kind: name
    name: higgstesth2
    create: true
routing:
  instances:
    - id: main
      netns: higgstesth2
      enabled: true
      disabled: true
`
	if err := parseConfigYAML(input, config); err == nil {
		t.Fatal("parseConfigYAML should reject conflicting enabled/disabled")
	}
}
