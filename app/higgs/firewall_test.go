package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/Catofes/higgs/pkg/firewall"
)

func TestParseConfigYAMLFirewallOverlay(t *testing.T) {
	config := defaultAppConfig()
	input := `
netns:
  default:
    kind: name
    name: h2
    create: true
firewall:
  instances:
    - id: h2
      netns: h2
      enabled: true
      mode: managed
      backend: auto
      default_policy: drop
      xfrm_tunnel_pattern: "hgs*"
      local_services:
        - proto: tcp
          port: 8080
          sources:
            - 10.42.0.0/16
      forwarding:
        transit: false
        allow_prefixes:
          - 10.42.0.0/16
`
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	if len(config.Firewall.Instances) != 1 {
		t.Fatalf("expected 1 firewall instance, got %d", len(config.Firewall.Instances))
	}
	inst := config.Firewall.Instances[0]
	if inst.ID != "h2" {
		t.Errorf("ID = %s, want h2", inst.ID)
	}
	if inst.Mode != firewall.ModeManaged {
		t.Errorf("Mode = %s, want managed", inst.Mode)
	}
	if inst.DefaultPolicy != firewall.DefaultPolicyDrop {
		t.Errorf("DefaultPolicy = %s, want drop", inst.DefaultPolicy)
	}
	if len(inst.LocalServices) != 1 {
		t.Fatalf("expected 1 local service, got %d", len(inst.LocalServices))
	}
	if inst.LocalServices[0].Port != 8080 {
		t.Errorf("service port = %d, want 8080", inst.LocalServices[0].Port)
	}
	if inst.Forwarding.Transit {
		t.Error("transit should be false")
	}
	if len(inst.Forwarding.AllowPrefixes) != 1 {
		t.Errorf("allow_prefixes len = %d, want 1", len(inst.Forwarding.AllowPrefixes))
	}
}

func TestParseConfigYAMLFirewallHost(t *testing.T) {
	config := defaultAppConfig()
	input := `
firewall:
  instances:
    - id: host-ipsec
      host: true
      mode: managed
      backend: nft
      host_ports:
        ike: true
        natt: true
      redirect_grace:
        enabled: true
`
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	if len(config.Firewall.Instances) != 1 {
		t.Fatalf("expected 1 firewall instance, got %d", len(config.Firewall.Instances))
	}
	inst := config.Firewall.Instances[0]
	if !inst.IsHost {
		t.Error("expected IsHost=true")
	}
	if inst.NetNS != "host" {
		t.Errorf("NetNS = %s, want host", inst.NetNS)
	}
	if !inst.HostPorts.IKE {
		t.Error("IKE should be true")
	}
	if !inst.HostPorts.NATT {
		t.Error("NATT should be true")
	}
	if !inst.RedirectGrace.Enabled {
		t.Error("redirect grace should be enabled")
	}
}

func TestParseConfigYAMLFirewallInvalidMode(t *testing.T) {
	config := defaultAppConfig()
	input := `
netns:
  default:
    kind: name
    name: h2
    create: true
firewall:
  instances:
    - id: h2
      netns: h2
      mode: bogus
`
	if err := parseConfigYAML(input, config); err == nil {
		t.Error("expected error for invalid mode")
	}
}

func TestParseConfigYAMLFirewallInvalidBackend(t *testing.T) {
	config := defaultAppConfig()
	input := `
netns:
  default:
    kind: name
    name: h2
    create: true
firewall:
  instances:
    - id: h2
      netns: h2
      backend: bogus
`
	if err := parseConfigYAML(input, config); err == nil {
		t.Error("expected error for invalid backend")
	}
}

func TestParseConfigYAMLFirewallUnknownNetns(t *testing.T) {
	config := defaultAppConfig()
	input := `
firewall:
  instances:
    - id: h2
      netns: nonexistent
`
	if err := parseConfigYAML(input, config); err == nil {
		t.Error("expected error for unknown netns")
	}
}

func TestFirewallInstancesEnabled(t *testing.T) {
	config := &appConfig{
		Firewall: firewallConfig{
			Instances: []FirewallInstanceConfig{
				{ID: "a", Enabled: true, Mode: firewall.ModeManaged},
				{ID: "b", Enabled: false, Mode: firewall.ModeManaged},
				{ID: "c", Enabled: true, Mode: firewall.ModeDisabled},
			},
		},
	}
	enabled := firewallInstancesEnabled(config)
	if len(enabled) != 1 {
		t.Fatalf("expected 1 enabled, got %d", len(enabled))
	}
	if enabled[0].ID != "a" {
		t.Errorf("expected instance a, got %s", enabled[0].ID)
	}
}

func TestFirewallInstanceSpecFromConfig(t *testing.T) {
	inst := FirewallInstanceConfig{
		ID: "h2", NetNS: "h2", IsHost: false,
		Enabled: true, Mode: firewall.ModeManaged,
		Backend: firewall.BackendNFT, DefaultPolicy: firewall.DefaultPolicyDrop,
		OwnerPrefix: "higgs", XFRMTunnelPattern: "hgs*",
		LocalServices: []firewall.LocalService{{Proto: "tcp", Port: 443}},
	}
	spec := firewallInstanceSpecFromConfig(inst, nil, 500, 4500)
	if spec.ID != "h2" {
		t.Errorf("ID = %s", spec.ID)
	}
	if spec.CharonIKEPort != 500 {
		t.Errorf("IKEPort = %d", spec.CharonIKEPort)
	}
	if len(spec.LocalServices) != 1 {
		t.Errorf("local services = %d", len(spec.LocalServices))
	}
}

func TestReconcileFirewall_NoInstances(t *testing.T) {
	d := &DaemonService{
		Sync: &SyncRuntime{
			App:   &Runtime{Config: &appConfig{}},
			State: &stateFile{},
		},
	}
	if err := d.reconcileFirewall(context.Background()); err != nil {
		t.Fatalf("reconcileFirewall with no instances: %v", err)
	}
}

func TestDebugFirewall_NotConfigured(t *testing.T) {
	rt := &Runtime{Config: &appConfig{}}
	var buf bytes.Buffer
	instances := []FirewallInstanceConfig{}
	if err := writeDebugFirewall(&buf, rt, instances, nil); err != nil {
		t.Fatalf("writeDebugFirewall: %v", err)
	}
	output := buf.String()
	if !strings.Contains(output, "not configured") {
		t.Errorf("expected 'not configured' in output, got: %s", output)
	}
}

func TestDebugFirewall_InstanceOutput(t *testing.T) {
	rt := &Runtime{Config: &appConfig{}}
	instances := []FirewallInstanceConfig{
		{ID: "h2", NetNS: "h2", IsHost: false, Enabled: true, Mode: firewall.ModeManaged, Backend: firewall.BackendAuto, DefaultPolicy: firewall.DefaultPolicyDrop},
		{ID: "host", NetNS: "host", IsHost: true, Enabled: true, Mode: firewall.ModeManaged, HostPorts: firewall.HostPortConfig{IKE: true, NATT: true}, RedirectGrace: firewall.RedirectGrace{Enabled: true}},
	}
	snapshot := &firewallReconcileState{
		Backend: "dry-run",
		Instances: map[string]*firewallInstanceReconcileStateEntry{
			"h2": {Generation: 5, OwnedObjects: 10, PolicyHash: "abc123"},
		},
	}
	var buf bytes.Buffer
	if err := writeDebugFirewall(&buf, rt, instances, snapshot); err != nil {
		t.Fatalf("writeDebugFirewall: %v", err)
	}
	output := buf.String()
	if !strings.Contains(output, "backend: dry-run") {
		t.Errorf("missing backend line: %s", output)
	}
	if !strings.Contains(output, "instance h2") {
		t.Errorf("missing h2 instance: %s", output)
	}
	if !strings.Contains(output, "generation: 5") {
		t.Errorf("missing generation: %s", output)
	}
	if !strings.Contains(output, "host_ports: ike=true natt=true") {
		t.Errorf("missing host_ports: %s", output)
	}
	if !strings.Contains(output, "transit: false") {
		t.Errorf("missing transit: %s", output)
	}
}
