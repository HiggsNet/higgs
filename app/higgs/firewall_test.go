package main

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Catofes/higgs/pkg/firewall"
	"github.com/Catofes/higgs/pkg/routing"
	"github.com/Catofes/higgs/pkg/transport/ipsec"
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
      redirect_grace: {}
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

func TestParseConfigYAMLFirewallDisabled(t *testing.T) {
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
      disabled: true
`
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	if len(config.Firewall.Instances) != 1 {
		t.Fatalf("expected 1 firewall instance, got %d", len(config.Firewall.Instances))
	}
	if config.Firewall.Instances[0].Enabled {
		t.Fatal("firewall instance should be disabled")
	}
}

func TestParseConfigYAMLFirewallRejectsHostNetnsConflict(t *testing.T) {
	config := defaultAppConfig()
	input := `
netns:
  default:
    kind: name
    name: h2
    create: true
firewall:
  instances:
    - id: ambiguous
      host: true
      netns: h2
`
	err := parseConfigYAML(input, config)
	if err == nil {
		t.Fatal("expected error for host/netns conflict")
	}
	if !strings.Contains(err.Error(), "host: true conflicts with netns") {
		t.Fatalf("unexpected error: %v", err)
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

func TestBuildFirewallPolicyInputHostRedirectGracePorts(t *testing.T) {
	state, _ := buildTestNetworkState(t)
	now := time.Unix(6000, 0)
	state.ManagedZone = "node-b.catofes."
	state.Network.Zones[state.ManagedZone].Records[ipsec.RecordKeyPorts] = unsignedIPsecRecord(t, state.ManagedZone, ipsec.RecordKeyPorts, ipsec.RecordTypePorts, ipsec.PortRecord{
		Version: 1,
		Mode:    ipsec.PortModeFixed,
		Current: &ipsec.PortSelection{
			Generation: 3,
			IKE:        ipsec.PortBinding{Local: 1500, Advertised: 1500},
			NATT:       ipsec.PortBinding{Local: 14500, Advertised: 14500},
		},
		Previous: []ipsec.PortSelection{
			{
				Generation: 2,
				IKE:        ipsec.PortBinding{Local: 1400, Advertised: 1400},
				NATT:       ipsec.PortBinding{Local: 14400, Advertised: 14400},
				ValidUntil: now.Add(time.Minute).Unix(),
			},
			{
				Generation: 1,
				IKE:        ipsec.PortBinding{Local: 1300, Advertised: 1300},
				NATT:       ipsec.PortBinding{Local: 14300, Advertised: 14300},
				ValidUntil: now.Add(-time.Second).Unix(),
			},
		},
		UpdatedAt: now.Unix(),
	})
	oldNow := nowFunc
	nowFunc = func() time.Time { return now }
	t.Cleanup(func() { nowFunc = oldNow })

	input := buildFirewallPolicyInput(
		firewall.FirewallInstanceSpec{ID: "host", IsHost: true},
		&routing.AuthorizedRouteSet{},
		state,
		defaultAppConfig(),
	)
	if len(input.AdvertisedCurrentIKEPorts) != 1 || input.AdvertisedCurrentIKEPorts[0] != 1500 {
		t.Fatalf("current IKE ports = %v, want [1500]", input.AdvertisedCurrentIKEPorts)
	}
	if len(input.AdvertisedCurrentNATTPorts) != 1 || input.AdvertisedCurrentNATTPorts[0] != 14500 {
		t.Fatalf("current NAT-T ports = %v, want [14500]", input.AdvertisedCurrentNATTPorts)
	}
	if len(input.AdvertisedPreviousIKEPorts) != 1 || input.AdvertisedPreviousIKEPorts[0] != 1400 {
		t.Fatalf("previous IKE ports = %v, want [1400]", input.AdvertisedPreviousIKEPorts)
	}
	if len(input.AdvertisedPreviousNATTPorts) != 1 || input.AdvertisedPreviousNATTPorts[0] != 14400 {
		t.Fatalf("previous NAT-T ports = %v, want [14400]", input.AdvertisedPreviousNATTPorts)
	}
}

type captureFirewallOwnerDriver struct {
	firewall.DryRunDriver
	owners []firewall.Owner
}

func (d *captureFirewallOwnerDriver) ListOwned(ctx context.Context, owner firewall.Owner) (firewall.FirewallObservedState, error) {
	d.owners = append(d.owners, owner)
	return firewall.FirewallObservedState{}, nil
}

func TestReconcileFirewallUsesScopeForOwnedObjects(t *testing.T) {
	state, config := buildTestNetworkState(t)
	appConfig := defaultAppConfig()
	appConfig.Firewall.Instances = []FirewallInstanceConfig{
		{
			ID:            "higgs",
			NetNS:         "default",
			Enabled:       true,
			Mode:          firewall.ModeManaged,
			Backend:       firewall.BackendNone,
			DefaultPolicy: firewall.DefaultPolicyDrop,
		},
		{
			ID:        "host-ipsec",
			NetNS:     "host",
			IsHost:    true,
			Enabled:   true,
			Mode:      firewall.ModeManaged,
			Backend:   firewall.BackendNone,
			HostPorts: firewall.HostPortConfig{IKE: true, NATT: true},
		},
	}
	rt := &Runtime{
		Config:    appConfig,
		StatePath: filepath.Join(t.TempDir(), "higgs.db"),
		Clock:     func() time.Time { return time.Unix(7000, 0) },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	driver := &captureFirewallOwnerDriver{}
	service := newDaemonService(rt, state, config, time.Second)
	service.firewallDriver = driver
	if err := service.reconcileFirewall(context.Background()); err != nil {
		t.Fatalf("reconcileFirewall: %v", err)
	}
	if len(driver.owners) != 2 {
		t.Fatalf("owners = %+v, want two instances", driver.owners)
	}
	if driver.owners[0].InstanceID != "default" {
		t.Fatalf("overlay owner scope = %q, want default", driver.owners[0].InstanceID)
	}
	if driver.owners[1].InstanceID != "host" {
		t.Fatalf("host owner scope = %q, want host", driver.owners[1].InstanceID)
	}
}

func TestFirewallReconcileDirtyIntervalAndRecover(t *testing.T) {
	state, config := buildTestNetworkState(t)
	appConfig := defaultAppConfig()
	appConfig.Firewall.Instances = []FirewallInstanceConfig{{
		ID:            "h2",
		NetNS:         "h2",
		Enabled:       true,
		Mode:          firewall.ModeManaged,
		Backend:       firewall.BackendNone,
		DefaultPolicy: firewall.DefaultPolicyDrop,
	}}
	rt := &Runtime{
		Config:    appConfig,
		StatePath: filepath.Join(t.TempDir(), "higgs.db"),
		Clock:     func() time.Time { return time.Unix(7000, 0) },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	service := newDaemonService(rt, state, config, time.Second)

	if service.firewallReconcileInterval() != defaultFirewallReconcileInterval {
		t.Fatalf("firewall interval = %s, want %s", service.firewallReconcileInterval(), defaultFirewallReconcileInterval)
	}
	base := time.Unix(7000, 0)
	if got := nextFirewallReconcileTime(base, 5*time.Second); !got.Equal(base.Add(5 * time.Second)) {
		t.Fatalf("nextFirewallReconcileTime = %s, want %s", got, base.Add(5*time.Second))
	}
	if got := nextFirewallReconcileTime(base, 0); !got.IsZero() {
		t.Fatalf("nextFirewallReconcileTime disabled = %s, want zero", got)
	}
	if service.flushFirewallReconcile(context.Background()) {
		t.Fatal("flushFirewallReconcile should be false when not dirty")
	}

	service.recoverFirewallOnStart(context.Background())
	if service.firewallDirty {
		t.Fatal("recoverFirewallOnStart should flush and clear firewallDirty")
	}
	if state.FirewallReconcile == nil || state.FirewallReconcile.Instances["h2"] == nil {
		t.Fatalf("firewall reconcile state missing after recover: %+v", state.FirewallReconcile)
	}
	entry := state.FirewallReconcile.Instances["h2"]
	if entry.PolicyHash == "" || entry.OwnedObjects == 0 || entry.LastRunUnix != 7000 {
		t.Fatalf("firewall reconcile entry = %+v, want hash/objects/last run", entry)
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
