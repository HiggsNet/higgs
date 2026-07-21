package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Catofes/higgs/internal/observer"
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
    name: higgstesth2
    create: true
    forwarding:
      transit: false
      allow_prefixes:
        - 10.42.0.0/16
firewall:
  instances:
    - id: higgstesth2
      netns: higgstesth2
      mode: managed
      backend: auto
      default_policy: drop
      xfrm_tunnel_pattern: "hgs*"
      local_services:
        - proto: tcp
          port: 8080
          sources:
            - 10.42.0.0/16
`
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	if len(config.Firewall.Instances) != 1 {
		t.Fatalf("expected 1 firewall instance, got %d", len(config.Firewall.Instances))
	}
	inst := config.Firewall.Instances[0]
	if inst.ID != "higgstesth2" {
		t.Errorf("ID = %s, want higgstesth2", inst.ID)
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
	policy := netnsForwardingPolicy(config, inst.NetNS)
	if policy.Transit {
		t.Error("transit should be false")
	}
	if len(policy.AllowPrefixes) != 1 {
		t.Errorf("allow_prefixes len = %d, want 1", len(policy.AllowPrefixes))
	}
}

func TestParseConfigYAMLFirewallInlineHooks(t *testing.T) {
	config := defaultAppConfig()
	input := `
netns:
  default:
    kind: name
    name: h2
firewall:
  instances:
    - id: h2
      backend: auto
      nft_hooks:
        pre_input:
          - 'tcp dport 22 accept'
      iptables_hooks:
        ipv4:
          pre_input:
            - '-s 10.20.0.0/16 -j ACCEPT'
            - '-s 10.30.0.0/16 -j ACCEPT'
        ipv6:
          pre_input:
            - '-s 2001:db8::/32 -j ACCEPT'
`
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	got := config.Firewall.Instances[0].NativeHooks
	if len(got.NFT.PreInput) != 1 || len(got.IPTables.IPv4.PreInput) != 2 || len(got.IPTables.IPv6.PreInput) != 1 {
		t.Fatalf("parsed inline hooks = %+v", got)
	}
}

func TestParseConfigYAMLFirewallInlineHooksRejectsBothFamily(t *testing.T) {
	config := defaultAppConfig()
	input := `
netns:
  default:
    kind: name
    name: h2
firewall:
  instances:
    - id: h2
      iptables_hooks:
        both:
          pre_input:
            - '-j ACCEPT'
`
	err := parseConfigYAML(input, config)
	if err == nil || !strings.Contains(err.Error(), "field both not found") {
		t.Fatalf("parseConfigYAML error = %v, want strict rejection of both", err)
	}
}

func TestParseConfigYAMLFirewallRejectsRemovedExternalChainHooks(t *testing.T) {
	config := defaultAppConfig()
	err := parseConfigYAML(`
netns:
  default:
    kind: name
    name: h2
firewall:
  instances:
    - id: h2
      hooks:
        pre_input: admin_input
`, config)
	if err == nil || !strings.Contains(err.Error(), "field hooks not found") {
		t.Fatalf("parseConfigYAML error = %v, want strict rejection of removed hooks", err)
	}
}

func TestParseConfigYAMLFirewallOverlayDefaultsToDefaultNetNS(t *testing.T) {
	config := defaultAppConfig()
	input := `
netns:
  default:
    kind: name
    name: higgstesth2
    create: true
firewall:
  instances:
    - id: higgstesth2
      mode: managed
`
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	if len(config.Firewall.Instances) != 1 {
		t.Fatalf("expected 1 firewall instance, got %d", len(config.Firewall.Instances))
	}
	inst := config.Firewall.Instances[0]
	if inst.NetNS != "default" {
		t.Fatalf("NetNS = %s, want default", inst.NetNS)
	}
	if inst.IsHost {
		t.Fatal("defaulted netns instance should not be host")
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

func TestParseConfigYAMLFirewallHostDefaultsForIPsecRange(t *testing.T) {
	config := defaultAppConfig()
	input := `
ipsec:
  port_mode: range
  port_range:
    from: 30000
    to: 30099
firewall:
  instances:
    - id: host-ipsec
      host: true
`
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	if len(config.Firewall.Instances) != 1 {
		t.Fatalf("expected 1 firewall instance, got %d", len(config.Firewall.Instances))
	}
	inst := config.Firewall.Instances[0]
	if !inst.HostPorts.IKE || !inst.HostPorts.NATT {
		t.Fatalf("range mode host ports = %+v, want IKE/NATT enabled by default", inst.HostPorts)
	}
	if !inst.RedirectGrace.Enabled {
		t.Fatal("range mode should enable redirect_grace by default")
	}
}

func TestParseConfigYAMLFirewallHostRangeDefaultsCanBeDisabled(t *testing.T) {
	config := defaultAppConfig()
	input := `
ipsec:
  port_mode: range
  port_range:
    from: 30000
    to: 30099
firewall:
  instances:
    - id: host-ipsec
      host: true
      host_ports:
        ike: false
        natt: false
      redirect_grace:
        disabled: true
`
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	inst := config.Firewall.Instances[0]
	if inst.HostPorts.IKE || inst.HostPorts.NATT {
		t.Fatalf("explicit host port disables ignored: %+v", inst.HostPorts)
	}
	if inst.RedirectGrace.Enabled {
		t.Fatal("explicit redirect_grace disabled should override range default")
	}
}

func TestParseConfigYAMLFirewallHostListenAddrs(t *testing.T) {
	config := defaultAppConfig()
	input := `
firewall:
  instances:
    - id: host-ipsec
      host: true
      listen_addrs:
        - 172.17.16.168
        - "[2408:400a:101:3801:6cbd:8fb4:ae31:750a]:4500"
`
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	if len(config.Firewall.Instances) != 1 {
		t.Fatalf("expected 1 firewall instance, got %d", len(config.Firewall.Instances))
	}
	inst := config.Firewall.Instances[0]
	if len(inst.ListenAddrs) != 2 {
		t.Fatalf("expected 2 listen addrs, got %d: %+v", len(inst.ListenAddrs), inst.ListenAddrs)
	}
	if inst.ListenAddrs[0].String() != "172.17.16.168" {
		t.Errorf("listen addr[0] = %s, want 172.17.16.168", inst.ListenAddrs[0])
	}
	if inst.ListenAddrs[1].String() != "2408:400a:101:3801:6cbd:8fb4:ae31:750a" {
		t.Errorf("listen addr[1] = %s, want 2408:400a:101:3801:6cbd:8fb4:ae31:750a", inst.ListenAddrs[1])
	}
}

func TestParseConfigYAMLFirewallHostListenAddrsInvalid(t *testing.T) {
	config := defaultAppConfig()
	input := `
firewall:
  instances:
    - id: host-ipsec
      host: true
      listen_addrs:
        - not-an-address
`
	err := parseConfigYAML(input, config)
	if err == nil {
		t.Fatal("expected error for invalid listen_addrs")
	}
	if !strings.Contains(err.Error(), "listen_addrs") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseConfigYAMLFirewallDisabled(t *testing.T) {
	config := defaultAppConfig()
	input := `
netns:
  default:
    kind: name
    name: higgstesth2
    create: true
firewall:
  instances:
    - id: higgstesth2
      netns: higgstesth2
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
    name: higgstesth2
    create: true
firewall:
  instances:
    - id: ambiguous
      host: true
      netns: higgstesth2
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
    name: higgstesth2
    create: true
firewall:
  instances:
    - id: higgstesth2
      netns: higgstesth2
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
    name: higgstesth2
    create: true
firewall:
  instances:
    - id: higgstesth2
      netns: higgstesth2
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
    - id: higgstesth2
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
		ID: "higgstesth2", NetNS: "higgstesth2", IsHost: false,
		Enabled: true, Mode: firewall.ModeManaged,
		Backend: firewall.BackendNFT, DefaultPolicy: firewall.DefaultPolicyDrop,
		OwnerPrefix: "higgs", XFRMTunnelPattern: "hgs*",
		LocalServices: []firewall.LocalService{{Proto: "tcp", Port: 443}},
	}
	spec := firewallInstanceSpecFromConfig(inst, nil, 500, 4500)
	if spec.ID != "higgstesth2" {
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
	owners  []firewall.Owner
	onApply func()
}

func (d *captureFirewallOwnerDriver) ListOwned(ctx context.Context, owner firewall.Owner) (firewall.FirewallObservedState, error) {
	d.owners = append(d.owners, owner)
	return firewall.FirewallObservedState{}, nil
}

func (d *captureFirewallOwnerDriver) Apply(ctx context.Context, plan firewall.FirewallPlan, desired *firewall.FirewallDesiredState) (firewall.FirewallApplyResult, error) {
	if d.onApply != nil {
		d.onApply()
	}
	return d.DryRunDriver.Apply(ctx, plan, desired)
}

type blockingFirewallDriver struct {
	firewall.DryRunDriver
	started chan struct{}
	unblock chan struct{}
}

func (d *blockingFirewallDriver) Apply(ctx context.Context, plan firewall.FirewallPlan, desired *firewall.FirewallDesiredState) (firewall.FirewallApplyResult, error) {
	close(d.started)
	select {
	case <-d.unblock:
	case <-ctx.Done():
		return firewall.FirewallApplyResult{}, ctx.Err()
	}
	return d.DryRunDriver.Apply(ctx, plan, desired)
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

func TestLongFirewallReconcileDoesNotBlockCommittedReaders(t *testing.T) {
	state, config := buildTestNetworkState(t)
	appConfig := defaultAppConfig()
	appConfig.Observer.Enabled = true
	appConfig.Firewall.Instances = []FirewallInstanceConfig{{
		ID:            "higgstesth2",
		NetNS:         "higgstesth2",
		Enabled:       true,
		Mode:          firewall.ModeManaged,
		Backend:       firewall.BackendNone,
		DefaultPolicy: firewall.DefaultPolicyDrop,
	}}
	rt := &Runtime{
		Config:    appConfig,
		StatePath: filepath.Join(t.TempDir(), "higgs.db"),
		Clock:     func() time.Time { return time.Unix(7020, 0) },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	service := newDaemonService(rt, state, config, time.Second)
	driver := &blockingFirewallDriver{
		started: make(chan struct{}),
		unblock: make(chan struct{}),
	}
	service.firewallDriver = driver

	done := make(chan error, 1)
	go func() {
		done <- service.reconcileFirewall(context.Background())
	}()
	select {
	case <-driver.started:
	case <-time.After(time.Second):
		close(driver.unblock)
		t.Fatal("firewall reconcile did not enter blocking apply")
	}

	committedRev := service.StateStore.Meta().Revision
	statusDone := make(chan controlResponse, 1)
	go func() {
		statusDone <- controlRequestViaPipe(t, service, controlRequest{Method: "status"})
	}()
	select {
	case status := <-statusDone:
		if !status.OK || status.StateRevision != committedRev {
			close(driver.unblock)
			t.Fatalf("status response = %#v, want committed revision %d", status, committedRev)
		}
	case <-time.After(time.Second):
		close(driver.unblock)
		t.Fatal("control status blocked behind firewall reconcile apply")
	}

	srv := newObserverServer(service, appConfig.Observer)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	rr := httptest.NewRecorder()
	observerDone := make(chan struct{})
	go func() {
		srv.handler().ServeHTTP(rr, req)
		close(observerDone)
	}()
	select {
	case <-observerDone:
		if rr.Code != http.StatusOK {
			close(driver.unblock)
			t.Fatalf("observer status code = %d, want %d; body=%s", rr.Code, http.StatusOK, rr.Body.String())
		}
		var resp observer.APIResponse
		if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
			close(driver.unblock)
			t.Fatalf("decode observer status: %v", err)
		}
		data := resp.Data.(map[string]any)
		if data["state_revision"] != float64(committedRev) {
			close(driver.unblock)
			t.Fatalf("observer status data = %#v, want committed revision %d", data, committedRev)
		}
	case <-time.After(time.Second):
		close(driver.unblock)
		t.Fatal("observer status blocked behind firewall reconcile apply")
	}

	close(driver.unblock)
	if err := <-done; err != nil {
		t.Fatalf("reconcileFirewall: %v", err)
	}
}

func TestReconcileFirewallStaleCommitPreservesNewRevision(t *testing.T) {
	state, config := buildTestNetworkState(t)
	appConfig := defaultAppConfig()
	appConfig.Firewall.Instances = []FirewallInstanceConfig{{
		ID:            "higgstesth2",
		NetNS:         "higgstesth2",
		Enabled:       true,
		Mode:          firewall.ModeManaged,
		Backend:       firewall.BackendNone,
		DefaultPolicy: firewall.DefaultPolicyDrop,
	}}
	rt := &Runtime{
		Config:    appConfig,
		StatePath: filepath.Join(t.TempDir(), "higgs.db"),
		Clock:     func() time.Time { return time.Unix(7010, 0) },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	service := newDaemonService(rt, state, config, time.Second)
	driver := &captureFirewallOwnerDriver{}
	driver.onApply = func() {
		if _, err := service.StateStore.Update(func(state *stateFile) error {
			state.IdentityKeyPath = "newer-firewall-revision"
			return nil
		}); err != nil {
			t.Fatalf("advance state revision during firewall apply: %v", err)
		}
		driver.onApply = nil
	}
	service.firewallDriver = driver

	if err := service.reconcileFirewall(context.Background()); err != nil {
		t.Fatalf("reconcileFirewall: %v", err)
	}
	if !service.firewallDirty {
		t.Fatal("firewallDirty = false, want stale firewall summary commit to schedule another reconcile")
	}
	snapshot, _ := service.StateStore.Snapshot()
	if snapshot.IdentityKeyPath != "newer-firewall-revision" {
		t.Fatalf("identity key path = %q, want newer revision preserved", snapshot.IdentityKeyPath)
	}
	if snapshot.FirewallReconcile == nil || snapshot.FirewallReconcile.Instances["higgstesth2"] == nil {
		t.Fatalf("firewall reconcile summary = %+v, want committed stale summary", snapshot.FirewallReconcile)
	}
}

func TestFirewallDriverNetNSResolvesDefaultAlias(t *testing.T) {
	appConfig := defaultAppConfig()
	appConfig.Netns = netnsConfig{Names: map[string]ipsec.NetNSSpec{
		"default":     {Kind: ipsec.NetNSName, Name: "higgstesth2", Create: true},
		"higgstesth2": {Kind: ipsec.NetNSName, Name: "higgstesth2", Create: true},
	}}
	got, err := firewallDriverNetNS(FirewallInstanceConfig{ID: "higgs", NetNS: "default"}, appConfig)
	if err != nil {
		t.Fatalf("firewallDriverNetNS: %v", err)
	}
	if got != "higgstesth2" {
		t.Fatalf("driver netns = %q, want higgstesth2", got)
	}
	host, err := firewallDriverNetNS(FirewallInstanceConfig{ID: "host-ipsec", IsHost: true}, appConfig)
	if err != nil {
		t.Fatalf("host firewallDriverNetNS: %v", err)
	}
	if host != "" {
		t.Fatalf("host driver netns = %q, want empty host namespace", host)
	}
}

func TestFirewallReconcileDirtyIntervalAndRecover(t *testing.T) {
	state, config := buildTestNetworkState(t)
	appConfig := defaultAppConfig()
	appConfig.Firewall.Instances = []FirewallInstanceConfig{{
		ID:            "higgstesth2",
		NetNS:         "higgstesth2",
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
	snapshot, _ := service.StateStore.Snapshot()
	if snapshot.FirewallReconcile == nil || snapshot.FirewallReconcile.Instances["higgstesth2"] == nil {
		t.Fatalf("firewall reconcile state missing after recover: %+v", snapshot.FirewallReconcile)
	}
	entry := snapshot.FirewallReconcile.Instances["higgstesth2"]
	if entry.PolicyHash == "" || entry.OwnedObjects == 0 || entry.LastRunUnix != 7000 {
		t.Fatalf("firewall reconcile entry = %+v, want hash/objects/last run", entry)
	}
}

func TestBuildFirewallDebugView(t *testing.T) {
	instances := []FirewallInstanceConfig{
		{ID: "higgstesth2", NetNS: "higgstesth2", IsHost: false, Enabled: true, Mode: firewall.ModeManaged, Backend: firewall.BackendAuto, DefaultPolicy: firewall.DefaultPolicyDrop,
			NativeHooks: firewall.NativeHooks{
				NFT:      firewall.InlineHookRules{PreInput: []string{"counter"}},
				IPTables: firewall.IPTablesInlineHooks{IPv4: firewall.InlineHookRules{PreInput: []string{"-j ACCEPT"}}},
			}},
		{ID: "host", NetNS: "host", IsHost: true, Enabled: true, Mode: firewall.ModeManaged, HostPorts: firewall.HostPortConfig{IKE: true, NATT: true}, RedirectGrace: firewall.RedirectGrace{Enabled: true}},
	}
	snapshot := &firewallReconcileState{
		Backend: "dry-run",
		Instances: map[string]*firewallInstanceReconcileStateEntry{
			"higgstesth2": {Backend: firewall.BackendNFT, Generation: 5, OwnedObjects: 10, PolicyHash: "abc123"},
		},
	}
	view := buildFirewallDebugView(nil, instances, snapshot)
	if view.Backend != "dry-run" {
		t.Fatalf("backend = %q, want dry-run", view.Backend)
	}
	if len(view.Instances) != 2 {
		t.Fatalf("instances = %d, want 2", len(view.Instances))
	}
	if got := view.Instances[0]; got.ID != "higgstesth2" || got.Generation != 5 || got.OwnedObjects != 10 || got.PolicyHash != "abc123" {
		t.Fatalf("first instance = %+v, want reconcile fields", got)
	}
	if got := view.Instances[0]; got.ResolvedBackend != firewall.BackendNFT || len(got.InlineHooks) != 2 || got.InlineHooks[0].State != "active" || got.InlineHooks[1].State != "inactive" {
		t.Fatalf("first instance inline hooks = %+v, resolved backend %q", got.InlineHooks, got.ResolvedBackend)
	}
	if got := view.Instances[1]; !got.IsHost || !got.HostIKE || !got.HostNATT || !got.RedirectGrace {
		t.Fatalf("host instance = %+v, want host flags", got)
	}
}
