package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	photonlinux "github.com/HiggsNet/photon/internal/photonlinux"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func TestNewDaemonServiceDefaultsInterval(t *testing.T) {
	service := newTestDaemonService(&Runtime{}, &stateFile{}, &syncConfigFile{}, 0)
	if service.Interval != defaultDaemonInterval {
		t.Fatalf("default interval = %s, want %s", service.Interval, defaultDaemonInterval)
	}
	if service.Sync == nil {
		t.Fatal("sync runtime is nil")
	}
}

func TestConfiguredStrongSwanRuntimeWithoutLinkGroupsHasNoIPsecDrivers(t *testing.T) {
	runtime, err := newConfiguredLinuxRuntime(ipsecConfig{Driver: ipsecDriverStrongSwan}, nil)
	if err != nil {
		t.Fatalf("newConfiguredLinuxRuntime: %v", err)
	}
	ipsecDriver, xfrmDriver := runtime.IPsecDrivers()
	if ipsecDriver != nil || xfrmDriver != nil {
		t.Fatalf("drivers = (%T, %T), want no-op without link groups", ipsecDriver, xfrmDriver)
	}
}

func TestDaemonServiceReplacesAndClosesSingleLinuxRuntime(t *testing.T) {
	service := newTestDaemonService(&Runtime{}, &stateFile{}, &syncConfigFile{}, time.Second)
	firstClosed := 0
	firstDriver := &ipsec.DryRunDriver{}
	first := photonlinux.NewRuntime(photonlinux.RuntimeOptions{
		IPsecDriver: firstDriver,
		XFRMDriver:  firstDriver,
		Close: func() error {
			firstClosed++
			return nil
		},
	})
	if err := service.installLinuxRuntime(first); err != nil {
		t.Fatalf("install first Linux runtime: %v", err)
	}
	if got, _ := service.ipsecDrivers(); got != firstDriver {
		t.Fatalf("active IPsec driver = %T, want first injected driver", got)
	}

	secondClosed := 0
	secondDriver := &ipsec.DryRunDriver{}
	second := photonlinux.NewRuntime(photonlinux.RuntimeOptions{
		IPsecDriver: secondDriver,
		XFRMDriver:  secondDriver,
		Close: func() error {
			secondClosed++
			return nil
		},
	})
	if err := service.installLinuxRuntime(second); err != nil {
		t.Fatalf("replace Linux runtime: %v", err)
	}
	if firstClosed != 1 {
		t.Fatalf("first runtime close calls = %d, want 1", firstClosed)
	}
	if got, _ := service.ipsecDrivers(); got != secondDriver {
		t.Fatalf("active IPsec driver = %T, want replacement driver", got)
	}
	if err := service.closeLinuxRuntime(); err != nil {
		t.Fatalf("close Linux runtime: %v", err)
	}
	if secondClosed != 1 {
		t.Fatalf("second runtime close calls = %d, want 1", secondClosed)
	}
	if service.linuxRuntime != nil {
		t.Fatal("Linux runtime remains installed after close")
	}
}

func TestDaemonServiceStateChangedHook(t *testing.T) {
	state := &stateFile{ManagedZone: "node-a.catofes."}
	service := newTestDaemonService(&Runtime{}, state, &syncConfigFile{}, time.Second)
	var called bool
	service.Hooks.OnStateChanged = func(got *stateFile) {
		called = true
		if got == state || got == nil || got.ManagedZone != state.ManagedZone {
			t.Fatalf("hook got unexpected detached state: %+v", got)
		}
		got.ManagedZone = "retained-mutation.invalid."
	}
	service.notifyStateChanged()
	if !called {
		t.Fatal("state changed hook was not called")
	}
	committed, _ := service.StateStore.Snapshot()
	if committed.ManagedZone != state.ManagedZone {
		t.Fatalf("hook mutation leaked into committed state: %s", committed.ManagedZone)
	}
}

func TestDaemonNotifyStateChangedDefersReconcileWhileDrainingEvents(t *testing.T) {
	state, config := buildTestNetworkState(t)
	service := newTestDaemonService(&Runtime{Config: defaultAppConfig()}, state, config, time.Second)
	service.drainingEvents = true
	var flushed []string
	service.Hooks.OnReconcileFlush = func(layer string) {
		flushed = append(flushed, layer)
	}

	service.notifyStateChanged()

	if len(flushed) != 0 {
		t.Fatalf("reconcile flushed while draining events: %v", flushed)
	}
	if !service.ipsecDirty || !service.routingDirty || !service.firewallDirty {
		t.Fatalf("dirty flags = ipsec:%v routing:%v firewall:%v, want all true", service.ipsecDirty, service.routingDirty, service.firewallDirty)
	}
}

func TestEmptyFirewallAndRoutingFlushDoNotRepublishLegacyState(t *testing.T) {
	state, config := buildTestNetworkState(t)
	service := newTestDaemonService(&Runtime{Config: defaultAppConfig()}, state, config, time.Second)
	beforeRevision := service.StateStore.Meta().Revision

	service.firewallDirty = true
	flushed, err := service.flushFirewallReconcileResult(context.Background())
	if err != nil {
		t.Fatalf("flushFirewallReconcileResult: %v", err)
	}
	if !flushed {
		t.Fatal("firewall reconcile was not flushed")
	}

	service.routingDirty = true
	flushed, err = service.flushRoutingReconcileResult(context.Background())
	if err != nil {
		t.Fatalf("flushRoutingReconcileResult: %v", err)
	}
	if !flushed {
		t.Fatal("routing reconcile was not flushed")
	}

	if revision := service.StateStore.Meta().Revision; revision != beforeRevision {
		t.Fatalf("empty reconciles changed revision from %d to %d", beforeRevision, revision)
	}
}

func TestDaemonReloadConfigReconcilesIPsecLinkGroups(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(4200, 0)
	addTestIPsecRecords(t, state.Network.Zones["node-b.catofes."], "node-b.catofes.", now, ipsec.RoleIn)
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "data")
	statePath := filepath.Join(dataDir, "photon.db")
	configPath := filepath.Join(dir, "config.yaml")
	t.Setenv("PHOTON_CONFIG", configPath)
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatalf("MkdirAll(dataDir): %v", err)
	}
	if err := os.WriteFile(configPath, []byte("data_dir: "+dataDir+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(initial config): %v", err)
	}
	appConfig := defaultAppConfig()
	appConfig.DataDir = dataDir
	appConfig.StatePath = statePath
	rt := &Runtime{
		Config:    appConfig,
		StatePath: statePath,
		Clock:     func() time.Time { return now },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	service := newTestDaemonService(rt, state, config, time.Second)

	reply := make(chan daemonEventResult, 1)
	service.Events <- daemonEvent{Type: daemonEventReloadConfig, Reply: reply}
	syncNow, shutdown, _, _, _ := service.processEvents(context.Background())
	result := <-reply
	if result.Error != nil {
		t.Fatalf("processEvents(reload initial): %v", result.Error)
	}
	if !syncNow || shutdown {
		t.Fatalf("initial reload syncNow/shutdown = %v/%v, want true/false", syncNow, shutdown)
	}
	latest := service.currentState()
	if len(latest.LinkInstances) != 0 {
		t.Fatalf("initial link instances = %+v, want none", latest.LinkInstances)
	}

	reloadedConfig := strings.Join([]string{
		"data_dir: " + dataDir,
		"ipsec:",
		"  driver: dry-run",
		"overlays:",
		"  - id: main",
		"    provider: strongswan",
		"    netns:",
		"      name: photontesth2",
		"      create: true",
		"    default_path_mode: family-redundant",
		"    address_source_order: [manual-address]",
		"    connect:",
		"      - strongswan://*.catofes.?role=in",
		"",
	}, "\n")
	if err := os.WriteFile(configPath, []byte(reloadedConfig), 0o600); err != nil {
		t.Fatalf("WriteFile(reloaded config): %v", err)
	}

	reply = make(chan daemonEventResult, 1)
	service.Events <- daemonEvent{Type: daemonEventReloadConfig, Reply: reply}
	syncNow, shutdown, _, _, _ = service.processEvents(context.Background())
	result = <-reply
	if result.Error != nil {
		t.Fatalf("processEvents(reload overlay): %v", result.Error)
	}
	if !syncNow || shutdown {
		t.Fatalf("overlay reload syncNow/shutdown = %v/%v, want true/false", syncNow, shutdown)
	}
	latest = service.currentState()
	if len(latest.LinkInstances) != 1 {
		t.Fatalf("link instances after reload = %d, want 1", len(latest.LinkInstances))
	}
	if latest.IPsecReconcile == nil || len(latest.IPsecReconcile.Actions) != 1 || latest.IPsecReconcile.Actions[0].Action != ipsec.ReconcileActionCreate {
		t.Fatalf("ipsec reconcile after reload = %+v, want create", latest.IPsecReconcile)
	}
	if len(service.Sync.App.Config.IPsec.LinkGroups) != 1 || service.Sync.Config.PeerID != config.PeerID {
		t.Fatalf("daemon config was not refreshed: app=%+v sync=%+v", service.Sync.App.Config.IPsec.LinkGroups, service.Sync.Config)
	}
}

func TestDaemonReloadConfigRejectsStatePathSwitch(t *testing.T) {
	state, config := buildTestNetworkState(t)
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	dataDir := filepath.Join(dir, "data")
	otherDir := filepath.Join(dir, "other")
	t.Setenv("PHOTON_CONFIG", configPath)
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatalf("MkdirAll(dataDir): %v", err)
	}
	if err := os.WriteFile(configPath, []byte("data_dir: "+otherDir+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(config): %v", err)
	}
	rt := &Runtime{
		Config:    defaultAppConfig(),
		StatePath: filepath.Join(dataDir, "photon.db"),
		Clock:     func() time.Time { return time.Unix(4300, 0) },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	service := newTestDaemonService(rt, state, config, time.Second)

	result, syncNow, shutdown := service.handleEvent(daemonEvent{Type: daemonEventReloadConfig})
	if result.Error == nil || !strings.Contains(result.Error.Error(), "restart daemon to switch state") {
		t.Fatalf("reload error = %v, want state path switch rejection", result.Error)
	}
	if syncNow || shutdown {
		t.Fatalf("syncNow/shutdown = %v/%v, want false/false", syncNow, shutdown)
	}
}

func TestRootCommandIncludesDaemon(t *testing.T) {
	for _, command := range rootCommand().Commands {
		if command.Name == "daemon" {
			return
		}
	}
	t.Fatal("root command does not include daemon")
}
