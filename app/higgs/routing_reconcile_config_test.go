package main

import (
	"context"
	"github.com/Catofes/higgs/pkg/routing/bird"
	"github.com/Catofes/higgs/pkg/transport/ipsec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestReconcileRoutingGeneratesConfig(t *testing.T) {
	state, config := buildTestNetworkStateForRouting(t)
	now := time.Unix(4000, 0)

	appConfig := defaultAppConfig()
	appConfig.DataDir = t.TempDir()
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{{
		ID:              "main",
		Provider:        ipsec.ProviderStrongSwan,
		NetNS:           ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: "higgstesth2", Create: true},
		DefaultPathMode: ipsec.PathModeFamilyRedundant,
	}}
	appConfig.Netns = netnsConfig{Names: map[string]ipsec.NetNSSpec{"higgstesth2": {Kind: ipsec.NetNSName, Name: "higgstesth2", Create: true}}}
	appConfig.Routing, _ = parseRoutingConfigInstances([]routingInstanceYAML{{ID: "main", NetNS: "higgstesth2", Enabled: boolPtr(true), Mode: ipsec.RoutingModeManaged}}, appConfig.Netns, appConfig.DataDir)

	rt := &Runtime{
		Config:    appConfig,
		StatePath: filepath.Join(t.TempDir(), "higgs.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}

	pm := &fakeBirdProcessManager{running: false}
	client := &fakeBirdClient{}
	service := newDaemonService(rt, state, config, time.Second)
	service.birdProcessManager = pm
	service.birdClientFactory = func(socketPath string, timeout time.Duration) birdClient {
		return client
	}

	if err := service.reconcileRouting(context.Background()); err != nil {
		t.Fatalf("reconcileRouting: %v", err)
	}

	latest, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if len(latest.BirdInstances) != 1 {
		t.Fatalf("BirdInstances len = %d, want 1", len(latest.BirdInstances))
	}
	inst := latest.BirdInstances["higgstesth2"]
	if inst == nil {
		t.Fatalf("missing bird instance state for netns higgstesth2")
	}
	if inst.ConfigPath == "" {
		t.Fatalf("ConfigPath is empty")
	}
	if inst.LastConfigHash == "" {
		t.Fatalf("LastConfigHash is empty")
	}
	if inst.State != birdInstanceStateRunning {
		t.Fatalf("State = %q, want running", inst.State)
	}
	if !pm.started {
		t.Fatalf("BIRD process manager Start was not called")
	}

	configBytes, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	_ = configBytes

	cfg, err := readFileString(inst.ConfigPath)
	if err != nil {
		t.Fatalf("read generated config: %v", err)
	}

	// Import filter should contain the IPAM assignment prefixes (authorized route
	// space) for both local and remote zones.
	if !strings.Contains(cfg, "10.0.0.0/16") {
		t.Errorf("import filter missing local assignment prefix 10.0.0.0/16")
	}
	if !strings.Contains(cfg, "10.1.0.0/24") {
		t.Errorf("import filter missing remote route prefix 10.1.0.0/24")
	}

	// Export filter should contain only the local prefix.
	importIdx := strings.Index(cfg, "filter higgs_import_higgstesth2")
	exportIdx := strings.Index(cfg, "filter higgs_export_higgstesth2")
	if importIdx == -1 || exportIdx == -1 {
		t.Fatalf("missing import/export filters")
	}
	exportFilter := cfg[exportIdx:]
	if !strings.Contains(exportFilter, "10.0.0.0/24") {
		t.Errorf("export filter missing local prefix 10.0.0.0/24")
	}
	if strings.Contains(exportFilter, "10.1.0.0/24") {
		t.Errorf("export filter should not contain remote prefix 10.1.0.0/24")
	}
	if !strings.Contains(cfg, `interface "hgs*" {`) {
		t.Errorf("babel interface should use configured XFRM interface pattern:\n%s", cfg)
	}

	// BIRD process should have been started with the generated config path.
	if pm.startSpec.ConfigPath != inst.ConfigPath {
		t.Errorf("Start config path = %q, want %q", pm.startSpec.ConfigPath, inst.ConfigPath)
	}
}

func TestReconcileRoutingConfigChangeUsesFullBirdConfigure(t *testing.T) {
	state, config := buildTestNetworkStateForRouting(t)
	now := time.Unix(4000, 0)

	appConfig := defaultAppConfig()
	appConfig.DataDir = t.TempDir()
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{{
		ID:              "main",
		Provider:        ipsec.ProviderStrongSwan,
		NetNS:           ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: "higgstesth2", Create: true},
		DefaultPathMode: ipsec.PathModeFamilyRedundant,
	}}
	appConfig.Netns = netnsConfig{Names: map[string]ipsec.NetNSSpec{"higgstesth2": {Kind: ipsec.NetNSName, Name: "higgstesth2", Create: true}}}
	appConfig.Routing, _ = parseRoutingConfigInstances([]routingInstanceYAML{{ID: "main", NetNS: "higgstesth2", Enabled: boolPtr(true), Mode: ipsec.RoutingModeManaged}}, appConfig.Netns, appConfig.DataDir)

	rt := &Runtime{
		Config:    appConfig,
		StatePath: filepath.Join(t.TempDir(), "higgs.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}

	pm := &fakeBirdProcessManager{running: true}
	client := &fakeBirdClient{}
	service := newDaemonService(rt, state, config, time.Second)
	service.birdProcessManager = pm
	service.birdClientFactory = func(socketPath string, timeout time.Duration) birdClient {
		return client
	}

	if err := service.reconcileRouting(context.Background()); err != nil {
		t.Fatalf("reconcileRouting: %v", err)
	}
	if pm.started {
		t.Fatalf("running managed BIRD should be reconfigured, not restarted")
	}
	if client.configureCalls != 1 {
		t.Fatalf("Configure calls = %d, want 1", client.configureCalls)
	}
	if client.configureSoftCalls != 0 {
		t.Fatalf("ConfigureSoft calls = %d, want 0", client.configureSoftCalls)
	}
	if client.configurePath == "" {
		t.Fatalf("Configure path is empty")
	}
}

func TestReconcileRoutingForceReloadUsesFullBirdConfigureWhenHashUnchanged(t *testing.T) {
	state, config := buildTestNetworkStateForRouting(t)
	now := time.Unix(4000, 0)

	appConfig := defaultAppConfig()
	appConfig.DataDir = t.TempDir()
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{{
		ID:              "main",
		Provider:        ipsec.ProviderStrongSwan,
		NetNS:           ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: "higgstesth2", Create: true},
		DefaultPathMode: ipsec.PathModeFamilyRedundant,
	}}
	appConfig.Netns = netnsConfig{Names: map[string]ipsec.NetNSSpec{"higgstesth2": {Kind: ipsec.NetNSName, Name: "higgstesth2", Create: true}}}
	appConfig.Routing, _ = parseRoutingConfigInstances([]routingInstanceYAML{{ID: "main", NetNS: "higgstesth2", Enabled: boolPtr(true), Mode: ipsec.RoutingModeManaged}}, appConfig.Netns, appConfig.DataDir)

	rt := &Runtime{
		Config:    appConfig,
		StatePath: filepath.Join(t.TempDir(), "higgs.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}

	pm := &fakeBirdProcessManager{running: false}
	client := &fakeBirdClient{}
	service := newDaemonService(rt, state, config, time.Second)
	service.birdProcessManager = pm
	service.birdClientFactory = func(socketPath string, timeout time.Duration) birdClient {
		return client
	}
	if err := service.reconcileRouting(context.Background()); err != nil {
		t.Fatalf("initial reconcileRouting: %v", err)
	}

	pm.running = true
	pm.started = false
	client.configureCalls = 0
	client.configureSoftCalls = 0
	service.routingForceReload = true
	if err := service.reconcileRouting(context.Background()); err != nil {
		t.Fatalf("force reconcileRouting: %v", err)
	}
	if pm.started {
		t.Fatalf("force reload should reconfigure running BIRD, not restart it")
	}
	if client.configureCalls != 1 {
		t.Fatalf("Configure calls = %d, want 1", client.configureCalls)
	}
	if client.configureSoftCalls != 0 {
		t.Fatalf("ConfigureSoft calls = %d, want 0", client.configureSoftCalls)
	}
}

func TestReconcileRoutingMergesBirdInstanceWhenRevisionChanged(t *testing.T) {
	state, config := buildTestNetworkStateForRouting(t)
	now := time.Unix(4010, 0)

	appConfig := defaultAppConfig()
	appConfig.DataDir = t.TempDir()
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{{
		ID:              "main",
		Provider:        ipsec.ProviderStrongSwan,
		NetNS:           ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: "higgstesth2", Create: true},
		DefaultPathMode: ipsec.PathModeFamilyRedundant,
	}}
	appConfig.Netns = netnsConfig{Names: map[string]ipsec.NetNSSpec{"higgstesth2": {Kind: ipsec.NetNSName, Name: "higgstesth2", Create: true}}}
	appConfig.Routing, _ = parseRoutingConfigInstances([]routingInstanceYAML{{ID: "main", NetNS: "higgstesth2", Enabled: boolPtr(true), Mode: ipsec.RoutingModeManaged}}, appConfig.Netns, appConfig.DataDir)

	rt := &Runtime{
		Config:    appConfig,
		StatePath: filepath.Join(t.TempDir(), "higgs.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}

	pm := &fakeBirdProcessManager{running: false}
	service := newDaemonService(rt, state, config, time.Second)
	pm.onStart = func(bird.BirdInstanceSpec) {
		if _, err := service.StateStore.Update(func(state *stateFile) error {
			state.IdentityKeyPath = "newer-routing-revision"
			return nil
		}); err != nil {
			t.Fatalf("advance state revision during routing apply: %v", err)
		}
	}
	service.birdProcessManager = pm
	service.birdClientFactory = func(socketPath string, timeout time.Duration) birdClient {
		return &fakeBirdClient{}
	}

	if err := service.reconcileRouting(context.Background()); err != nil {
		t.Fatalf("reconcileRouting: %v", err)
	}
	if service.routingDirty {
		t.Fatal("routingDirty = true, want token-compatible BIRD instance merge to complete")
	}
	snapshot, _ := service.StateStore.Snapshot()
	if snapshot.IdentityKeyPath != "newer-routing-revision" {
		t.Fatalf("identity key path = %q, want newer revision preserved", snapshot.IdentityKeyPath)
	}
	if len(snapshot.BirdInstances) != 1 || snapshot.BirdInstances["higgstesth2"] == nil {
		t.Fatalf("bird instances = %+v, want merged higgstesth2 instance", snapshot.BirdInstances)
	}
	if snapshot.RoutingReconcile == nil || snapshot.RoutingReconcile.LastError != "" {
		t.Fatalf("routing reconcile = %+v, want successful summary", snapshot.RoutingReconcile)
	}
}

func TestReconcileRoutingExternalModeOnlyStatus(t *testing.T) {
	state, config := buildTestNetworkStateForRouting(t)
	now := time.Unix(4000, 0)

	appConfig := defaultAppConfig()
	appConfig.DataDir = t.TempDir()
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{{
		ID:              "main",
		Provider:        ipsec.ProviderStrongSwan,
		NetNS:           ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: "higgstesth2", Create: true},
		DefaultPathMode: ipsec.PathModeFamilyRedundant,
	}}
	appConfig.Netns = netnsConfig{Names: map[string]ipsec.NetNSSpec{"higgstesth2": {Kind: ipsec.NetNSName, Name: "higgstesth2", Create: true}}}
	appConfig.Netns = netnsConfig{Names: map[string]ipsec.NetNSSpec{"higgstesth2": {Kind: ipsec.NetNSName, Name: "higgstesth2", Create: true}}}
	appConfig.Routing, _ = parseRoutingConfigInstances([]routingInstanceYAML{{ID: "main", NetNS: "higgstesth2", Enabled: boolPtr(true), Mode: ipsec.RoutingModeExternal}}, appConfig.Netns, appConfig.DataDir)

	rt := &Runtime{
		Config:    appConfig,
		StatePath: filepath.Join(t.TempDir(), "higgs.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}

	client := &fakeBirdClient{}
	service := newDaemonService(rt, state, config, time.Second)
	service.birdClientFactory = func(socketPath string, timeout time.Duration) birdClient {
		return client
	}

	if err := service.reconcileRouting(context.Background()); err != nil {
		t.Fatalf("reconcileRouting: %v", err)
	}

	if !client.statusCalled {
		t.Fatalf("external mode should call client.Status")
	}

	latest, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	inst := latest.BirdInstances["higgstesth2"]
	if inst == nil || inst.State != birdInstanceStateRunning {
		t.Fatalf("external instance state = %+v, want running", inst)
	}
}

func TestReconcileRoutingSkipsWhenDisabled(t *testing.T) {
	state, config := buildTestNetworkStateForRouting(t)
	now := time.Unix(4000, 0)

	appConfig := defaultAppConfig()
	appConfig.DataDir = t.TempDir()
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{{
		ID:              "main",
		Provider:        ipsec.ProviderStrongSwan,
		NetNS:           ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: "higgstesth2", Create: true},
		DefaultPathMode: ipsec.PathModeFamilyRedundant,
	}}

	rt := &Runtime{
		Config:    appConfig,
		StatePath: filepath.Join(t.TempDir(), "higgs.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}

	service := newDaemonService(rt, state, config, time.Second)
	if err := service.reconcileRouting(context.Background()); err != nil {
		t.Fatalf("reconcileRouting: %v", err)
	}

	latest, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if len(latest.BirdInstances) != 0 {
		t.Fatalf("BirdInstances len = %d, want 0", len(latest.BirdInstances))
	}
}

func TestRoutingReconcileInterval(t *testing.T) {
	appConfig := defaultAppConfig()
	appConfig.Routing = routingConfig{Instances: []RoutingInstance{
		{ID: "a", NetNS: "higgstesth2", Enabled: true, Mode: ipsec.RoutingModeManaged},
	}}
	service := newDaemonService(&Runtime{Config: appConfig}, &stateFile{}, &syncConfigFile{}, time.Second)
	if got := service.routingReconcileInterval(); got != 30*time.Second {
		t.Fatalf("routingReconcileInterval = %s, want 30s", got)
	}
}

func TestRoutingReconcileIntervalZeroWhenDisabled(t *testing.T) {
	appConfig := defaultAppConfig()
	appConfig.Routing = routingConfig{Instances: []RoutingInstance{
		{ID: "a", NetNS: "higgstesth2", Enabled: false, Mode: ipsec.RoutingModeManaged},
	}}
	service := newDaemonService(&Runtime{Config: appConfig}, &stateFile{}, &syncConfigFile{}, time.Second)
	if got := service.routingReconcileInterval(); got != 0 {
		t.Fatalf("routingReconcileInterval = %s, want 0", got)
	}
}
