package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Catofes/higgs/pkg/core/zone"
	higgscrypto "github.com/Catofes/higgs/pkg/crypto"
	"github.com/Catofes/higgs/pkg/health"
	"github.com/Catofes/higgs/pkg/routing"
	"github.com/Catofes/higgs/pkg/routing/bird"
	"github.com/Catofes/higgs/pkg/transport/ipsec"
)

type successfulHealthProber struct{}

func (successfulHealthProber) Probe(ctx context.Context, target health.ProbeTarget, cfg health.ProbeConfig) health.ProbeResult {
	return health.ProbeResult{InstanceID: target.InstanceID, RTT: 5 * time.Millisecond, Success: true}
}

func (successfulHealthProber) Type() string { return health.ProbeTypeICMP }

type fakeBirdProcessManager struct {
	started   bool
	startSpec bird.BirdInstanceSpec
	startErr  error
	stopped   bool
	stopSpec  bird.BirdInstanceSpec
	stopErr   error
	running   bool
}

func (f *fakeBirdProcessManager) Start(ctx context.Context, spec bird.BirdInstanceSpec) error {
	f.started = true
	f.startSpec = spec
	return f.startErr
}

func (f *fakeBirdProcessManager) Stop(ctx context.Context, spec bird.BirdInstanceSpec) error {
	f.stopped = true
	f.stopSpec = spec
	f.running = false
	return f.stopErr
}

func (f *fakeBirdProcessManager) IsRunning(ctx context.Context) bool {
	return f.running
}

type fakeBirdClient struct {
	statusErr    error
	status       *bird.BirdObservedState
	configureErr error
	statusCalled bool
}

func (f *fakeBirdClient) Status(ctx context.Context) (*bird.BirdObservedState, error) {
	f.statusCalled = true
	if f.status != nil {
		return f.status, f.statusErr
	}
	return &bird.BirdObservedState{}, f.statusErr
}

func (f *fakeBirdClient) Configure(ctx context.Context, path string) error {
	return f.configureErr
}

func (f *fakeBirdClient) ConfigureSoft(ctx context.Context, path string) error {
	return f.configureErr
}

func TestReconcileRoutingGeneratesConfig(t *testing.T) {
	state, config := buildTestNetworkStateForRouting(t)
	now := time.Unix(4000, 0)

	appConfig := defaultAppConfig()
	appConfig.DataDir = t.TempDir()
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{{
		ID:              "main",
		Provider:        ipsec.ProviderStrongSwan,
		NetNS:           ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: "h2", Create: true},
		DefaultPathMode: ipsec.PathModeFamilyRedundant,
	}}
	appConfig.Netns = netnsConfig{Names: map[string]ipsec.NetNSSpec{"h2": {Kind: ipsec.NetNSName, Name: "h2", Create: true}}}
	appConfig.Routing, _ = parseRoutingConfigInstances([]routingInstanceYAML{{ID: "main", NetNS: "h2", Enabled: boolPtr(true), Mode: ipsec.RoutingModeManaged}}, appConfig.Netns, appConfig.DataDir)

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
	inst := latest.BirdInstances["h2"]
	if inst == nil {
		t.Fatalf("missing bird instance state for netns h2")
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
	if !strings.Contains(cfg, "10.0.0.0/16+") {
		t.Errorf("import filter missing local assignment prefix 10.0.0.0/16")
	}
	if !strings.Contains(cfg, "10.1.0.0/16+") {
		t.Errorf("import filter missing remote assignment prefix 10.1.0.0/16")
	}

	// Export filter should contain only the local prefix.
	importIdx := strings.Index(cfg, "filter higgs_import_h2")
	exportIdx := strings.Index(cfg, "filter higgs_export_h2")
	if importIdx == -1 || exportIdx == -1 {
		t.Fatalf("missing import/export filters")
	}
	exportFilter := cfg[exportIdx:]
	if !strings.Contains(exportFilter, "10.0.0.0/24+") {
		t.Errorf("export filter missing local prefix 10.0.0.0/24")
	}
	if strings.Contains(exportFilter, "10.1.0.0/24+") {
		t.Errorf("export filter should not contain remote prefix 10.1.0.0/24")
	}

	// BIRD process should have been started with the generated config path.
	if pm.startSpec.ConfigPath != inst.ConfigPath {
		t.Errorf("Start config path = %q, want %q", pm.startSpec.ConfigPath, inst.ConfigPath)
	}
}

func TestRoutingDryRunSmoke(t *testing.T) {
	state, config, _ := buildDryRunSmokeNetworkState(t)
	now := time.Unix(4000, 0)

	// Verify the route set authorizes the expected announcements without errors.
	ars, err := routing.BuildAuthorizedRouteSet(state.Network, now)
	if err != nil {
		t.Fatalf("BuildAuthorizedRouteSet: %v", err)
	}
	if len(ars.Errors) > 0 {
		t.Fatalf("unexpected authorization errors: %+v", ars.Errors)
	}

	appConfig := defaultAppConfig()
	appConfig.DataDir = t.TempDir()
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{{
		ID:              "ipsec-main",
		Provider:        ipsec.ProviderStrongSwan,
		NetNS:           ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: "h2", Create: true},
		DefaultPathMode: ipsec.PathModeFamilyRedundant,
	}}
	appConfig.Netns = netnsConfig{Names: map[string]ipsec.NetNSSpec{"h2": {Kind: ipsec.NetNSName, Name: "h2", Create: true}}}
	appConfig.Routing, _ = parseRoutingConfigInstances([]routingInstanceYAML{{ID: "ipsec-main", NetNS: "h2", Enabled: boolPtr(true), Mode: ipsec.RoutingModeManaged}}, appConfig.Netns, appConfig.DataDir)

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
	inst := latest.BirdInstances["h2"]
	if inst == nil {
		t.Fatalf("missing bird instance state for netns h2")
	}
	if inst.State == birdInstanceStateError {
		t.Fatalf("bird instance state is error: %s", inst.LastError)
	}
	if inst.ConfigPath == "" {
		t.Fatalf("ConfigPath is empty")
	}

	cfg, err := readFileString(inst.ConfigPath)
	if err != nil {
		t.Fatalf("read generated config: %v", err)
	}

	importIdx := strings.Index(cfg, "filter higgs_import_h2")
	exportIdx := strings.Index(cfg, "filter higgs_export_h2")
	if importIdx == -1 || exportIdx == -1 {
		t.Fatalf("missing import/export filters")
	}
	importFilter := cfg[importIdx:exportIdx]
	exportFilter := cfg[exportIdx:]

	// Import filter should contain the authorized IPAM assignment prefixes.
	if !strings.Contains(importFilter, "10.0.0.0/16+") {
		t.Errorf("import filter missing authorized prefix 10.0.0.0/16+")
	}
	if !strings.Contains(importFilter, "10.1.0.0/16+") {
		t.Errorf("import filter missing authorized prefix 10.1.0.0/16+")
	}

	// Export filter should contain only the local announcement.
	if !strings.Contains(exportFilter, "10.0.1.0/24+") {
		t.Errorf("export filter missing local prefix 10.0.1.0/24+")
	}
	if strings.Contains(exportFilter, "10.1.1.0/24") {
		t.Errorf("export filter should not contain remote prefix 10.1.1.0/24")
	}

	// The reconcile run itself should not have recorded any error.
	if latest.RoutingReconcile != nil && latest.RoutingReconcile.LastError != "" {
		t.Errorf("unexpected routing reconcile error: %s", latest.RoutingReconcile.LastError)
	}
}

func TestIPAMRoutingSmoke(t *testing.T) {
	_, config, signers, rt := buildIPAMRoutingSmokeNetworkState(t)
	now := rt.Now()

	// Publish pool and assignment as the catofes. administrator.
	if err := runWithZonePrivateKey(rt, signers["catofes."], func() error {
		if err := createIPAMPoolWithRuntime(rt, "catofes.", "10.0.0.0/16", "catofes."); err != nil {
			return err
		}
		return assignIPAMWithRuntime(rt, "catofes.", "10.0.0.0/16", "node-a.catofes.", false)
	}); err != nil {
		t.Fatalf("catofes IPAM writes: %v", err)
	}

	// Announce a route as node-a.catofes.
	if err := runWithZonePrivateKey(rt, signers["node-a.catofes."], func() error {
		return announceRouteWithRuntime(rt, "node-a.catofes.", "10.0.1.0/24")
	}); err != nil {
		t.Fatalf("node-a route announce: %v", err)
	}

	// Reload state to see records written by the CLI functions.
	state, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState after CLI writes: %v", err)
	}

	// Verify the authorized route set before reconcile.
	ars, err := routing.BuildAuthorizedRouteSet(state.Network, now)
	if err != nil {
		t.Fatalf("BuildAuthorizedRouteSet: %v", err)
	}
	if len(ars.Errors) > 0 {
		t.Fatalf("unexpected authorization errors: %+v", ars.Errors)
	}
	if _, ok := ars.Announced["node-a.catofes."][netip.MustParsePrefix("10.0.1.0/24")]; !ok {
		t.Fatalf("expected 10.0.1.0/24 to be authorized for node-a.catofes.")
	}

	// Reconcile routing and verify BIRD config import/export filters.
	pm := &fakeBirdProcessManager{running: false}
	service := newDaemonService(rt, state, config, time.Second)
	service.birdProcessManager = pm
	service.birdClientFactory = func(socketPath string, timeout time.Duration) birdClient {
		return &fakeBirdClient{}
	}

	if err := service.reconcileRouting(context.Background()); err != nil {
		t.Fatalf("reconcileRouting: %v", err)
	}

	latest, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	inst := latest.BirdInstances["h2"]
	if inst == nil || inst.ConfigPath == "" {
		t.Fatalf("missing bird instance state or config path")
	}

	cfg, err := readFileString(inst.ConfigPath)
	if err != nil {
		t.Fatalf("read generated config: %v", err)
	}

	importIdx := strings.Index(cfg, "filter higgs_import_h2")
	exportIdx := strings.Index(cfg, "filter higgs_export_h2")
	if importIdx == -1 || exportIdx == -1 {
		t.Fatalf("missing import/export filters")
	}
	importFilter := cfg[importIdx:exportIdx]
	exportFilter := cfg[exportIdx:]

	if !strings.Contains(importFilter, "10.0.0.0/16+") {
		t.Errorf("import filter missing authorized assignment prefix 10.0.0.0/16+")
	}
	if !strings.Contains(exportFilter, "10.0.1.0/24+") {
		t.Errorf("export filter missing local announcement prefix 10.0.1.0/24+")
	}

	_ = signers
}

func TestAutoAnnounceAssignedIPsRoutingSmoke(t *testing.T) {
	_, config, signers, rt := buildIPAMRoutingSmokeNetworkState(t)
	rt.Config.IPAM.AutoAnnounceAssignedIPs = true
	now := rt.Now()

	// Publish pool and assignment as the catofes. administrator.
	// The assignment is for node-a.catofes., so auto-announce should pick it up.
	if err := runWithZonePrivateKey(rt, signers["catofes."], func() error {
		if err := createIPAMPoolWithRuntime(rt, "catofes.", "10.0.0.0/16", "catofes."); err != nil {
			return err
		}
		return assignIPAMWithRuntime(rt, "catofes.", "10.0.0.0/24", "node-a.catofes.", false)
	}); err != nil {
		t.Fatalf("catofes IPAM writes: %v", err)
	}

	// Reload state to see records written by the CLI functions.
	state, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState after CLI writes: %v", err)
	}
	// Restore the managed-zone signing key; runWithZonePrivateKey left the
	// state with the catofes. administrator key.
	state.ZonePrivateKey = signers["node-a.catofes."]

	// Reconcile routing and let auto-announce publish the route.
	pm := &fakeBirdProcessManager{running: false}
	service := newDaemonService(rt, state, config, time.Second)
	service.birdProcessManager = pm
	service.birdClientFactory = func(socketPath string, timeout time.Duration) birdClient {
		return &fakeBirdClient{}
	}

	if err := service.reconcileRouting(context.Background()); err != nil {
		t.Fatalf("reconcileRouting: %v", err)
	}

	// Verify the route announcement record was auto-published.
	key, _ := routing.NormalizeRouteAnnouncementKey("10.0.0.0/24")
	rec := service.Sync.State.Network.Zones["node-a.catofes."].Records[key]
	if rec == nil {
		t.Fatalf("expected auto-published announcement for 10.0.0.0/24")
	}
	ann, err := routing.ParseRouteAnnouncementRecord(rec)
	if err != nil {
		t.Fatalf("ParseRouteAnnouncementRecord: %v", err)
	}
	if !ann.Active {
		t.Fatalf("expected active auto-published announcement")
	}
	if ann.Prefix != "10.0.0.0/24" {
		t.Fatalf("expected prefix 10.0.0.0/24, got %s", ann.Prefix)
	}

	// Verify the BIRD export filter includes the auto-announced prefix.
	latest, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	inst := latest.BirdInstances["h2"]
	if inst == nil || inst.ConfigPath == "" {
		t.Fatalf("missing bird instance state or config path")
	}
	cfg, err := readFileString(inst.ConfigPath)
	if err != nil {
		t.Fatalf("read generated config: %v", err)
	}
	exportIdx := strings.Index(cfg, "filter higgs_export_h2")
	if exportIdx == -1 {
		t.Fatalf("missing export filter")
	}
	exportFilter := cfg[exportIdx:]
	if !strings.Contains(exportFilter, "10.0.0.0/24+") {
		t.Errorf("export filter missing auto-announced prefix 10.0.0.0/24+")
	}

	_ = now
}

func TestRoutingDryRunSmokeRevokeAssignment(t *testing.T) {
	state, config, signers := buildDryRunSmokeNetworkState(t)
	now := time.Unix(4000, 0)

	// Initial authorized route set should authorize node-a's announcement.
	ars, err := routing.BuildAuthorizedRouteSet(state.Network, now)
	if err != nil {
		t.Fatalf("BuildAuthorizedRouteSet: %v", err)
	}
	if len(ars.Errors) > 0 {
		t.Fatalf("unexpected authorization errors: %+v", ars.Errors)
	}
	if _, ok := ars.Announced["node-a.catofes."][netip.MustParsePrefix("10.0.1.0/24")]; !ok {
		t.Fatalf("expected 10.0.1.0/24 to be authorized for node-a.catofes.")
	}
	if _, ok := ars.Assignments[netip.MustParsePrefix("10.0.0.0/16")]; !ok {
		t.Fatalf("expected 10.0.0.0/16 assignment to be present")
	}

	// Revoke the assignment covering node-a's announcement.
	revokeRouteAssignment(t, state, "catofes.", "10.0.0.0/16", "node-a.catofes.", now.Add(time.Second), signers["catofes."])

	// After revocation the assignment and its authorized announcement should disappear.
	ars, err = routing.BuildAuthorizedRouteSet(state.Network, now.Add(time.Second))
	if err != nil {
		t.Fatalf("BuildAuthorizedRouteSet after revoke: %v", err)
	}
	if _, ok := ars.Announced["node-a.catofes."][netip.MustParsePrefix("10.0.1.0/24")]; ok {
		t.Fatalf("expected 10.0.1.0/24 to be removed from authorized announcements after assignment revoke")
	}
	if _, ok := ars.Assignments[netip.MustParsePrefix("10.0.0.0/16")]; ok {
		t.Fatalf("expected 10.0.0.0/16 assignment to be removed after revoke")
	}
	foundErr := false
	for _, e := range ars.Errors {
		if e.Code == "route_unauthorized_no_assignment" && e.Prefix == netip.MustParsePrefix("10.0.1.0/24") {
			foundErr = true
			break
		}
	}
	if !foundErr {
		t.Fatalf("expected route_unauthorized_no_assignment error for 10.0.1.0/24, got %+v", ars.Errors)
	}

	// Reconcile routing again and verify the export filter no longer contains the revoked prefix.
	appConfig := defaultAppConfig()
	appConfig.DataDir = t.TempDir()
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{{
		ID:              "ipsec-main",
		Provider:        ipsec.ProviderStrongSwan,
		NetNS:           ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: "h2", Create: true},
		DefaultPathMode: ipsec.PathModeFamilyRedundant,
	}}
	appConfig.Netns = netnsConfig{Names: map[string]ipsec.NetNSSpec{"h2": {Kind: ipsec.NetNSName, Name: "h2", Create: true}}}
	appConfig.Routing, _ = parseRoutingConfigInstances([]routingInstanceYAML{{ID: "ipsec-main", NetNS: "h2", Enabled: boolPtr(true), Mode: ipsec.RoutingModeManaged}}, appConfig.Netns, appConfig.DataDir)

	rt := &Runtime{
		Config:    appConfig,
		StatePath: filepath.Join(t.TempDir(), "higgs.db"),
		Clock:     func() time.Time { return now.Add(time.Second) },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}

	pm := &fakeBirdProcessManager{running: false}
	service := newDaemonService(rt, state, config, time.Second)
	service.birdProcessManager = pm
	service.birdClientFactory = func(socketPath string, timeout time.Duration) birdClient {
		return &fakeBirdClient{}
	}

	if err := service.reconcileRouting(context.Background()); err != nil {
		t.Fatalf("reconcileRouting: %v", err)
	}

	latest, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	inst := latest.BirdInstances["h2"]
	if inst == nil || inst.ConfigPath == "" {
		t.Fatalf("missing bird instance state or config path")
	}

	cfg, err := readFileString(inst.ConfigPath)
	if err != nil {
		t.Fatalf("read generated config: %v", err)
	}

	importIdx := strings.Index(cfg, "filter higgs_import_h2")
	exportIdx := strings.Index(cfg, "filter higgs_export_h2")
	if importIdx == -1 || exportIdx == -1 {
		t.Fatalf("missing import/export filters")
	}
	importFilter := cfg[importIdx:exportIdx]
	exportFilter := cfg[exportIdx:]

	if !strings.Contains(importFilter, "10.1.0.0/16+") {
		t.Errorf("import filter missing remaining authorized prefix 10.1.0.0/16+")
	}
	if strings.Contains(importFilter, "10.0.0.0/16+") {
		t.Errorf("import filter should not contain revoked prefix 10.0.0.0/16+")
	}
	if strings.Contains(exportFilter, "10.0.1.0/24+") {
		t.Errorf("export filter should not contain revoked local prefix 10.0.1.0/24+")
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
		NetNS:           ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: "h2", Create: true},
		DefaultPathMode: ipsec.PathModeFamilyRedundant,
	}}
	appConfig.Netns = netnsConfig{Names: map[string]ipsec.NetNSSpec{"h2": {Kind: ipsec.NetNSName, Name: "h2", Create: true}}}
	appConfig.Netns = netnsConfig{Names: map[string]ipsec.NetNSSpec{"h2": {Kind: ipsec.NetNSName, Name: "h2", Create: true}}}
	appConfig.Routing, _ = parseRoutingConfigInstances([]routingInstanceYAML{{ID: "main", NetNS: "h2", Enabled: boolPtr(true), Mode: ipsec.RoutingModeExternal}}, appConfig.Netns, appConfig.DataDir)

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
	inst := latest.BirdInstances["h2"]
	if inst == nil || inst.State != birdInstanceStateRunning {
		t.Fatalf("external instance state = %+v, want running", inst)
	}
}

func TestReconcileRoutingFeedsBirdObservationToRotateCutoverGate(t *testing.T) {
	state, config := buildTestNetworkStateForRouting(t)
	now := time.Unix(4000, 0)

	appConfig := defaultAppConfig()
	appConfig.DataDir = t.TempDir()
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{{
		ID:              "main",
		Provider:        ipsec.ProviderStrongSwan,
		NetNS:           ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: "h2", Create: true},
		DefaultPathMode: ipsec.PathModeFamilyRedundant,
	}}
	appConfig.Netns = netnsConfig{Names: map[string]ipsec.NetNSSpec{"h2": {Kind: ipsec.NetNSName, Name: "h2", Create: true}}}
	appConfig.Routing, _ = parseRoutingConfigInstances([]routingInstanceYAML{{ID: "main", NetNS: "h2", Enabled: boolPtr(true), Mode: ipsec.RoutingModeManaged}}, appConfig.Netns, appConfig.DataDir)

	state.LinkInstances = map[string]linkInstanceState{
		"link-1": {
			ID:                  "link-1",
			GroupID:             "main",
			ActualState:         "up",
			InterfaceName:       "hgs-old",
			StagedInterfaceName: "hgs-new",
		},
	}

	rt := &Runtime{
		Config:    appConfig,
		StatePath: filepath.Join(t.TempDir(), "higgs.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}

	manager := health.NewManager(
		health.ProbeConfig{Interval: -time.Second, Timeout: 100 * time.Millisecond, Burst: 1, LossWindow: 5, MaxConcurrent: 2},
		health.DefaultHysteresisConfig(),
		successfulHealthProber{},
	)
	manager.UpsertTarget(health.ProbeTarget{
		ProbeID:        healthProbeID("link-1", "staged"),
		InstanceID:     "link-1",
		ProbeRole:      "staged",
		InterfaceName:  "hgs-new",
		PeerTunnelAddr: netip.MustParseAddr("10.0.0.2"),
		State:          "up",
		Staged:         true,
	}, now)
	if dispatched := manager.Tick(context.Background(), now); dispatched != 1 {
		t.Fatalf("health probes dispatched = %d, want 1", dispatched)
	}

	client := &fakeBirdClient{status: &bird.BirdObservedState{
		Neighbors: []bird.BirdNeighbor{{Interface: "hgs-new", Metric: 96}},
		Routes:    []bird.BirdRoute{{Iface: "hgs-new", Protocol: "babel1", Selected: false, Metric: 96}},
	}}
	service := newDaemonService(rt, state, config, time.Second)
	service.health = manager
	service.birdProcessManager = &fakeBirdProcessManager{running: false}
	service.birdClientFactory = func(socketPath string, timeout time.Duration) birdClient {
		return client
	}

	if err := service.reconcileRouting(context.Background()); err != nil {
		t.Fatalf("reconcileRouting without selected route: %v", err)
	}
	if ready := service.ipsecRotateCutoverReady()["link-1"]; ready {
		t.Fatalf("cutover should stay blocked until BIRD has a selected staged route")
	}

	client.status = &bird.BirdObservedState{
		Neighbors: []bird.BirdNeighbor{{Interface: "hgs-new", Metric: 96}},
		Routes:    []bird.BirdRoute{{Iface: "hgs-new", Protocol: "babel1", Selected: true, Metric: 96}},
	}
	if err := service.reconcileRouting(context.Background()); err != nil {
		t.Fatalf("reconcileRouting with selected route: %v", err)
	}
	if ready := service.ipsecRotateCutoverReady()["link-1"]; !ready {
		t.Fatalf("cutover should be ready after BIRD neighbor and selected route converge")
	}

	client.statusErr = errors.New("birdc unavailable")
	if err := service.reconcileRouting(context.Background()); err != nil {
		t.Fatalf("reconcileRouting with stale BIRD observation: %v", err)
	}
	if ready := service.ipsecRotateCutoverReady()["link-1"]; ready {
		t.Fatalf("cutover should be blocked when fresh BIRD observation is unavailable")
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
		NetNS:           ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: "h2", Create: true},
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

func boolPtr(v bool) *bool { return &v }

func buildTestNetworkStateForRouting(t *testing.T) (*stateFile, *syncConfigFile) {
	t.Helper()

	rootPub, rootPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(root): %v", err)
	}
	catofesPub, catofesPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(catofes): %v", err)
	}
	nodeAPub, nodeAPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(node-a): %v", err)
	}
	nodeBPub, nodeBPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(node-b): %v", err)
	}

	rootAuthority := &zone.ZoneAuthority{
		Zone:      zone.RootZone,
		Epoch:     1,
		Threshold: 1,
		Keys: []zone.AuthorizedKey{{
			Key: rootPub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermDelegate},
			}},
		}},
	}
	catofesAuthority := &zone.ZoneAuthority{
		Zone:      "catofes.",
		Epoch:     1,
		Threshold: 1,
		Keys: []zone.AuthorizedKey{{
			Key: catofesPub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermDelegate},
			}},
		}},
	}
	nodeAAuthority := &zone.ZoneAuthority{
		Zone:      "node-a.catofes.",
		Epoch:     1,
		Threshold: 1,
		Keys: []zone.AuthorizedKey{{
			Key: nodeAPub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermWrite},
			}},
		}},
	}
	nodeBAuthority := &zone.ZoneAuthority{
		Zone:      "node-b.catofes.",
		Epoch:     1,
		Threshold: 1,
		Keys: []zone.AuthorizedKey{{
			Key: nodeBPub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermWrite},
			}},
		}},
	}

	catofesDelegation := &zone.Delegation{
		ZoneName:  "catofes.",
		Scope:     zone.DelegationScopeDirectChild,
		Authority: *catofesAuthority,
	}
	if err := higgscrypto.SignDelegation(catofesDelegation, zone.RootZone, rootPriv); err != nil {
		t.Fatalf("SignDelegation(catofes): %v", err)
	}
	nodeADelegation := &zone.Delegation{
		ZoneName:  "node-a.catofes.",
		Scope:     zone.DelegationScopeDirectChild,
		Authority: *nodeAAuthority,
	}
	if err := higgscrypto.SignDelegation(nodeADelegation, "catofes.", catofesPriv); err != nil {
		t.Fatalf("SignDelegation(node-a): %v", err)
	}
	nodeBDelegation := &zone.Delegation{
		ZoneName:  "node-b.catofes.",
		Scope:     zone.DelegationScopeDirectChild,
		Authority: *nodeBAuthority,
	}
	if err := higgscrypto.SignDelegation(nodeBDelegation, "catofes.", catofesPriv); err != nil {
		t.Fatalf("SignDelegation(node-b): %v", err)
	}

	ns := zone.NewNetworkState()
	ns.Zones[zone.RootZone] = zone.NewZoneState(zone.RootZone, rootAuthority)
	ns.Zones["catofes."] = zone.NewZoneState("catofes.", catofesAuthority)
	ns.Zones["node-a.catofes."] = zone.NewZoneState("node-a.catofes.", nodeAAuthority)
	ns.Zones["node-b.catofes."] = zone.NewZoneState("node-b.catofes.", nodeBAuthority)
	ns.Zones[zone.RootZone].Delegations["catofes."] = catofesDelegation
	ns.Zones["catofes."].Delegations["node-a.catofes."] = nodeADelegation
	ns.Zones["catofes."].Delegations["node-b.catofes."] = nodeBDelegation

	configureValidation(ns)

	now := time.Unix(123, 0)
	if err := higgscrypto.VerifyChain(ns, "catofes.", now); err != nil {
		t.Fatalf("VerifyChain(catofes): %v", err)
	}
	if err := higgscrypto.VerifyChain(ns, "node-a.catofes.", now); err != nil {
		t.Fatalf("VerifyChain(node-a): %v", err)
	}
	if err := higgscrypto.VerifyChain(ns, "node-b.catofes.", now); err != nil {
		t.Fatalf("VerifyChain(node-b): %v", err)
	}

	state := &stateFile{
		ManagedZone:    "node-a.catofes.",
		Network:        ns,
		ZonePrivateKey: nodeAPriv,
	}
	addIPAMPool(t, state, zone.RootZone, "10.0.0.0/8", zone.RootZone, time.Unix(123, 0), rootPriv)
	addIPAMPool(t, state, zone.RootZone, "10.0.0.0/16", "catofes.", time.Unix(124, 0), rootPriv)
	addIPAMPool(t, state, zone.RootZone, "10.1.0.0/16", "catofes.", time.Unix(125, 0), rootPriv)
	config := &syncConfigFile{
		PeerID:     "node-a.catofes.",
		ListenAddr: "127.0.0.1:0",
	}

	// Pool delegations covering the assignments below.
	addIPAMPool(t, state, "catofes.", "10.0.0.0/16", "catofes.", now, catofesPriv)
	addIPAMPool(t, state, "catofes.", "10.1.0.0/16", "catofes.", now, catofesPriv)

	// Assign prefixes and announce routes.
	addRouteAssignment(t, state, "catofes.", "10.0.0.0/16", "node-a.catofes.", true, now, catofesPriv)
	addRouteAssignment(t, state, "catofes.", "10.1.0.0/16", "node-b.catofes.", true, now, catofesPriv)
	addRouteAnnouncement(t, state, "node-a.catofes.", "10.0.0.0/24", true, now, nodeAPriv)
	addRouteAnnouncement(t, state, "node-b.catofes.", "10.1.0.0/24", true, now, nodeBPriv)

	return state, config
}

func buildDryRunSmokeNetworkState(t *testing.T) (*stateFile, *syncConfigFile, map[zone.ZonePath]ed25519.PrivateKey) {
	t.Helper()

	rootPub, rootPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(root): %v", err)
	}
	catofesPub, catofesPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(catofes): %v", err)
	}
	nodeAPub, nodeAPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(node-a): %v", err)
	}
	nodeBPub, nodeBPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(node-b): %v", err)
	}

	rootAuthority := &zone.ZoneAuthority{
		Zone:      zone.RootZone,
		Epoch:     1,
		Threshold: 1,
		Keys: []zone.AuthorizedKey{{
			Key: rootPub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermDelegate},
			}},
		}},
	}
	catofesAuthority := &zone.ZoneAuthority{
		Zone:      "catofes.",
		Epoch:     1,
		Threshold: 1,
		Keys: []zone.AuthorizedKey{{
			Key: catofesPub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermDelegate},
			}},
		}},
	}
	nodeAAuthority := &zone.ZoneAuthority{
		Zone:      "node-a.catofes.",
		Epoch:     1,
		Threshold: 1,
		Keys: []zone.AuthorizedKey{{
			Key: nodeAPub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermWrite},
			}},
		}},
	}
	nodeBAuthority := &zone.ZoneAuthority{
		Zone:      "node-b.catofes.",
		Epoch:     1,
		Threshold: 1,
		Keys: []zone.AuthorizedKey{{
			Key: nodeBPub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermWrite},
			}},
		}},
	}

	catofesDelegation := &zone.Delegation{
		ZoneName:  "catofes.",
		Scope:     zone.DelegationScopeDirectChild,
		Authority: *catofesAuthority,
	}
	if err := higgscrypto.SignDelegation(catofesDelegation, zone.RootZone, rootPriv); err != nil {
		t.Fatalf("SignDelegation(catofes): %v", err)
	}
	nodeADelegation := &zone.Delegation{
		ZoneName:  "node-a.catofes.",
		Scope:     zone.DelegationScopeDirectChild,
		Authority: *nodeAAuthority,
	}
	if err := higgscrypto.SignDelegation(nodeADelegation, "catofes.", catofesPriv); err != nil {
		t.Fatalf("SignDelegation(node-a): %v", err)
	}
	nodeBDelegation := &zone.Delegation{
		ZoneName:  "node-b.catofes.",
		Scope:     zone.DelegationScopeDirectChild,
		Authority: *nodeBAuthority,
	}
	if err := higgscrypto.SignDelegation(nodeBDelegation, "catofes.", catofesPriv); err != nil {
		t.Fatalf("SignDelegation(node-b): %v", err)
	}

	ns := zone.NewNetworkState()
	ns.Zones[zone.RootZone] = zone.NewZoneState(zone.RootZone, rootAuthority)
	ns.Zones["catofes."] = zone.NewZoneState("catofes.", catofesAuthority)
	ns.Zones["node-a.catofes."] = zone.NewZoneState("node-a.catofes.", nodeAAuthority)
	ns.Zones["node-b.catofes."] = zone.NewZoneState("node-b.catofes.", nodeBAuthority)
	ns.Zones[zone.RootZone].Delegations["catofes."] = catofesDelegation
	ns.Zones["catofes."].Delegations["node-a.catofes."] = nodeADelegation
	ns.Zones["catofes."].Delegations["node-b.catofes."] = nodeBDelegation

	configureValidation(ns)

	now := time.Unix(123, 0)
	if err := higgscrypto.VerifyChain(ns, "catofes.", now); err != nil {
		t.Fatalf("VerifyChain(catofes): %v", err)
	}
	if err := higgscrypto.VerifyChain(ns, "node-a.catofes.", now); err != nil {
		t.Fatalf("VerifyChain(node-a): %v", err)
	}
	if err := higgscrypto.VerifyChain(ns, "node-b.catofes.", now); err != nil {
		t.Fatalf("VerifyChain(node-b): %v", err)
	}

	state := &stateFile{
		ManagedZone:    "node-a.catofes.",
		Network:        ns,
		ZonePrivateKey: nodeAPriv,
	}
	addIPAMPool(t, state, zone.RootZone, "10.0.0.0/8", zone.RootZone, time.Unix(123, 0), rootPriv)
	addIPAMPool(t, state, zone.RootZone, "10.0.0.0/16", "catofes.", time.Unix(124, 0), rootPriv)
	addIPAMPool(t, state, zone.RootZone, "10.1.0.0/16", "catofes.", time.Unix(125, 0), rootPriv)
	config := &syncConfigFile{
		PeerID:     "node-a.catofes.",
		ListenAddr: "127.0.0.1:0",
	}
	signers := map[zone.ZonePath]ed25519.PrivateKey{
		zone.RootZone:     rootPriv,
		"catofes.":        catofesPriv,
		"node-a.catofes.": nodeAPriv,
		"node-b.catofes.": nodeBPriv,
	}

	// Pool delegations covering the assignments below.
	addIPAMPool(t, state, "catofes.", "10.0.0.0/16", "catofes.", now, catofesPriv)
	addIPAMPool(t, state, "catofes.", "10.1.0.0/16", "catofes.", now, catofesPriv)

	// IPAM assignments in catofes. for the two leaf nodes.
	addRouteAssignment(t, state, "catofes.", "10.0.0.0/16", "node-a.catofes.", true, now, catofesPriv)
	addRouteAssignment(t, state, "catofes.", "10.1.0.0/16", "node-b.catofes.", true, now, catofesPriv)

	// Active route announcements in the respective leaf zones.
	addRouteAnnouncement(t, state, "node-a.catofes.", "10.0.1.0/24", true, now, nodeAPriv)
	addRouteAnnouncement(t, state, "node-b.catofes.", "10.1.1.0/24", true, now, nodeBPriv)

	return state, config, signers
}

// buildIPAMRoutingSmokeNetworkState creates a minimal delegation chain where
// catofes. holds PermAllocateIP and node-a.catofes. holds PermWriteRoute,
// so the IPAM/routing CLI functions can sign records for both zones in the
// same test by switching ZonePrivateKey on the returned Runtime.
func buildIPAMRoutingSmokeNetworkState(t *testing.T) (*stateFile, *syncConfigFile, map[zone.ZonePath]ed25519.PrivateKey, *Runtime) {
	t.Helper()

	rootPub, rootPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(root): %v", err)
	}
	catofesPub, catofesPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(catofes): %v", err)
	}
	nodeAPub, nodeAPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(node-a): %v", err)
	}

	rootAuthority := &zone.ZoneAuthority{
		Zone:      zone.RootZone,
		Epoch:     1,
		Threshold: 1,
		Keys: []zone.AuthorizedKey{{
			Key: rootPub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermDelegate},
			}},
		}},
	}
	catofesAuthority := &zone.ZoneAuthority{
		Zone:      "catofes.",
		Epoch:     1,
		Threshold: 1,
		Keys: []zone.AuthorizedKey{{
			Key: catofesPub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermDelegate, zone.PermAllocateIP},
			}},
		}},
	}
	nodeAAuthority := &zone.ZoneAuthority{
		Zone:      "node-a.catofes.",
		Epoch:     1,
		Threshold: 1,
		Keys: []zone.AuthorizedKey{{
			Key: nodeAPub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermWriteRoute},
			}},
		}},
	}

	catofesDelegation := &zone.Delegation{
		ZoneName:  "catofes.",
		Scope:     zone.DelegationScopeDirectChild,
		Authority: *catofesAuthority,
	}
	if err := higgscrypto.SignDelegation(catofesDelegation, zone.RootZone, rootPriv); err != nil {
		t.Fatalf("SignDelegation(catofes): %v", err)
	}
	nodeADelegation := &zone.Delegation{
		ZoneName:  "node-a.catofes.",
		Scope:     zone.DelegationScopeDirectChild,
		Authority: *nodeAAuthority,
	}
	if err := higgscrypto.SignDelegation(nodeADelegation, "catofes.", catofesPriv); err != nil {
		t.Fatalf("SignDelegation(node-a): %v", err)
	}

	ns := zone.NewNetworkState()
	ns.Zones[zone.RootZone] = zone.NewZoneState(zone.RootZone, rootAuthority)
	ns.Zones["catofes."] = zone.NewZoneState("catofes.", catofesAuthority)
	ns.Zones["node-a.catofes."] = zone.NewZoneState("node-a.catofes.", nodeAAuthority)
	ns.Zones[zone.RootZone].Delegations["catofes."] = catofesDelegation
	ns.Zones["catofes."].Delegations["node-a.catofes."] = nodeADelegation

	configureValidation(ns)

	now := time.Unix(123, 0)
	if err := higgscrypto.VerifyChain(ns, "catofes.", now); err != nil {
		t.Fatalf("VerifyChain(catofes): %v", err)
	}
	if err := higgscrypto.VerifyChain(ns, "node-a.catofes.", now); err != nil {
		t.Fatalf("VerifyChain(node-a): %v", err)
	}

	state := &stateFile{
		ManagedZone:    "node-a.catofes.",
		Network:        ns,
		ZonePrivateKey: nodeAPriv,
	}
	addIPAMPool(t, state, zone.RootZone, "10.0.0.0/8", zone.RootZone, time.Unix(123, 0), rootPriv)
	addIPAMPool(t, state, zone.RootZone, "10.0.0.0/16", "catofes.", time.Unix(124, 0), rootPriv)
	config := &syncConfigFile{
		PeerID:     "node-a.catofes.",
		ListenAddr: "127.0.0.1:0",
	}
	signers := map[zone.ZonePath]ed25519.PrivateKey{
		zone.RootZone:     rootPriv,
		"catofes.":        catofesPriv,
		"node-a.catofes.": nodeAPriv,
	}

	appConfig := defaultAppConfig()
	appConfig.DataDir = t.TempDir()
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{{
		ID:              "ipsec-main",
		Provider:        ipsec.ProviderStrongSwan,
		NetNS:           ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: "h2", Create: true},
		DefaultPathMode: ipsec.PathModeFamilyRedundant,
	}}
	appConfig.Netns = netnsConfig{Names: map[string]ipsec.NetNSSpec{"h2": {Kind: ipsec.NetNSName, Name: "h2", Create: true}}}
	appConfig.Routing, _ = parseRoutingConfigInstances([]routingInstanceYAML{{ID: "ipsec-main", NetNS: "h2", Enabled: boolPtr(true), Mode: ipsec.RoutingModeManaged}}, appConfig.Netns, appConfig.DataDir)

	rt := &Runtime{
		Config:    appConfig,
		StatePath: filepath.Join(t.TempDir(), "higgs.db"),
		Clock:     func() time.Time { return time.Unix(4000, 0) },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}

	return state, config, signers, rt
}

func addIPAMPool(t *testing.T, state *stateFile, source zone.ZonePath, prefix string, delegatedTo zone.ZonePath, now time.Time, signer ed25519.PrivateKey) {
	t.Helper()
	canonical, err := routing.CanonicalizePrefix(prefix)
	if err != nil {
		t.Fatalf("invalid prefix %q: %v", prefix, err)
	}
	key, err := routing.NormalizeIPAMPoolKey(prefix)
	if err != nil {
		t.Fatalf("normalize pool key: %v", err)
	}
	record := routing.IPAMPoolRecord{Version: 1, Prefix: canonical, DelegatedTo: delegatedTo, Active: true}
	value, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("marshal pool: %v", err)
	}
	signed, err := buildSignedRecordAt(signingState(state, signer), source, key, value, routing.RecordTypeIPAMPool, now)
	if err != nil {
		t.Fatalf("buildSignedRecordAt: %v", err)
	}
	state.Network.Zones[source].Records[key] = signed
}

func addRouteAssignment(t *testing.T, state *stateFile, source zone.ZonePath, prefix string, assignedTo zone.ZonePath, active bool, now time.Time, signer ed25519.PrivateKey) {
	t.Helper()
	canonical, err := routing.CanonicalizePrefix(prefix)
	if err != nil {
		t.Fatalf("invalid prefix %q: %v", prefix, err)
	}
	key, err := routing.NormalizeIPAMAssignmentKey(prefix)
	if err != nil {
		t.Fatalf("normalize assignment key: %v", err)
	}
	record := routing.IPAMAssignmentRecord{Version: 1, Prefix: canonical, AssignedTo: assignedTo, Active: active}
	value, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("marshal assignment: %v", err)
	}
	signed, err := buildSignedRecordAt(signingState(state, signer), source, key, value, routing.RecordTypeIPAMAssignment, now)
	if err != nil {
		t.Fatalf("buildSignedRecordAt: %v", err)
	}
	state.Network.Zones[source].Records[key] = signed
}

func revokeRouteAssignment(t *testing.T, state *stateFile, source zone.ZonePath, prefix string, assignedTo zone.ZonePath, now time.Time, signer ed25519.PrivateKey) {
	t.Helper()
	addRouteAssignment(t, state, source, prefix, assignedTo, false, now, signer)
}

func addRouteAnnouncement(t *testing.T, state *stateFile, path zone.ZonePath, prefix string, active bool, now time.Time, signer ed25519.PrivateKey) {
	t.Helper()
	canonical, err := routing.CanonicalizePrefix(prefix)
	if err != nil {
		t.Fatalf("invalid prefix %q: %v", prefix, err)
	}
	key, err := routing.NormalizeRouteAnnouncementKey(prefix)
	if err != nil {
		t.Fatalf("normalize route key: %v", err)
	}
	record := routing.RouteAnnouncementRecord{Version: 1, Prefix: canonical, Active: active}
	value, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("marshal route announcement: %v", err)
	}
	signed, err := buildSignedRecordAt(signingState(state, signer), path, key, value, routing.RecordTypeRouteAnnouncement, now)
	if err != nil {
		t.Fatalf("buildSignedRecordAt: %v", err)
	}
	state.Network.Zones[path].Records[key] = signed
}

func signingState(state *stateFile, signer ed25519.PrivateKey) *stateFile {
	out := cloneStateFile(state)
	out.ZonePrivateKey = signer
	return out
}

func readFileString(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// runWithZonePrivateKey loads the current state, switches the signing key to
// the supplied private key, saves it, runs f, and lets f persist any further
// state changes. This lets a single test exercise CLI functions for multiple
// zones without clobbering records written by previous steps.
func runWithZonePrivateKey(rt *Runtime, key ed25519.PrivateKey, f func() error) error {
	state, err := rt.LoadState()
	if err != nil {
		return err
	}
	state.ZonePrivateKey = key
	if err := rt.SaveState(state); err != nil {
		return err
	}
	return f()
}

func TestRoutingReconcileInterval(t *testing.T) {
	appConfig := defaultAppConfig()
	appConfig.Routing = routingConfig{Instances: []RoutingInstance{
		{ID: "a", NetNS: "h2", Enabled: true, Mode: ipsec.RoutingModeManaged},
	}}
	service := newDaemonService(&Runtime{Config: appConfig}, &stateFile{}, &syncConfigFile{}, time.Second)
	if got := service.routingReconcileInterval(); got != 30*time.Second {
		t.Fatalf("routingReconcileInterval = %s, want 30s", got)
	}
}

func TestRoutingReconcileIntervalZeroWhenDisabled(t *testing.T) {
	appConfig := defaultAppConfig()
	appConfig.Routing = routingConfig{Instances: []RoutingInstance{
		{ID: "a", NetNS: "h2", Enabled: false, Mode: ipsec.RoutingModeManaged},
	}}
	service := newDaemonService(&Runtime{Config: appConfig}, &stateFile{}, &syncConfigFile{}, time.Second)
	if got := service.routingReconcileInterval(); got != 0 {
		t.Fatalf("routingReconcileInterval = %s, want 0", got)
	}
}

func TestStopManagedBirdInstancesStopsManagedOnly(t *testing.T) {
	appConfig := defaultAppConfig()
	appConfig.DataDir = t.TempDir()
	appConfig.Netns = netnsConfig{Names: map[string]ipsec.NetNSSpec{
		"h2": {Kind: ipsec.NetNSName, Name: "h2", Create: true},
		"h3": {Kind: ipsec.NetNSName, Name: "h3", Create: true},
	}}
	var err error
	appConfig.Routing, err = parseRoutingConfigInstances([]routingInstanceYAML{
		{ID: "managed", NetNS: "h2", Enabled: boolPtr(true), Mode: ipsec.RoutingModeManaged},
		{ID: "external", NetNS: "h3", Enabled: boolPtr(true), Mode: ipsec.RoutingModeExternal},
	}, appConfig.Netns, appConfig.DataDir)
	if err != nil {
		t.Fatalf("parseRoutingConfigInstances: %v", err)
	}

	managedPM := &fakeBirdProcessManager{running: true}
	externalPM := &fakeBirdProcessManager{running: true}
	service := newDaemonService(&Runtime{Config: appConfig}, &stateFile{}, &syncConfigFile{}, time.Second)
	service.birdProcessManagers = map[string]birdProcessManager{
		"h2": managedPM,
		"h3": externalPM,
	}

	if err := service.stopManagedBirdInstances(context.Background()); err != nil {
		t.Fatalf("stopManagedBirdInstances: %v", err)
	}
	if !managedPM.stopped {
		t.Fatalf("managed BIRD process manager was not stopped")
	}
	if managedPM.stopSpec.NetNSName != "h2" {
		t.Fatalf("Stop netns = %q, want h2", managedPM.stopSpec.NetNSName)
	}
	if managedPM.stopSpec.ControlSocketPath == "" || managedPM.stopSpec.PIDFilePath == "" || managedPM.stopSpec.ConfigPath == "" {
		t.Fatalf("Stop spec paths must be populated: %+v", managedPM.stopSpec)
	}
	if externalPM.stopped {
		t.Fatalf("external BIRD process manager should not be stopped")
	}
}

func TestFlushRoutingReconcileCoalesces(t *testing.T) {
	state, config := buildTestNetworkStateForRouting(t)
	now := time.Unix(4000, 0)

	appConfig := defaultAppConfig()
	appConfig.DataDir = t.TempDir()
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{{
		ID:              "main",
		Provider:        ipsec.ProviderStrongSwan,
		NetNS:           ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: "h2", Create: true},
		DefaultPathMode: ipsec.PathModeFamilyRedundant,
	}}
	appConfig.Netns = netnsConfig{Names: map[string]ipsec.NetNSSpec{"h2": {Kind: ipsec.NetNSName, Name: "h2", Create: true}}}
	appConfig.Routing, _ = parseRoutingConfigInstances([]routingInstanceYAML{{ID: "main", NetNS: "h2", Enabled: boolPtr(true), Mode: ipsec.RoutingModeManaged}}, appConfig.Netns, appConfig.DataDir)

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
	service.birdProcessManager = pm

	if service.flushRoutingReconcile(context.Background()) {
		t.Fatalf("flushRoutingReconcile should return false when not dirty")
	}

	service.routingDirty = true
	if !service.flushRoutingReconcile(context.Background()) {
		t.Fatalf("flushRoutingReconcile should return true when dirty")
	}

	if service.routingDirty {
		t.Fatalf("routingDirty should be cleared after flush")
	}

	latest, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if len(latest.BirdInstances) != 1 {
		t.Fatalf("BirdInstances len = %d, want 1", len(latest.BirdInstances))
	}
}

func TestAutoAnnounceAssignedIPsDisabled(t *testing.T) {
	state, rt := buildAutoAnnounceTestState(t, "node-a.catofes.", []string{"10.0.0.0/24"}, nil)
	rt.Config.IPAM.AutoAnnounceAssignedIPs = false

	service := newDaemonService(rt, state, &syncConfigFile{}, time.Second)
	ars, err := routing.BuildAuthorizedRouteSet(state.Network, rt.Now())
	if err != nil {
		t.Fatalf("BuildAuthorizedRouteSet: %v", err)
	}
	if err := service.autoAnnounceAssignedIPs(ars); err != nil {
		t.Fatalf("autoAnnounceAssignedIPs: %v", err)
	}
	if len(state.Network.Zones["node-a.catofes."].Records) != 0 {
		t.Fatalf("expected no announcements when disabled, got %d", len(state.Network.Zones["node-a.catofes."].Records))
	}
}

func TestAutoAnnounceAssignedIPsPublishesNew(t *testing.T) {
	state, rt := buildAutoAnnounceTestState(t, "node-a.catofes.", []string{"10.0.0.0/24"}, nil)

	service := newDaemonService(rt, state, &syncConfigFile{}, time.Second)
	ars, err := routing.BuildAuthorizedRouteSet(state.Network, rt.Now())
	if err != nil {
		t.Fatalf("BuildAuthorizedRouteSet: %v", err)
	}
	if err := service.autoAnnounceAssignedIPs(ars); err != nil {
		t.Fatalf("autoAnnounceAssignedIPs: %v", err)
	}

	key, _ := routing.NormalizeRouteAnnouncementKey("10.0.0.0/24")
	rec := state.Network.Zones["node-a.catofes."].Records[key]
	if rec == nil {
		t.Fatalf("expected announcement record for %s", key)
	}
	ann, err := routing.ParseRouteAnnouncementRecord(rec)
	if err != nil {
		t.Fatalf("ParseRouteAnnouncementRecord: %v", err)
	}
	if !ann.Active {
		t.Fatalf("expected active announcement, got active=false")
	}
	if ann.Prefix != "10.0.0.0/24" {
		t.Fatalf("expected prefix 10.0.0.0/24, got %s", ann.Prefix)
	}
}

func TestAutoAnnounceAssignedIPsWithdrawsStale(t *testing.T) {
	state, rt := buildAutoAnnounceTestState(t, "node-a.catofes.", nil, map[string]bool{"10.0.0.0/24": true})

	service := newDaemonService(rt, state, &syncConfigFile{}, time.Second)
	ars, err := routing.BuildAuthorizedRouteSet(state.Network, rt.Now())
	if err != nil {
		t.Fatalf("BuildAuthorizedRouteSet: %v", err)
	}
	if err := service.autoAnnounceAssignedIPs(ars); err != nil {
		t.Fatalf("autoAnnounceAssignedIPs: %v", err)
	}

	key, _ := routing.NormalizeRouteAnnouncementKey("10.0.0.0/24")
	rec := state.Network.Zones["node-a.catofes."].Records[key]
	if rec == nil {
		t.Fatalf("expected withdrawal record for %s", key)
	}
	ann, err := routing.ParseRouteAnnouncementRecord(rec)
	if err != nil {
		t.Fatalf("ParseRouteAnnouncementRecord: %v", err)
	}
	if ann.Active {
		t.Fatalf("expected withdrawn announcement, got active=true")
	}
}

func TestAutoAnnounceAssignedIPsSkipsExisting(t *testing.T) {
	state, rt := buildAutoAnnounceTestState(t, "node-a.catofes.", []string{"10.0.0.0/24"}, map[string]bool{"10.0.0.0/24": true})

	service := newDaemonService(rt, state, &syncConfigFile{}, time.Second)
	ars, err := routing.BuildAuthorizedRouteSet(state.Network, rt.Now())
	if err != nil {
		t.Fatalf("BuildAuthorizedRouteSet: %v", err)
	}
	if err := service.autoAnnounceAssignedIPs(ars); err != nil {
		t.Fatalf("autoAnnounceAssignedIPs: %v", err)
	}

	key, _ := routing.NormalizeRouteAnnouncementKey("10.0.0.0/24")
	rec := state.Network.Zones["node-a.catofes."].Records[key]
	if rec == nil {
		t.Fatalf("expected announcement record for %s", key)
	}
	if rec.Version != 1 {
		t.Fatalf("expected no rewrite, version=%d", rec.Version)
	}
}

func TestAutoAnnounceAssignedIPsSkipsInvalidAssignment(t *testing.T) {
	state, rt := buildAutoAnnounceTestState(t, "node-a.catofes.", []string{"192.168.0.0/24"}, nil)

	service := newDaemonService(rt, state, &syncConfigFile{}, time.Second)
	ars, err := routing.BuildAuthorizedRouteSet(state.Network, rt.Now())
	if err != nil {
		t.Fatalf("BuildAuthorizedRouteSet: %v", err)
	}
	if len(ars.Errors) == 0 {
		t.Fatalf("expected authorization errors for un-pooled assignment")
	}
	if err := service.autoAnnounceAssignedIPs(ars); err != nil {
		t.Fatalf("autoAnnounceAssignedIPs: %v", err)
	}

	key, _ := routing.NormalizeRouteAnnouncementKey("192.168.0.0/24")
	if state.Network.Zones["node-a.catofes."].Records[key] != nil {
		t.Fatalf("expected no announcement for invalid assignment")
	}
}

func buildAutoAnnounceTestState(t *testing.T, managedZone zone.ZonePath, assignments []string, announcements map[string]bool) (*stateFile, *Runtime) {
	t.Helper()
	rootPub, rootPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(root): %v", err)
	}
	catofesPub, catofesPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(catofes): %v", err)
	}
	managedPub, managedPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(managed): %v", err)
	}

	rootAuthority := &zone.ZoneAuthority{
		Zone:      zone.RootZone,
		Epoch:     1,
		Threshold: 1,
		Keys: []zone.AuthorizedKey{{
			Key: rootPub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermDelegate},
			}},
		}},
	}
	catofesAuthority := &zone.ZoneAuthority{
		Zone:      "catofes.",
		Epoch:     1,
		Threshold: 1,
		Keys: []zone.AuthorizedKey{{
			Key: catofesPub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermDelegate, zone.PermAllocateIP},
			}},
		}},
	}
	managedAuthority := &zone.ZoneAuthority{
		Zone:      managedZone,
		Epoch:     1,
		Threshold: 1,
		Keys: []zone.AuthorizedKey{{
			Key: managedPub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermWrite, zone.PermWriteRoute},
			}},
		}},
	}

	ns := zone.NewNetworkState()
	ns.Zones[zone.RootZone] = zone.NewZoneState(zone.RootZone, rootAuthority)
	ns.Zones["catofes."] = zone.NewZoneState("catofes.", catofesAuthority)
	ns.Zones[managedZone] = zone.NewZoneState(managedZone, managedAuthority)

	catofesDelegation := testSignedDelegation(t, "catofes.", *catofesAuthority, zone.RootZone, rootPriv)
	managedDelegation := testSignedDelegation(t, managedZone, *managedAuthority, "catofes.", catofesPriv)
	ns.Zones[zone.RootZone].Delegations["catofes."] = catofesDelegation
	ns.Zones["catofes."].Delegations[managedZone] = managedDelegation
	stateForPools := &stateFile{Network: ns, ZonePrivateKey: catofesPriv, RootPrivateKey: rootPriv}
	addIPAMPool(t, stateForPools, zone.RootZone, "10.0.0.0/8", zone.RootZone, time.Unix(1, 0), rootPriv)
	addIPAMPool(t, stateForPools, zone.RootZone, "10.0.0.0/16", "catofes.", time.Unix(2, 0), rootPriv)

	poolRecord := routing.IPAMPoolRecord{Version: 1, Prefix: "10.0.0.0/16", DelegatedTo: "catofes.", Active: true}
	poolValue, err := json.Marshal(poolRecord)
	if err != nil {
		t.Fatalf("marshal pool: %v", err)
	}
	poolKey, err := routing.NormalizeIPAMPoolKey("10.0.0.0/16")
	if err != nil {
		t.Fatalf("normalize pool key: %v", err)
	}
	poolRec, err := buildSignedRecordAt(&stateFile{Network: ns, ZonePrivateKey: catofesPriv, RootPrivateKey: rootPriv}, "catofes.", poolKey, poolValue, routing.RecordTypeIPAMPool, time.Unix(1, 0))
	if err != nil {
		t.Fatalf("sign pool: %v", err)
	}
	ns.Zones["catofes."].Records[poolKey] = poolRec

	for _, prefix := range assignments {
		assignRecord := routing.IPAMAssignmentRecord{Version: 1, Prefix: prefix, AssignedTo: managedZone, Active: true}
		assignValue, err := json.Marshal(assignRecord)
		if err != nil {
			t.Fatalf("marshal assignment: %v", err)
		}
		assignKey, err := routing.NormalizeIPAMAssignmentKey(prefix)
		if err != nil {
			t.Fatalf("normalize assignment key: %v", err)
		}
		assignRec, err := buildSignedRecordAt(&stateFile{Network: ns, ZonePrivateKey: catofesPriv, RootPrivateKey: rootPriv}, "catofes.", assignKey, assignValue, routing.RecordTypeIPAMAssignment, time.Unix(1, 0))
		if err != nil {
			t.Fatalf("sign assignment: %v", err)
		}
		ns.Zones["catofes."].Records[assignKey] = assignRec
	}

	for prefix, active := range announcements {
		annRecord := routing.RouteAnnouncementRecord{Version: 1, Prefix: prefix, Active: active}
		annValue, err := json.Marshal(annRecord)
		if err != nil {
			t.Fatalf("marshal announcement: %v", err)
		}
		annKey, err := routing.NormalizeRouteAnnouncementKey(prefix)
		if err != nil {
			t.Fatalf("normalize announcement key: %v", err)
		}
		annRec, err := buildSignedRecordAt(&stateFile{Network: ns, ZonePrivateKey: managedPriv, RootPrivateKey: rootPriv}, managedZone, annKey, annValue, routing.RecordTypeRouteAnnouncement, time.Unix(1, 0))
		if err != nil {
			t.Fatalf("sign announcement: %v", err)
		}
		ns.Zones[managedZone].Records[annKey] = annRec
	}

	configureValidation(ns)
	for _, path := range []zone.ZonePath{"catofes.", managedZone} {
		if err := higgscrypto.VerifyChain(ns, path, time.Unix(1000, 0)); err != nil {
			t.Fatalf("VerifyChain(%s): %v", path, err)
		}
	}

	state := &stateFile{
		ManagedZone:    managedZone,
		Network:        ns,
		ZonePrivateKey: managedPriv,
		RootPrivateKey: rootPriv,
	}
	rt := &Runtime{
		Config: &appConfig{IPAM: ipamConfig{AutoAnnounceAssignedIPs: true}},
		Clock:  func() time.Time { return time.Unix(1000, 0) },
	}
	return state, rt
}
