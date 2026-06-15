package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Catofes/higgs/pkg/core/zone"
	higgscrypto "github.com/Catofes/higgs/pkg/crypto"
	"github.com/Catofes/higgs/pkg/routing"
	"github.com/Catofes/higgs/pkg/routing/bird"
	"github.com/Catofes/higgs/pkg/transport/ipsec"
)

type fakeBirdProcessManager struct {
	started   bool
	startSpec bird.BirdInstanceSpec
	startErr  error
	running   bool
}

func (f *fakeBirdProcessManager) Start(ctx context.Context, spec bird.BirdInstanceSpec) error {
	f.started = true
	f.startSpec = spec
	return f.startErr
}

func (f *fakeBirdProcessManager) Stop(ctx context.Context, spec bird.BirdInstanceSpec) error {
	f.running = false
	return nil
}

func (f *fakeBirdProcessManager) IsRunning(ctx context.Context) bool {
	return f.running
}

type fakeBirdClient struct {
	statusErr    error
	configureErr error
	statusCalled bool
}

func (f *fakeBirdClient) Status(ctx context.Context) (*bird.BirdObservedState, error) {
	f.statusCalled = true
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
		Direction:       ipsec.DirectionOutbound,
		Routing: ipsec.RoutingSpec{
			Enabled: true,
			Mode:    ipsec.RoutingModeManaged,
		},
	}}

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
	inst := latest.BirdInstances["main"]
	if inst == nil {
		t.Fatalf("missing bird instance state for overlay main")
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
	importIdx := strings.Index(cfg, "filter higgs_import_main")
	exportIdx := strings.Index(cfg, "filter higgs_export_main")
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
		Direction:       ipsec.DirectionOutbound,
		Routing: ipsec.RoutingSpec{
			Enabled: true,
			Mode:    ipsec.RoutingModeManaged,
		},
	}}

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
	inst := latest.BirdInstances["ipsec-main"]
	if inst == nil {
		t.Fatalf("missing bird instance state for overlay ipsec-main")
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

	importIdx := strings.Index(cfg, "filter higgs_import_ipsec_main")
	exportIdx := strings.Index(cfg, "filter higgs_export_ipsec_main")
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
	state, config, signers, rt := buildIPAMRoutingSmokeNetworkState(t)
	now := rt.Now()

	// Publish pool and assignment as the catofes. administrator.
	if err := runWithZonePrivateKey(rt, signers["catofes."], func() error {
		if err := createIPAMPoolWithRuntime(rt, "catofes.", "10.0.0.0/16", "catofes."); err != nil {
			return err
		}
		return assignIPAMWithRuntime(rt, "catofes.", "10.0.0.0/16", "node-a.catofes.")
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
	inst := latest.BirdInstances["ipsec-main"]
	if inst == nil || inst.ConfigPath == "" {
		t.Fatalf("missing bird instance state or config path")
	}

	cfg, err := readFileString(inst.ConfigPath)
	if err != nil {
		t.Fatalf("read generated config: %v", err)
	}

	importIdx := strings.Index(cfg, "filter higgs_import_ipsec_main")
	exportIdx := strings.Index(cfg, "filter higgs_export_ipsec_main")
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
		Direction:       ipsec.DirectionOutbound,
		Routing: ipsec.RoutingSpec{
			Enabled: true,
			Mode:    ipsec.RoutingModeManaged,
		},
	}}

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
	inst := latest.BirdInstances["ipsec-main"]
	if inst == nil || inst.ConfigPath == "" {
		t.Fatalf("missing bird instance state or config path")
	}

	cfg, err := readFileString(inst.ConfigPath)
	if err != nil {
		t.Fatalf("read generated config: %v", err)
	}

	importIdx := strings.Index(cfg, "filter higgs_import_ipsec_main")
	exportIdx := strings.Index(cfg, "filter higgs_export_ipsec_main")
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
		Direction:       ipsec.DirectionOutbound,
		Routing: ipsec.RoutingSpec{
			Enabled: true,
			Mode:    ipsec.RoutingModeExternal,
		},
	}}

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
	inst := latest.BirdInstances["main"]
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
		NetNS:           ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: "h2", Create: true},
		DefaultPathMode: ipsec.PathModeFamilyRedundant,
		Direction:       ipsec.DirectionOutbound,
		Routing: ipsec.RoutingSpec{
			Enabled: false,
		},
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
		Direction:       ipsec.DirectionOutbound,
		Routing: ipsec.RoutingSpec{
			Enabled: true,
			Mode:    ipsec.RoutingModeManaged,
		},
	}}

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
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{
		{
			ID:        "a",
			Routing:   ipsec.RoutingSpec{Enabled: true, Mode: ipsec.RoutingModeManaged},
			Reconcile: ipsec.ReconcilePolicy{IntervalSeconds: 45},
		},
		{
			ID:        "b",
			Routing:   ipsec.RoutingSpec{Enabled: true, Mode: ipsec.RoutingModeManaged},
			Reconcile: ipsec.ReconcilePolicy{IntervalSeconds: 15},
		},
	}
	service := newDaemonService(&Runtime{Config: appConfig}, &stateFile{}, &syncConfigFile{}, time.Second)
	if got := service.routingReconcileInterval(); got != 15*time.Second {
		t.Fatalf("routingReconcileInterval = %s, want 15s", got)
	}
}

func TestRoutingReconcileIntervalZeroWhenDisabled(t *testing.T) {
	appConfig := defaultAppConfig()
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{{
		ID:      "a",
		Routing: ipsec.RoutingSpec{Enabled: false},
	}}
	service := newDaemonService(&Runtime{Config: appConfig}, &stateFile{}, &syncConfigFile{}, time.Second)
	if got := service.routingReconcileInterval(); got != 0 {
		t.Fatalf("routingReconcileInterval = %s, want 0", got)
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
		Direction:       ipsec.DirectionOutbound,
		Routing:         ipsec.RoutingSpec{Enabled: true, Mode: ipsec.RoutingModeManaged},
	}}

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
