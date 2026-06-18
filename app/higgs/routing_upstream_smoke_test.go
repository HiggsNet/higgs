package main

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Catofes/higgs/pkg/core/zone"
	"github.com/Catofes/higgs/pkg/routing"
	"github.com/Catofes/higgs/pkg/routing/bird"
	"github.com/Catofes/higgs/pkg/transport/ipsec"
)

// TestUpstreamRoutingDryRunSmoke verifies that the upstream veth + static route
// pipeline produces a valid BIRD config with multi-interface blocks and the
// filter correctly includes the assigned prefixes.
func TestUpstreamRoutingDryRunSmoke(t *testing.T) {
	state, syncConfig := buildTestNetworkStateForRouting(t)
	now := time.Unix(4000, 0)

	appConfig := defaultAppConfig()
	appConfig.DataDir = t.TempDir()
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{{
		ID:              "main",
		Provider:        ipsec.ProviderStrongSwan,
		NetNS:           ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: "h2", Create: true},
		DefaultPathMode: ipsec.PathModeFamilyRedundant,
		Direction:       ipsec.DirectionOutbound,
	}}
	appConfig.Netns = netnsConfig{Names: map[string]ipsec.NetNSSpec{"h2": {Kind: ipsec.NetNSName, Name: "h2", Create: true}}}

	upstreamYAML := []routingInstanceYAML{{
		ID:           "main",
		NetNS:        "h2",
		Enabled:      boolPtr(true),
		Mode:         ipsec.RoutingModeManaged,
		InterfacePat: "hgs*",
		Upstream: &upstreamConfigYAML{
			Enabled:       boolPtr(true),
			Interface:     "hgs-upstream0",
			CreateVeth:    boolPtr(true),
			PeerInterface: "hgs-upstream1",
			IPv4LL:        "169.254.0.1/30",
			IPv6LL:        "fe80::1/64",
		},
	}}
	appConfig.Routing, _ = parseRoutingConfigInstances(upstreamYAML, appConfig.Netns, appConfig.DataDir)

	rt := &Runtime{
		Config:    appConfig,
		StatePath: filepath.Join(t.TempDir(), "higgs.db"),
		Clock:     func() time.Time { return now },
	}

	// Verify upstream config was parsed correctly.
	inst := appConfig.Routing.Instances[0]
	if inst.Upstream == nil || !inst.Upstream.Enabled {
		t.Fatal("upstream config not parsed correctly")
	}

	// Build a fake veth manager.
	fakeVM := &fakeVethManager{}
	pm := &fakeBirdProcessManager{running: false}
	client := &fakeBirdClient{}

	service := newDaemonService(rt, state, syncConfig, time.Second)
	service.birdProcessManager = pm
	service.birdClientFactory = func(socketPath string, timeout time.Duration) birdClient { return client }
	service.vethManager = fakeVM

	ctx := context.Background()
	if err := service.reconcileRouting(ctx); err != nil {
		t.Fatalf("reconcileRouting: %v", err)
	}

	// Verify veth manager was called.
	if !fakeVM.ensureCalled {
		t.Error("vethManager.EnsureVethPair was not called during reconcile")
	}

	// Read the generated config and verify upstream interface + static route support.
	latest, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	birdState := latest.BirdInstances["h2"]
	if birdState == nil {
		t.Fatal("BirdInstances[h2] is nil")
	}
	if birdState.State != birdInstanceStateRunning {
		t.Errorf("bird state = %q, want running", birdState.State)
	}

	// Read the generated config file.
	cfgBytes, err := os.ReadFile(birdState.ConfigPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	cfgStr := string(cfgBytes)

	// Assert upstream interface block exists.
	if !strings.Contains(cfgStr, `interface "hgs-upstream*" {`) {
		t.Errorf("BIRD config missing upstream interface block\n%s", cfgStr)
	}

	// Assert primary interface has type tunnel.
	if !strings.Contains(cfgStr, "type tunnel;") {
		t.Errorf("BIRD config missing type tunnel in primary block\n%s", cfgStr)
	}

	// Count type tunnel: exactly 1 (only primary, NOT upstream).
	if cnt := strings.Count(cfgStr, "type tunnel;"); cnt != 1 {
		t.Errorf("expected exactly 1 type tunnel, got %d\n%s", cnt, cfgStr)
	}

	// Assert default route rejection in filters.
	if !strings.Contains(cfgStr, "if net ~ [ 0.0.0.0/0 ] then reject;") {
		t.Errorf("BIRD config missing IPv4 default route rejection\n%s", cfgStr)
	}
	if !strings.Contains(cfgStr, "if net ~ [ ::/0 ] then reject;") {
		t.Errorf("BIRD config missing IPv6 default route rejection\n%s", cfgStr)
	}
}

// TestUpstreamRoutingWithIPAMAssignment verifies that IPAM assignments for the
// local zone produce static routes via the upstream interface.
func TestUpstreamRoutingWithIPAMAssignment(t *testing.T) {
	state, _ := buildTestNetworkStateForRouting(t)
	now := time.Unix(4000, 0)

	// Add an IPAM assignment for node-a.catofes.
	assignmentPrefix := netip.MustParsePrefix("10.42.0.0/24")
	assignmentRec := routing.IPAMAssignmentRecord{
		Version:    1,
		Prefix:     assignmentPrefix.String(),
		AssignedTo: "node-a.catofes.",
		Active:     true,
	}
	assignmentValue, _ := json.Marshal(assignmentRec)
	assignmentKey := routing.RecordKeyPrefixIPAMAssignments + strings.ReplaceAll(assignmentPrefix.String(), "/", "_")
	if zs := state.Network.Zones["node-a.catofes."]; zs != nil {
		zs.Records[assignmentKey] = &zone.Record{
			Zone:      "node-a.catofes.",
			Key:       assignmentKey,
			Value:     assignmentValue,
			Type:      routing.RecordTypeIPAMAssignment,
			Version:   1,
			Timestamp: now.Unix(),
		}
	}
	// Also add a pool covering the assignment in the root zone.
	poolRec := routing.IPAMPoolRecord{
		Version:     1,
		Prefix:      "10.42.0.0/16",
		DelegatedTo: "catofes.",
		Active:      true,
	}
	poolValue, _ := json.Marshal(poolRec)
	poolKey := routing.RecordKeyPrefixIPAMPools + strings.ReplaceAll("10.42.0.0/16", "/", "_")
	if zs := state.Network.Zones[zone.RootZone]; zs != nil {
		zs.Records[poolKey] = &zone.Record{
			Zone:      zone.RootZone,
			Key:       poolKey,
			Value:     poolValue,
			Type:      routing.RecordTypeIPAMPool,
			Version:   1,
			Timestamp: now.Unix(),
		}
	}
	// Add sub-assignment in catofes for node-a.
	catAssignmentRec := routing.IPAMAssignmentRecord{
		Version:    1,
		Prefix:     "10.42.0.0/24",
		AssignedTo: "node-a.catofes.",
		Active:     true,
	}
	catAssignmentValue, _ := json.Marshal(catAssignmentRec)
	catAssignmentKey := routing.RecordKeyPrefixIPAMAssignments + strings.ReplaceAll("10.42.0.0/24", "/", "_")
	if zs := state.Network.Zones["catofes."]; zs != nil {
		zs.Records[catAssignmentKey] = &zone.Record{
			Zone:      "catofes.",
			Key:       catAssignmentKey,
			Value:     catAssignmentValue,
			Type:      routing.RecordTypeIPAMAssignment,
			Version:   1,
			Timestamp: now.Unix(),
		}
	}

	// Build AuthorizedRouteSet and verify the assignment is present.
	ars, err := routing.BuildAuthorizedRouteSet(state.Network, now)
	if err != nil {
		t.Fatalf("BuildAuthorizedRouteSet: %v", err)
	}

	dataDir := t.TempDir()
	netnsCfg := netnsConfig{Names: map[string]ipsec.NetNSSpec{"h2": {Kind: ipsec.NetNSName, Name: "h2", Create: true}}}

	// Build the BirdInstanceSpec via parseRoutingConfigInstances for proper path derivation.
	yamlInstances := []routingInstanceYAML{{
		ID:           "main",
		NetNS:        "h2",
		Enabled:      boolPtr(true),
		Mode:         "managed",
		InterfacePat: "hgs*",
		Upstream: &upstreamConfigYAML{
			Enabled:   boolPtr(true),
			Interface: "hgs-upstream0",
			IPv6LL:    "fe80::1/64",
		},
	}}
	parsedCfg, err := parseRoutingConfigInstances(yamlInstances, netnsCfg, dataDir)
	if err != nil {
		t.Fatalf("parseRoutingConfigInstances: %v", err)
	}
	inst := parsedCfg.Instances[0]
	if inst.Upstream == nil || !inst.Upstream.Enabled {
		t.Fatal("upstream config not parsed correctly")
	}
	ng := &netnsOverlayGroup{
		NetNSName: "h2",
		Overlays:  []string{"main"},
		Spec:      ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: "h2", Create: true},
	}
	routerID := bird.StableRouterID("node-a.catofes.", rootTrustHash(state.Network), "h2")
	spec := buildBirdInstanceSpecForNetns(inst, routerID, "/tmp", ng, netnsCfg, ars, "node-a.catofes.")

	// Verify the assignment prefix appears in static routes.
	foundAssignment := false
	for _, sr := range spec.StaticRoutes {
		if sr.Prefix == assignmentPrefix {
			foundAssignment = true
			if sr.Via != "hgs-upstream0" {
				t.Errorf("static route via = %q, want hgs-upstream0", sr.Via)
			}
		}
	}
	if !foundAssignment {
		t.Errorf("assignment prefix %s not found in static routes (%d routes)", assignmentPrefix, len(spec.StaticRoutes))
	}

	// Generate BIRD config and verify the static route is rendered.
	importSet := assignmentPrefixes(ars)
	exportSet := authorizedPrefixes(ars, []zone.ZonePath{"node-a.catofes."})
	cfgBytes, err := bird.DefaultConfigGenerator{}.Generate(spec, importSet, exportSet)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	cfgStr := string(cfgBytes)

	if !strings.Contains(cfgStr, "protocol static") {
		t.Errorf("BIRD config missing protocol static block\n%s", cfgStr)
	}
	if !strings.Contains(cfgStr, `route 10.42.0.0/24 via "hgs-upstream0";`) {
		t.Errorf("BIRD config missing static route for 10.42.0.0/24\n%s", cfgStr)
	}

	// Verify import filter includes the assigned prefix.
	if !strings.Contains(cfgStr, "10.42.0.0/24+") {
		t.Errorf("BIRD config missing import filter for 10.42.0.0/24+\n%s", cfgStr)
	}
}

// fakeVethManager is a no-op VethManager for testing.
type fakeVethManager struct {
	ensureCalled bool
	deleteCalled bool
}

func (m *fakeVethManager) EnsureVethPair(ctx context.Context, spec bird.VethSpec) error {
	m.ensureCalled = true
	return nil
}

func (m *fakeVethManager) DeleteVethPair(ctx context.Context, spec bird.VethSpec) error {
	m.deleteCalled = true
	return nil
}