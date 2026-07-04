package main

import (
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Catofes/higgs/pkg/routing/bird"
	"github.com/Catofes/higgs/pkg/transport/ipsec"
)

func TestDebugRoutesFallbackComputesAuthorizedRouteSet(t *testing.T) {
	state, _ := buildTestNetworkStateForRouting(t)
	now := time.Unix(4000, 0)

	appConfig := defaultAppConfig()
	appConfig.DataDir = t.TempDir()
	rt := &Runtime{
		Config:    appConfig,
		StatePath: filepath.Join(t.TempDir(), "higgs.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}

	var buf strings.Builder
	if err := debugRoutesWithRuntime(rt, &buf); err != nil {
		t.Fatalf("debugRoutesWithRuntime: %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, "local_zone: node-a.catofes.") {
		t.Errorf("expected local_zone node-a.catofes., got:\n%s", out)
	}
	if !strings.Contains(out, "10.0.0.0/24") {
		t.Errorf("expected local export prefix 10.0.0.0/24, got:\n%s", out)
	}
	if !strings.Contains(out, "zone node-a.catofes.") {
		t.Errorf("expected node-a.catofes. authorized zone, got:\n%s", out)
	}
	if !strings.Contains(out, "zone node-b.catofes.") {
		t.Errorf("expected node-b.catofes. authorized zone, got:\n%s", out)
	}
	if !strings.Contains(out, "10.1.0.0/24") {
		t.Errorf("expected remote prefix 10.1.0.0/24, got:\n%s", out)
	}
	if strings.Contains(out, "authorization_errors:") && strings.Contains(out, "route_unauthorized") {
		t.Errorf("did not expect authorization errors, got:\n%s", out)
	}
}

func TestDebugRouteExplainsPrefix(t *testing.T) {
	state, _ := buildTestNetworkStateForRouting(t)
	now := time.Unix(4000, 0)

	appConfig := defaultAppConfig()
	appConfig.DataDir = t.TempDir()
	rt := &Runtime{
		Config:    appConfig,
		StatePath: filepath.Join(t.TempDir(), "higgs.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}

	var buf strings.Builder
	if err := debugRouteWithRuntime(rt, "10.0.0.0/24", &buf); err != nil {
		t.Fatalf("debugRouteWithRuntime: %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, "prefix: 10.0.0.0/24") {
		t.Errorf("expected canonical prefix, got:\n%s", out)
	}
	if !strings.Contains(out, "local_export: true") {
		t.Errorf("expected local_export true, got:\n%s", out)
	}
	if !strings.Contains(out, "authorized: true") {
		t.Errorf("expected authorized true, got:\n%s", out)
	}
	if !strings.Contains(out, "announcing_zones: node-a.catofes.") {
		t.Errorf("expected announcing zone node-a.catofes., got:\n%s", out)
	}
	if !strings.Contains(out, "assignment_assigned_to: node-a.catofes.") {
		t.Errorf("expected assignment to node-a.catofes., got:\n%s", out)
	}
}

func TestDebugRoutesShowsBirdAuthorizedCrossView(t *testing.T) {
	dump := &routesDumpResponse{
		LocalZone: "node-a.catofes.",
		ExportSet: []string{"10.0.0.0/24"},
		Authorized: map[string][]string{
			"node-a.catofes.": {"10.0.0.0/24"},
			"node-b.catofes.": {"10.1.0.0/24"},
		},
		Assignments: map[string]routeAssignmentInfo{
			"10.0.0.0/16": {Source: "catofes.", AssignedTo: "node-a.catofes."},
			"10.1.0.0/16": {Source: "catofes.", AssignedTo: "node-b.catofes."},
		},
	}
	dump.BIRD = []birdRoutesView{{
		NetNS:      "higgstesth2",
		InstanceID: "main",
		State:      birdInstanceStateRunning,
		Routes: buildBirdRouteViews(dump, []bird.BirdRoute{
			{
				Prefix:   netip.MustParsePrefix("10.1.0.0/24"),
				Protocol: "babel1",
				Iface:    "hgs-node-b",
				Metric:   96,
				Selected: true,
			},
			{
				Prefix:   netip.MustParsePrefix("10.2.0.0/24"),
				Protocol: "babel1",
				Iface:    "hgs-node-c",
				Metric:   128,
				Selected: true,
			},
		}),
	}}

	var buf strings.Builder
	if err := writeDebugRoutes(&buf, dump); err != nil {
		t.Fatalf("writeDebugRoutes: %v", err)
	}
	out := buf.String()

	for _, want := range []string{
		"bird_routes: 1 instances",
		"netns higgstesth2",
		"10.1.0.0/24 selected=true authorized=true import_allowed=true zones=node-b.catofes. protocol=babel1 iface=hgs-node-b metric=96",
		"10.2.0.0/24 selected=true authorized=false import_allowed=false protocol=babel1 iface=hgs-node-c metric=128",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output, got:\n%s", want, out)
		}
	}

	buf.Reset()
	if err := writeDebugRoute(&buf, netip.MustParsePrefix("10.1.0.0/24"), dump); err != nil {
		t.Fatalf("writeDebugRoute: %v", err)
	}
	out = buf.String()
	if !strings.Contains(out, "bird_routes: 1") {
		t.Errorf("expected one bird route match, got:\n%s", out)
	}
	if !strings.Contains(out, "netns=higgstesth2 instance=main selected=true authorized=true import_allowed=true protocol=babel1 iface=hgs-node-b metric=96") {
		t.Errorf("expected bird route detail, got:\n%s", out)
	}
}

func TestDebugBabelFallbackShowsBirdInstances(t *testing.T) {
	state, _ := buildTestNetworkStateForRouting(t)
	state.BirdInstances = map[string]*BirdInstanceState{
		"higgstesth2": {
			NetNSName:      "higgstesth2",
			RouterID:       12345,
			ControlSocket:  "/run/higgs/bird/bird-main.ctl",
			ConfigPath:     "/run/higgs/bird/bird-main.conf",
			PIDFile:        "/run/higgs/bird/bird-main.pid",
			LastConfigHash: "deadbeef1234567890abcdef1234567890abcdef",
			State:          birdInstanceStateRunning,
			LastError:      "",
		},
	}

	appConfig := defaultAppConfig()
	appConfig.DataDir = t.TempDir()
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{{
		ID:              "main",
		Provider:        ipsec.ProviderStrongSwan,
		NetNS:           ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: "higgstesth2", Create: true},
		DefaultPathMode: ipsec.PathModeFamilyRedundant,
	}}
	appConfig.Netns = netnsConfig{Names: map[string]ipsec.NetNSSpec{
		"higgstesth2": {Kind: ipsec.NetNSName, Name: "higgstesth2", Create: true},
	}}
	appConfig.Routing = routingConfig{Instances: []RoutingInstance{{
		ID:      "main",
		NetNS:   "higgstesth2",
		Enabled: true,
		Mode:    ipsec.RoutingModeManaged,
	}}}
	rt := &Runtime{
		Config:    appConfig,
		StatePath: filepath.Join(t.TempDir(), "higgs.db"),
		Clock:     func() time.Time { return time.Unix(4000, 0) },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}

	var buf strings.Builder
	if err := debugBabelWithRuntime(rt, &buf); err != nil {
		t.Fatalf("debugBabelWithRuntime: %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, "netns higgstesth2") {
		t.Errorf("expected netns higgstesth2, got:\n%s", out)
	}
	if !strings.Contains(out, "instance_id: main") {
		t.Errorf("expected instance_id main, got:\n%s", out)
	}
	if !strings.Contains(out, "mode: managed") {
		t.Errorf("expected mode managed, got:\n%s", out)
	}
	if !strings.Contains(out, "shutdown_policy: persist") {
		t.Errorf("expected shutdown_policy persist, got:\n%s", out)
	}
	if !strings.Contains(out, "router_id: 12345") {
		t.Errorf("expected router_id 12345, got:\n%s", out)
	}
	if !strings.Contains(out, "control_socket: /run/higgs/bird/bird-main.ctl") {
		t.Errorf("expected control socket, got:\n%s", out)
	}
	if !strings.Contains(out, "state: running") {
		t.Errorf("expected state running, got:\n%s", out)
	}
	if !strings.Contains(out, "last_config_hash: deadbeef1234") {
		t.Errorf("expected short config hash, got:\n%s", out)
	}
}
