package main

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

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

func TestDebugBabelFallbackShowsBirdInstances(t *testing.T) {
	state, _ := buildTestNetworkStateForRouting(t)
	state.BirdInstances = map[string]*BirdInstanceState{
		"h2": {
			NetNSName:      "h2",
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
		NetNS:           ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: "h2", Create: true},
		DefaultPathMode: ipsec.PathModeFamilyRedundant,
		Direction:       ipsec.DirectionOutbound,
	}}
	appConfig.Netns = netnsConfig{Names: map[string]ipsec.NetNSSpec{
		"h2": {Kind: ipsec.NetNSName, Name: "h2", Create: true},
	}}
	appConfig.Routing = routingConfig{Instances: []RoutingInstance{{
		ID:      "main",
		NetNS:   "h2",
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

	if !strings.Contains(out, "netns h2") {
		t.Errorf("expected netns h2, got:\n%s", out)
	}
	if !strings.Contains(out, "instance_id: main") {
		t.Errorf("expected instance_id main, got:\n%s", out)
	}
	if !strings.Contains(out, "mode: managed") {
		t.Errorf("expected mode managed, got:\n%s", out)
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
