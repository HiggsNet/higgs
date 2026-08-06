package main

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Catofes/photon/pkg/transport/ipsec"
	"github.com/urfave/cli/v3"
)

func TestDebugRoutingCommandsAreConsolidated(t *testing.T) {
	debug := cmdDebug()
	routing := debugCommandByName(t, debug.Commands, "routing")
	if routing.Hidden {
		t.Fatal("canonical routing command must be visible")
	}

	wantChildren := []string{"status", "routes", "bird", "ip", "reload"}
	if len(routing.Commands) != len(wantChildren) {
		t.Fatalf("routing subcommands = %d, want %d", len(routing.Commands), len(wantChildren))
	}
	for i, want := range wantChildren {
		if got := routing.Commands[i].Name; got != want {
			t.Errorf("routing subcommand %d = %q, want %q", i, got, want)
		}
		if routing.Commands[i].Hidden {
			t.Errorf("canonical routing subcommand %q is hidden", want)
		}
	}

	bird := debugCommandByName(t, routing.Commands, "bird")
	wantBirdChildren := []string{"status", "interface", "filter", "route"}
	if len(bird.Commands) != len(wantBirdChildren) {
		t.Fatalf("bird subcommands = %d, want %d", len(bird.Commands), len(wantBirdChildren))
	}
	for i, want := range wantBirdChildren {
		if got := bird.Commands[i].Name; got != want {
			t.Errorf("bird subcommand %d = %q, want %q", i, got, want)
		}
	}

	ip := debugCommandByName(t, routing.Commands, "ip")
	if len(ip.Commands) != 1 || ip.Commands[0].Name != "route" {
		t.Fatalf("routing ip subcommands = %#v, want route", ip.Commands)
	}

	for _, name := range []string{"route", "routes", "babel", "babeld", "bird-dump", "routing-reload"} {
		if commandByName(debug.Commands, name) != nil {
			t.Errorf("legacy debug command %q must be removed", name)
		}
	}
}

func TestDebugHelpOnlyAdvertisesRoutingEntryPoint(t *testing.T) {
	command := rootCommand()
	var stdout, stderr strings.Builder
	command.Writer = &stdout
	command.ErrWriter = &stderr

	if err := command.Run(context.Background(), []string{"photon", "debug", "--help"}); err != nil {
		t.Fatalf("debug help: %v\nstderr:\n%s", err, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "routing") || !strings.Contains(out, "Inspect and reconcile routing") {
		t.Fatalf("debug help does not advertise the routing entry point:\n%s", out)
	}
	for _, legacy := range []string{"route ", "routes ", "babel ", "babeld ", "bird-dump ", "routing-reload "} {
		if strings.Contains(out, legacy) {
			t.Errorf("debug help still advertises legacy command %q:\n%s", strings.TrimSpace(legacy), out)
		}
	}
}

func debugCommandByName(t *testing.T, commands []*cli.Command, name string) *cli.Command {
	t.Helper()
	if command := commandByName(commands, name); command != nil {
		return command
	}
	t.Fatalf("command %q not found", name)
	return nil
}

func commandByName(commands []*cli.Command, name string) *cli.Command {
	for _, command := range commands {
		if command.Name == name {
			return command
		}
	}
	return nil
}

func TestBirdDebugCommandsUseLiveBabelViews(t *testing.T) {
	tests := []struct {
		view birdDebugView
		want []string
	}{
		{
			view: birdDebugStatus,
			want: []string{"show status", "show protocols all", "show babel neighbors"},
		},
		{
			view: birdDebugInterface,
			want: []string{"show interfaces"},
		},
		{
			view: birdDebugFilter,
			want: []string{"show symbols filter"},
		},
		{
			view: birdDebugRoute,
			want: []string{"show route table all where source = RTS_BABEL all"},
		},
	}
	for _, tt := range tests {
		got, err := birdDebugCommands(tt.view)
		if err != nil {
			t.Fatalf("birdDebugCommands(%q): %v", tt.view, err)
		}
		if strings.Join(got, "\n") != strings.Join(tt.want, "\n") {
			t.Errorf("birdDebugCommands(%q) = %#v, want %#v", tt.view, got, tt.want)
		}
	}
}

func TestExtractBirdFilterDefinitionsExcludesOtherConfig(t *testing.T) {
	config := `router id 10.0.0.1;

filter photon_import_main {
    if net ~ [ 10.0.0.0/8+ ] then accept;
    reject;
}

filter photon_export_main {
    if net ~ [ 10.1.0.0/24 ] then accept;
    reject;
}

protocol babel photon_babel_main {
    auth "mac" key id 1 password "do-not-print";
}`
	got := extractBirdFilterDefinitions(config)
	for _, want := range []string{"filter photon_import_main", "10.0.0.0/8+", "filter photon_export_main", "10.1.0.0/24"} {
		if !strings.Contains(got, want) {
			t.Errorf("filter definitions missing %q:\n%s", want, got)
		}
	}
	for _, unwanted := range []string{"router id", "protocol babel", "do-not-print"} {
		if strings.Contains(got, unwanted) {
			t.Errorf("filter definitions contain %q:\n%s", unwanted, got)
		}
	}
}

func TestDebugRoutesFallbackComputesAuthorizedRouteSet(t *testing.T) {
	state, _ := buildTestNetworkStateForRouting(t)
	now := time.Unix(4000, 0)

	appConfig := defaultAppConfig()
	appConfig.DataDir = t.TempDir()
	rt := &Runtime{
		Config:    appConfig,
		StatePath: filepath.Join(t.TempDir(), "photon.db"),
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
		StatePath: filepath.Join(t.TempDir(), "photon.db"),
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
		"photontesth2": {
			NetNSName:      "photontesth2",
			RouterID:       12345,
			ControlSocket:  "/run/photon/bird/bird-main.ctl",
			ConfigPath:     "/run/photon/bird/bird-main.conf",
			PIDFile:        "/run/photon/bird/bird-main.pid",
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
		NetNS:           ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: "photontesth2", Create: true},
		DefaultPathMode: ipsec.PathModeFamilyRedundant,
	}}
	appConfig.Netns = netnsConfig{Names: map[string]ipsec.NetNSSpec{
		"photontesth2": {Kind: ipsec.NetNSName, Name: "photontesth2", Create: true},
	}}
	appConfig.Routing = routingConfig{Instances: []RoutingInstance{{
		ID:      "main",
		NetNS:   "photontesth2",
		Enabled: true,
		Mode:    ipsec.RoutingModeManaged,
	}}}
	rt := &Runtime{
		Config:    appConfig,
		StatePath: filepath.Join(t.TempDir(), "photon.db"),
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

	if !strings.Contains(out, "netns photontesth2") {
		t.Errorf("expected netns photontesth2, got:\n%s", out)
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
	if !strings.Contains(out, "control_socket: /run/photon/bird/bird-main.ctl") {
		t.Errorf("expected control socket, got:\n%s", out)
	}
	if !strings.Contains(out, "state: running") {
		t.Errorf("expected state running, got:\n%s", out)
	}
	if !strings.Contains(out, "last_config_hash: deadbeef1234") {
		t.Errorf("expected short config hash, got:\n%s", out)
	}
}
