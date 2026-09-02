package main

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
	"github.com/urfave/cli/v3"
)

func TestParseBirdBabelDetailAddsPhotonInterfaceContext(t *testing.T) {
	contexts := map[string]inspect.BirdInterfaceContext{
		"phx31d438dd": {Name: "phx31d438dd", Zone: "node-b.catofes.", Family: "ipv6", LinkID: "link-b"},
	}
	neighbors := parseBirdBabelNeighbors(`photon_babel_photon:
IP address                Interface  Metric Routes Hellos Expires Auth  RTT (ms)
fe80::93db:7db6:82ab:e22b phx31d438dd    100      1     16   5.640 No       3.280
`, contexts)
	if len(neighbors) != 1 || neighbors[0].Zone != "node-b.catofes." || neighbors[0].Family != "ipv6" || neighbors[0].RTT != "3.280" {
		t.Fatalf("neighbors = %#v", neighbors)
	}

	routes := parseBirdBabelRoutes(`photon_babel_photon:
Prefix                   Nexthop                   Interface Metric F Seqno Expires
2a0d:2905:1:3::/64       fe80::93db:7db6:82ab:e22b phx31d438dd   100 *   459  12.803
`, contexts)
	if len(routes) != 1 || routes[0].Flag != "*" || routes[0].Seqno != "459" || routes[0].Zone != "node-b.catofes." {
		t.Fatalf("routes = %#v", routes)
	}

	entries := parseBirdBabelEntries(`photon_babel_photon:
Prefix                   Router ID               Metric Seqno  Routes Sources
2a0d:2905:1:3::/64       00:00:00:00:56:35:60:b7    100   459      13       1
`, routes, contexts)
	if len(entries) != 1 || entries[0].Interface != "phx31d438dd" || entries[0].Zone != "node-b.catofes." || entries[0].Sources != "1" {
		t.Fatalf("entries = %#v", entries)
	}
}

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
			want: []string{"show status", "show protocols all", "show babel neighbors", "show babel routes", "show babel entries"},
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
			want: []string{"show route table all where source = RTS_BABEL all", "show babel routes"},
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
	verified, checkpoint, runtime, _ := buildTestRoutingOwners(t)
	now := time.Unix(4000, 0)

	appConfig := defaultAppConfig()
	appConfig.DataDir = t.TempDir()
	rt := &Runtime{
		Config:         appConfig,
		StatePath:      filepath.Join(t.TempDir(), "photon.db"),
		Clock:          func() time.Time { return now },
		DisableControl: true,
	}
	seedPartitionedStateDB(t, rt.StatePath, verified, checkpoint, runtime)

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
	verified, checkpoint, runtime, _ := buildTestRoutingOwners(t)
	now := time.Unix(4000, 0)

	appConfig := defaultAppConfig()
	appConfig.DataDir = t.TempDir()
	rt := &Runtime{
		Config:         appConfig,
		StatePath:      filepath.Join(t.TempDir(), "photon.db"),
		Clock:          func() time.Time { return now },
		DisableControl: true,
	}
	seedPartitionedStateDB(t, rt.StatePath, verified, checkpoint, runtime)

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

func TestDebugBabelRequiresOnlineDaemon(t *testing.T) {
	appConfig := defaultAppConfig()
	appConfig.DataDir = t.TempDir()
	rt := &Runtime{
		Config:         appConfig,
		Clock:          func() time.Time { return time.Unix(4000, 0) },
		DisableControl: true,
	}

	var buf strings.Builder
	if err := debugBabelWithRuntime(rt, &buf); err == nil || !strings.Contains(err.Error(), "requires a running daemon") {
		t.Fatalf("debugBabelWithRuntime error = %v", err)
	}
}
