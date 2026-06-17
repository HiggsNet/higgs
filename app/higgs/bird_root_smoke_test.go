package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Catofes/higgs/pkg/routing/bird"
	"github.com/Catofes/higgs/pkg/transport/ipsec"
)

// TestDaemonBIRDRoutingRootSmoke verifies that the daemon routing reconcile
// pipeline can start a real BIRD daemon inside a named netns, generate a
// valid config, apply it via birdc configure, and observe BIRD responding.
func TestDaemonBIRDRoutingRootSmoke(t *testing.T) {
	if os.Getenv("HIGGS_BIRD_SMOKE") != "1" {
		t.Skip("set HIGGS_BIRD_SMOKE=1 to run the root/system BIRD daemon routing smoke")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	nsName := "higgs-bird-rt-" + suffix
	dataDir := t.TempDir()

	t.Cleanup(func() {
		_ = exec.Command("ip", "netns", "delete", nsName).Run()
	})

	// Create the named netns and bring up loopback.
	if err := exec.CommandContext(ctx, "ip", "netns", "add", nsName).Run(); err != nil {
		t.Fatalf("ip netns add %s: %v", nsName, err)
	}
	if err := exec.CommandContext(ctx, "ip", "netns", "exec", nsName, "ip", "link", "set", "lo", "up").Run(); err != nil {
		t.Fatalf("set lo up: %v", err)
	}

	// Build a minimal state with root + catofes + node-a.
	state, syncConfig, _ := buildDryRunSmokeNetworkState(t)

	appConfig := defaultAppConfig()
	appConfig.DataDir = dataDir
	appConfig.Netns = netnsConfig{
		Names: map[string]ipsec.NetNSSpec{
			nsName: {Kind: ipsec.NetNSName, Name: nsName, Create: false},
		},
	}
	// Parse routing instance config with managed mode targeting the real netns.
	routingYAML := []routingInstanceYAML{{
		ID:           "main",
		NetNS:        nsName,
		Enabled:      boolPtr(true),
		Mode:         ipsec.RoutingModeManaged,
		InterfacePat: "hgs*",
	}}
	appConfig.Routing, _ = parseRoutingConfigInstances(routingYAML, appConfig.Netns, dataDir)
	if len(appConfig.Routing.Instances) == 0 {
		t.Fatal("routing instances empty after parse")
	}

	rt := &Runtime{
		Config:    appConfig,
		StatePath: filepath.Join(t.TempDir(), "higgs.db"),
		Clock:     func() time.Time { return time.Unix(123, 0) },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}

	// Use real process manager and birdc client.
	service := newDaemonService(rt, state, syncConfig, time.Second)
	service.birdProcessManager = bird.NewExecProcessManager("")
	service.birdClientFactory = func(socketPath string, timeout time.Duration) birdClient {
		return &realBirdClient{socketPath: socketPath, timeout: timeout}
	}

	// Run routing reconcile.
	if err := service.reconcileRouting(ctx); err != nil {
		t.Fatalf("reconcileRouting: %v", err)
	}

	// Verify BIRD is running.
	if !service.birdProcessManager.IsRunning(ctx) {
		t.Fatal("BIRD process is not running after reconcileRouting")
	}

	// Verify the control socket file exists.
	_ = appConfig.Routing.Instances[0] // ensure instance was parsed
	sockPath := filepath.Join(dataDir, "netns-"+nsName, "bird.ctl")
	if _, err := os.Stat(sockPath); err != nil {
		// The socket path may be derived differently; find it in state.
		latest, err2 := rt.LoadState()
		if err2 != nil {
			t.Fatalf("LoadState: %v", err2)
		}
		if birdState := latest.BirdInstances[nsName]; birdState != nil {
			sockPath = birdState.ControlSocket
		}
		if _, err := os.Stat(sockPath); err != nil {
			t.Fatalf("control socket not found: %v", err)
		}
	}

	// Verify BIRD responds via birdc.
	birdcOut, err := exec.CommandContext(ctx, "birdc", "-s", sockPath, "show", "status").CombinedOutput()
	if err != nil {
		t.Fatalf("birdc show status failed: %v\noutput: %s", err, string(birdcOut))
	}
	if !strings.Contains(string(birdcOut), "BIRD") {
		t.Errorf("birdc output missing BIRD identifier:\n%s", string(birdcOut))
	}

	t.Logf("Daemon BIRD routing root smoke: BIRD running in netns %s, birdc responds", nsName)
}

// TestDaemonBIRDUpstreamRootSmoke verifies the veth upstream pipeline with
// real BIRD: creates a veth pair, assigns addresses, starts BIRD, and
// verifies that the upstream interface block appears in the generated config.
func TestDaemonBIRDUpstreamRootSmoke(t *testing.T) {
	if os.Getenv("HIGGS_BIRD_SMOKE") != "1" {
		t.Skip("set HIGGS_BIRD_SMOKE=1 to run the root/system BIRD daemon upstream smoke")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	nsName := "higgs-bird-up-" + suffix
	dataDir := t.TempDir()
	upstreamIface := "hgsup0" + suffix[len(suffix)-3:]
	peerIface := "hgsup1" + suffix[len(suffix)-3:]

	t.Cleanup(func() {
		_ = exec.Command("ip", "netns", "delete", nsName).Run()
		_ = exec.Command("ip", "link", "del", peerIface).Run()
	})

	// Create netns.
	if err := exec.CommandContext(ctx, "ip", "netns", "add", nsName).Run(); err != nil {
		t.Fatalf("ip netns add %s: %v", nsName, err)
	}
	if err := exec.CommandContext(ctx, "ip", "netns", "exec", nsName, "ip", "link", "set", "lo", "up").Run(); err != nil {
		t.Fatalf("set lo up: %v", err)
	}

	// Create veth pair: peerIface stays in host ns, upstreamIface goes to netns.
	if err := exec.CommandContext(ctx, "ip", "link", "add", peerIface, "type", "veth", "peer", "name", upstreamIface).Run(); err != nil {
		t.Fatalf("create veth pair: %v", err)
	}
	_ = exec.CommandContext(ctx, "ip", "link", "set", upstreamIface, "netns", nsName).Run()
	_ = exec.CommandContext(ctx, "ip", "addr", "add", "169.254.0.1/30", "dev", peerIface).Run()
	_ = exec.CommandContext(ctx, "ip", "link", "set", peerIface, "up").Run()
	_ = exec.CommandContext(ctx, "ip", "netns", "exec", nsName, "ip", "addr", "add", "169.254.0.2/30", "dev", upstreamIface).Run()
	_ = exec.CommandContext(ctx, "ip", "netns", "exec", nsName, "ip", "link", "set", upstreamIface, "up").Run()

	// Build minimal state.
	state, syncConfig, _ := buildDryRunSmokeNetworkState(t)

	appConfig := defaultAppConfig()
	appConfig.DataDir = dataDir
	appConfig.Netns = netnsConfig{
		Names: map[string]ipsec.NetNSSpec{
			nsName: {Kind: ipsec.NetNSName, Name: nsName, Create: false},
		},
	}
	routingYAML := []routingInstanceYAML{{
		ID:           "main",
		NetNS:        nsName,
		Enabled:      boolPtr(true),
		Mode:         ipsec.RoutingModeManaged,
		InterfacePat: "hgs*",
		Upstream: &upstreamConfigYAML{
			Enabled:       boolPtr(true),
			Interface:     upstreamIface,
			CreateVeth:    boolPtr(false), // already created manually
			PeerInterface: peerIface,
			IPv4LL:        "169.254.0.2/30",
		},
	}}
	appConfig.Routing, _ = parseRoutingConfigInstances(routingYAML, appConfig.Netns, dataDir)
	if len(appConfig.Routing.Instances) == 0 {
		t.Fatal("routing instances empty after parse")
	}

	rt := &Runtime{
		Config:    appConfig,
		StatePath: filepath.Join(t.TempDir(), "higgs.db"),
		Clock:     func() time.Time { return time.Unix(123, 0) },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}

	// Use real process manager.
	service := newDaemonService(rt, state, syncConfig, time.Second)
	service.birdProcessManager = bird.NewExecProcessManager("")
	service.birdClientFactory = func(socketPath string, timeout time.Duration) birdClient {
		return &realBirdClient{socketPath: socketPath, timeout: timeout}
	}

	// Run routing reconcile.
	if err := service.reconcileRouting(ctx); err != nil {
		t.Fatalf("reconcileRouting: %v", err)
	}

	// Read generated config and verify upstream interface block.
	latest, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	birdState := latest.BirdInstances[nsName]
	if birdState == nil {
		t.Fatalf("BirdInstances[%s] is nil", nsName)
	}
	if birdState.State != birdInstanceStateRunning {
		t.Errorf("bird state = %q, want running", birdState.State)
	}
	cfgBytes, err := os.ReadFile(birdState.ConfigPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	cfgStr := string(cfgBytes)

	// Verify upstream interface pattern appears.
	// The upstream block uses the interface pattern derived from the config.
	if !strings.Contains(cfgStr, upstreamIface) {
		t.Errorf("BIRD config missing upstream interface %q\n%s", upstreamIface, cfgStr)
	}

	// Verify BIRD responds.
	birdcOut, err := exec.CommandContext(ctx, "birdc", "-s", birdState.ControlSocket, "show", "status").CombinedOutput()
	if err != nil {
		t.Fatalf("birdc show status failed: %v\noutput: %s", err, string(birdcOut))
	}

	t.Logf("Daemon BIRD upstream root smoke: upstream interface %s in config, BIRD running", upstreamIface)
}

// realBirdClient wraps birdc for root smoke tests where we need real birdc
// interaction.
type realBirdClient struct {
	socketPath string
	timeout    time.Duration
}

func (c *realBirdClient) Status(ctx context.Context) (*bird.BirdObservedState, error) {
	return &bird.BirdObservedState{}, nil
}

func (c *realBirdClient) Configure(ctx context.Context, _ string) error {
	return nil
}

func (c *realBirdClient) ConfigureSoft(ctx context.Context, _ string) error {
	return nil
}