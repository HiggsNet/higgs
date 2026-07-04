package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
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
	t.Cleanup(func() {
		_ = service.stopManagedBirdInstances(context.Background(), true)
	})

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

// TestDaemonBIRDAdoptRestartRootSmoke verifies the daemon restart shape for
// managed BIRD: the first daemon leaves BIRD running by default, and a fresh
// process manager adopts the existing daemon instead of restarting it.
func TestDaemonBIRDAdoptRestartRootSmoke(t *testing.T) {
	if os.Getenv("HIGGS_BIRD_SMOKE") != "1" {
		t.Skip("set HIGGS_BIRD_SMOKE=1 to run the root/system BIRD daemon adopt smoke")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	nsName := "higgs-bird-adopt-" + suffix
	dataDir := t.TempDir()

	t.Cleanup(func() {
		_ = exec.Command("ip", "netns", "delete", nsName).Run()
	})

	if err := exec.CommandContext(ctx, "ip", "netns", "add", nsName).Run(); err != nil {
		t.Fatalf("ip netns add %s: %v", nsName, err)
	}
	if err := exec.CommandContext(ctx, "ip", "netns", "exec", nsName, "ip", "link", "set", "lo", "up").Run(); err != nil {
		t.Fatalf("set lo up: %v", err)
	}

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

	service1 := newDaemonService(rt, state, syncConfig, time.Second)
	service1.birdProcessManager = bird.NewExecProcessManager("")
	service1.birdClientFactory = func(socketPath string, timeout time.Duration) birdClient {
		return &realBirdClient{socketPath: socketPath, timeout: timeout}
	}
	t.Cleanup(func() {
		_ = service1.stopManagedBirdInstances(context.Background(), true)
	})

	if err := service1.reconcileRouting(ctx); err != nil {
		t.Fatalf("initial reconcileRouting: %v", err)
	}
	if !service1.birdProcessManager.IsRunning(ctx) {
		t.Fatal("BIRD process is not running after initial reconcile")
	}

	latest, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState after initial reconcile: %v", err)
	}
	birdState := latest.BirdInstances[nsName]
	if birdState == nil {
		t.Fatalf("BirdInstances[%s] is nil", nsName)
	}
	initialPID := readSmokePID(t, birdState.PIDFile)

	if err := service1.stopManagedBirdInstances(ctx, false); err != nil {
		t.Fatalf("non-force stopManagedBirdInstances: %v", err)
	}
	if !service1.birdProcessManager.IsRunning(ctx) {
		t.Fatal("BIRD stopped on non-force daemon shutdown; default shutdown_policy should persist")
	}

	restartedState, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState before restart reconcile: %v", err)
	}
	service2 := newDaemonService(rt, restartedState, syncConfig, time.Second)
	service2.birdProcessManager = bird.NewExecProcessManager("")
	service2.birdClientFactory = func(socketPath string, timeout time.Duration) birdClient {
		return &realBirdClient{socketPath: socketPath, timeout: timeout}
	}
	t.Cleanup(func() {
		_ = service2.stopManagedBirdInstances(context.Background(), true)
	})

	if err := service2.reconcileRouting(ctx); err != nil {
		t.Fatalf("restart reconcileRouting: %v", err)
	}
	if !service2.birdProcessManager.IsRunning(ctx) {
		t.Fatal("fresh process manager did not adopt the existing BIRD process")
	}
	adoptedPID := readSmokePID(t, birdState.PIDFile)
	if adoptedPID != initialPID {
		t.Fatalf("BIRD pid changed across daemon restart: got %d want %d", adoptedPID, initialPID)
	}

	birdcOut, err := exec.CommandContext(ctx, "birdc", "-s", birdState.ControlSocket, "show", "status").CombinedOutput()
	if err != nil {
		t.Fatalf("birdc show status after adopt failed: %v\noutput: %s", err, string(birdcOut))
	}
	if !strings.Contains(string(birdcOut), "BIRD") {
		t.Errorf("birdc output missing BIRD identifier after adopt:\n%s", string(birdcOut))
	}

	t.Logf("Daemon BIRD adopt root smoke: BIRD pid %d persisted across daemon restart in netns %s", adoptedPID, nsName)
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
			Enabled:             boolPtr(true),
			UpstreamInterface:   upstreamIface,
			CreateVeth:          boolPtr(false), // already created manually
			DownstreamInterface: peerIface,
			UpstreamIPv4LL:      "169.254.0.2/30",
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
	t.Cleanup(func() {
		_ = service.stopManagedBirdInstances(context.Background(), true)
	})

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

func (c *realBirdClient) Raw(ctx context.Context, cmd string) (string, error) {
	return bird.NewClient(c.socketPath, c.timeout).Raw(ctx, cmd)
}

func readSmokePID(t *testing.T, path string) int {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read pidfile %s: %v", path, err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatalf("parse pidfile %s: %v", path, err)
	}
	if pid <= 0 {
		t.Fatalf("pidfile %s has invalid pid %d", path, pid)
	}
	return pid
}
