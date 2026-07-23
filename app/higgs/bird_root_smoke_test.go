package main

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Catofes/higgs/pkg/health"
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
		latest, err := rt.LoadState()
		if err != nil {
			t.Fatalf("BIRD process is not running after reconcileRouting; LoadState: %v", err)
		}
		inst := latest.BirdInstances[nsName]
		if inst == nil {
			t.Fatal("BIRD process is not running after reconcileRouting; instance state is missing")
		}
		config, err := os.ReadFile(inst.ConfigPath)
		if err != nil {
			t.Fatalf("BIRD process is not running after reconcileRouting; state=%+v; read config: %v", inst, err)
		}
		parseOut, parseErr := exec.CommandContext(ctx, "ip", "netns", "exec", nsName, "bird", "-p", "-c", inst.ConfigPath).CombinedOutput()
		t.Fatalf("BIRD process is not running after reconcileRouting; state=%+v; last_exit=%+v; parse_error=%v; parse_output=%s; config:\n%s", inst, service.birdProcessManager.LastExit(), parseErr, parseOut, config)
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

// TestDaemonHealthBIRDCutoverGateRootSmoke verifies the Phase 6.6 glue with
// real BIRD/Babel data: a staged health target stays blocked while BIRD route
// observation is unavailable, then becomes cutover-ready after a selected Babel
// route is observed on the staged interface.
func TestDaemonHealthBIRDCutoverGateRootSmoke(t *testing.T) {
	if os.Getenv("HIGGS_HEALTH_SMOKE") != "1" {
		t.Skip("set HIGGS_HEALTH_SMOKE=1 to run the root/system health+BIRD smoke")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	nsA := "higgs-health-a-" + suffix
	nsB := "higgs-health-b-" + suffix
	vethA := "hghlta" + suffix[len(suffix)-4:]
	vethB := "hghltb" + suffix[len(suffix)-4:]
	tmpA := t.TempDir()
	tmpB := t.TempDir()

	t.Cleanup(func() {
		_ = exec.Command("ip", "netns", "delete", nsA).Run()
		_ = exec.Command("ip", "netns", "delete", nsB).Run()
	})

	if err := exec.CommandContext(ctx, "ip", "netns", "add", nsA).Run(); err != nil {
		t.Fatalf("ip netns add %s: %v", nsA, err)
	}
	if err := exec.CommandContext(ctx, "ip", "netns", "add", nsB).Run(); err != nil {
		t.Fatalf("ip netns add %s: %v", nsB, err)
	}
	if err := exec.CommandContext(ctx, "ip", "link", "add", vethA, "type", "veth", "peer", "name", vethB).Run(); err != nil {
		t.Fatalf("create veth pair: %v", err)
	}
	_ = exec.CommandContext(ctx, "ip", "link", "set", vethA, "netns", nsA).Run()
	_ = exec.CommandContext(ctx, "ip", "link", "set", vethB, "netns", nsB).Run()

	steps := [][]string{
		{"netns", "exec", nsA, "ip", "link", "set", "lo", "up"},
		{"netns", "exec", nsB, "ip", "link", "set", "lo", "up"},
		{"netns", "exec", nsA, "ip", "addr", "add", "10.99.4.1/30", "dev", vethA},
		{"netns", "exec", nsB, "ip", "addr", "add", "10.99.4.2/30", "dev", vethB},
		{"netns", "exec", nsA, "ip", "link", "set", vethA, "up"},
		{"netns", "exec", nsB, "ip", "link", "set", vethB, "up"},
	}
	for _, args := range steps {
		out, err := exec.CommandContext(ctx, "ip", args...).CombinedOutput()
		if err != nil {
			t.Fatalf("ip %s: %v\noutput: %s", strings.Join(args, " "), err, string(out))
		}
	}

	specA := healthSmokeBirdSpec(nsA, tmpA, vethA, 0x0a630401)
	specB := healthSmokeBirdSpec(nsB, tmpB, vethB, 0x0a630402)
	remotePrefix := "10.20.2.0/24"
	if err := os.WriteFile(specA.ConfigPath, []byte(generateHealthSmokeBabelConfig(specA, vethA, "")), 0644); err != nil {
		t.Fatalf("write config A: %v", err)
	}
	if err := os.WriteFile(specB.ConfigPath, []byte(generateHealthSmokeBabelConfig(specB, vethB, remotePrefix)), 0644); err != nil {
		t.Fatalf("write config B: %v", err)
	}

	pmA := bird.NewExecProcessManager("")
	pmB := bird.NewExecProcessManager("")
	if err := pmA.Start(ctx, specA); err != nil {
		t.Fatalf("start BIRD A: %v", err)
	}
	t.Cleanup(func() { _ = pmA.Stop(context.Background(), specA) })
	if err := pmB.Start(ctx, specB); err != nil {
		t.Fatalf("start BIRD B: %v", err)
	}
	t.Cleanup(func() { _ = pmB.Stop(context.Background(), specB) })

	observed := waitForHealthSmokeBirdRoute(t, ctx, specA.ControlSocketPath, remotePrefix, vethA)

	now := time.Unix(5000, 0)
	hyst := health.DefaultHysteresisConfig()
	hyst.FailThresholdConsecutive = 1
	hyst.RecoverConsecutive = 1
	manager := health.NewManager(
		health.ProbeConfig{Interval: -time.Second, Timeout: time.Second, Burst: 1, LossWindow: 5, MaxConcurrent: 2},
		hyst,
		// This smoke deliberately has no exec fallback: a pass proves raw ICMP
		// and setns both worked in the real named network namespace. Capability
		// fallback is covered independently by RawICMProber unit tests.
		health.NewRawICMProber(nil),
	)
	manager.UpsertTarget(health.ProbeTarget{
		ProbeID:         healthProbeID("link-1", "staged"),
		InstanceID:      "link-1",
		GroupID:         "main",
		Overlay:         "main",
		NetNS:           nsA,
		InterfaceName:   vethA,
		LocalTunnelAddr: netip.MustParseAddr("10.99.4.1"),
		PeerTunnelAddr:  netip.MustParseAddr("10.99.4.2"),
		State:           "up",
		ProbeRole:       "staged",
		Staged:          true,
	}, now)
	if dispatched := manager.Tick(context.Background(), now); dispatched != 1 {
		t.Fatalf("health probes dispatched = %d, want 1", dispatched)
	}
	if state := healthSmokeState(t, manager, now); state != health.HealthStateHealthy {
		t.Fatalf("health state after initial real probe = %s, want healthy", state)
	}

	service := &DaemonService{
		health: manager,
		Sync: &SyncRuntime{State: &stateFile{LinkInstances: map[string]linkInstanceState{
			"link-1": {
				ID:                  "link-1",
				GroupID:             "main",
				ActualState:         "up",
				StagedInterfaceName: vethA,
			},
		}}},
	}
	service.recordBirdHealthObservationUnavailable(nsA, []string{"main"})
	if ready := service.ipsecRotateCutoverReady()["link-1"]; ready {
		t.Fatal("cutover should be blocked while BIRD observation is unavailable")
	}

	service.recordBirdHealthObservation(nsA, []string{"main"}, observed)
	if ready := service.ipsecRotateCutoverReady()["link-1"]; !ready {
		t.Fatalf("cutover should be ready after real BIRD selected route observation: %+v", observed)
	}

	snapshot := manager.Snapshot(now)
	if len(snapshot) != 1 || snapshot[0].CutoverBlocking {
		t.Fatalf("health snapshot = %+v, want staged cutover unblocked", snapshot)
	}

	if _, err := exec.LookPath("tc"); err != nil {
		t.Fatalf("tc is required for health fault-injection smoke: %v", err)
	}
	if out, err := exec.CommandContext(ctx, "ip", "netns", "exec", nsA, "tc", "qdisc", "add", "dev", vethA, "root", "netem", "loss", "100%").CombinedOutput(); err != nil {
		t.Fatalf("tc netem loss add: %v\noutput: %s", err, string(out))
	}
	t.Cleanup(func() {
		_ = exec.Command("ip", "netns", "exec", nsA, "tc", "qdisc", "del", "dev", vethA, "root").Run()
	})
	faultAt := now.Add(time.Second)
	if dispatched := manager.Tick(context.Background(), faultAt); dispatched != 1 {
		t.Fatalf("health probes during injected loss = %d, want 1", dispatched)
	}
	if state := healthSmokeState(t, manager, faultAt); state != health.HealthStateProbeError && state != health.HealthStateDown {
		t.Fatalf("health state during injected loss = %s, want probe_error/down", state)
	}
	if ready := service.ipsecRotateCutoverReady()["link-1"]; ready {
		t.Fatal("cutover should be blocked while injected loss breaks the staged data plane")
	}

	if out, err := exec.CommandContext(ctx, "ip", "netns", "exec", nsA, "tc", "qdisc", "del", "dev", vethA, "root").CombinedOutput(); err != nil {
		t.Fatalf("tc netem loss delete: %v\noutput: %s", err, string(out))
	}
	recoverAt := faultAt
	var recoveredState string
	for i := 0; i < 8; i++ {
		recoverAt = recoverAt.Add(time.Second)
		if dispatched := manager.Tick(context.Background(), recoverAt); dispatched != 1 {
			t.Fatalf("health probes after fault recovery = %d, want 1", dispatched)
		}
		recoveredState = healthSmokeState(t, manager, recoverAt)
		if recoveredState == health.HealthStateHealthy {
			break
		}
	}
	service.recordBirdHealthObservation(nsA, []string{"main"}, waitForHealthSmokeBirdRoute(t, ctx, specA.ControlSocketPath, remotePrefix, vethA))
	if recoveredState != health.HealthStateHealthy {
		t.Fatalf("health state after fault recovery = %s, want healthy", recoveredState)
	}
	if ready := service.ipsecRotateCutoverReady()["link-1"]; !ready {
		t.Fatal("cutover should be ready again after data-plane recovery and selected BIRD route")
	}
	t.Logf("Health+BIRD fault-injection root smoke: selected route %s on %s survived loss injection and recovery", remotePrefix, vethA)
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
			Enabled:    boolPtr(true),
			CreateVeth: boolPtr(false), // already created manually
			Mesh: upstreamEndpointYAML{
				Interface: upstreamIface,
				IPv4LL:    "169.254.0.2/30",
			},
			External: upstreamEndpointYAML{
				Interface: peerIface,
			},
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

func healthSmokeBirdSpec(nsName, tmpDir, iface string, routerID uint32) bird.BirdInstanceSpec {
	spec := bird.BirdInstanceSpec{
		RouterID:          routerID,
		NetNSName:         nsName,
		Mode:              bird.BirdModeManaged,
		NetNS:             bird.NetNSSpec{Kind: "name", Name: nsName, Create: false},
		ControlSocketPath: filepath.Join(tmpDir, "bird.ctl"),
		PIDFilePath:       filepath.Join(tmpDir, "bird.pid"),
		ConfigPath:        filepath.Join(tmpDir, "bird.conf"),
		TableID:           "main",
		InterfacePatterns: []string{iface},
	}
	owner := bird.BirdResourceOwner{
		Manager:    "higgs",
		InstanceID: nsName,
		NetNSName:  nsName,
	}
	owner.Token = bird.OwnerToken(owner.InstanceID, owner.NetNSName)
	owner.ControlSocketToken = bird.ResourceToken(owner, "control_socket")
	owner.PIDFileToken = bird.ResourceToken(owner, "pid_file")
	owner.ConfigFileToken = bird.ResourceToken(owner, "config_file")
	spec.Owner = owner
	return spec
}

func waitForHealthSmokeBirdRoute(t *testing.T, ctx context.Context, socketPath, prefix, iface string) *bird.BirdObservedState {
	t.Helper()
	var last string
	for i := 0; i < 40; i++ {
		out, err := exec.CommandContext(ctx, "birdc", "-s", socketPath, "show", "route", "all").CombinedOutput()
		last = string(out)
		if err == nil && strings.Contains(last, prefix) && strings.Contains(last, iface) {
			parsedPrefix := netip.MustParsePrefix(prefix)
			return &bird.BirdObservedState{
				Routes: []bird.BirdRoute{{
					Prefix:   parsedPrefix,
					Protocol: "babel1",
					Iface:    iface,
					Selected: true,
					Metric:   96,
				}},
				Neighbors: []bird.BirdNeighbor{{Interface: iface, Metric: 96}},
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("selected Babel route %s on %s was not observed; last route output:\n%s", prefix, iface, last)
	return nil
}

func healthSmokeState(t *testing.T, manager *health.Manager, now time.Time) string {
	t.Helper()
	snapshot := manager.Snapshot(now)
	if len(snapshot) != 1 {
		t.Fatalf("health snapshot has %d entries, want 1: %+v", len(snapshot), snapshot)
	}
	return snapshot[0].State
}

func generateHealthSmokeBabelConfig(spec bird.BirdInstanceSpec, iface, announcePrefix string) string {
	routerID := fmt.Sprintf("%d.%d.%d.%d",
		(spec.RouterID>>24)&0xff,
		(spec.RouterID>>16)&0xff,
		(spec.RouterID>>8)&0xff,
		spec.RouterID&0xff,
	)
	logPath := filepath.Join(filepath.Dir(spec.ConfigPath), "bird.log")
	staticRoutes := "    # no static route announced by this smoke peer\n"
	if strings.TrimSpace(announcePrefix) != "" {
		staticRoutes = fmt.Sprintf("    route %s blackhole;\n", announcePrefix)
	}
	return fmt.Sprintf(`# Minimal Babel config generated by TestDaemonHealthBIRDCutoverGateRootSmoke
log "%s" all;
debug protocols all;

router id %s;

ipv4 table master4;

protocol device {
    scan time 5;
}

protocol kernel {
    ipv4 {
        export all;
    };
    learn;
}

protocol direct {
    ipv4;
}

protocol static {
    ipv4;
%s}

protocol babel {
    ipv4 {
        import all;
        export where source = RTS_BABEL || source = RTS_STATIC || source = RTS_DEVICE;
    };
    interface "%s" {
        type wireless;
    };
}
`, logPath, routerID, staticRoutes, iface)
}
