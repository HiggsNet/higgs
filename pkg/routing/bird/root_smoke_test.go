package bird

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestExecProcessManagerRootSmoke verifies that ExecProcessManager can
// start and stop a real BIRD daemon inside a named network namespace.
// It requires root or CAP_NET_ADMIN + CAP_SYS_ADMIN and bird/birdc on PATH.
func TestExecProcessManagerRootSmoke(t *testing.T) {
	if os.Getenv("HIGGS_BIRD_SMOKE") != "1" {
		t.Skip("set HIGGS_BIRD_SMOKE=1 to run the root/system BIRD process manager smoke")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	nsName := "higgs-bird-pm-" + suffix
	tmpDir := t.TempDir()

	t.Cleanup(func() {
		_ = exec.Command("ip", "netns", "delete", nsName).Run()
	})

	// Create the named netns.
	if err := exec.CommandContext(ctx, "ip", "netns", "add", nsName).Run(); err != nil {
		t.Fatalf("ip netns add %s: %v", nsName, err)
	}

	// Set lo up inside the netns so BIRD can bind.
	if err := exec.CommandContext(ctx, "ip", "netns", "exec", nsName, "ip", "link", "set", "lo", "up").Run(); err != nil {
		t.Fatalf("set lo up in %s: %v", nsName, err)
	}

	spec := BirdInstanceSpec{
		RouterID:           0x0a000001, // 10.0.0.1
		NetNSName:          nsName,
		Mode:               BirdModeManaged,
		NetNS:              NetNSSpec{Kind: "name", Name: nsName, Create: false},
		ControlSocketPath:  filepath.Join(tmpDir, "bird.ctl"),
		PIDFilePath:        filepath.Join(tmpDir, "bird.pid"),
		ConfigPath:         filepath.Join(tmpDir, "bird.conf"),
		TableID:            "main",
		InterfacePatterns:  []string{"hgs*"},
		MetricBase:         100,
		MetricStaged:       200,
		MetricDraining:     500,
	}

	// Generate a minimal BIRD config.
	gen := DefaultConfigGenerator{}
	importSet := []netip.Prefix{}
	exportSet := []netip.Prefix{}
	cfgBytes, err := gen.Generate(spec, importSet, exportSet)
	if err != nil {
		t.Fatalf("Generate config: %v", err)
	}
	if err := os.WriteFile(spec.ConfigPath, cfgBytes, 0644); err != nil {
		t.Fatalf("WriteFile config: %v", err)
	}

	// Start BIRD via ExecProcessManager.
	pm := NewExecProcessManager("")
	pm.socketWaitTimeout = 5 * time.Second
	if err := pm.Start(ctx, spec); err != nil {
		t.Fatalf("ProcessManager.Start: %v", err)
	}

	t.Cleanup(func() {
		_ = pm.Stop(context.Background(), spec)
	})

	if !pm.IsRunning(ctx) {
		t.Fatal("BIRD process is not running after Start")
	}

	// Verify the control socket exists.
	if _, err := os.Stat(spec.ControlSocketPath); err != nil {
		t.Fatalf("control socket not found at %s: %v", spec.ControlSocketPath, err)
	}

	// Use birdc to verify BIRD responds.
	birdcOut, err := exec.CommandContext(ctx, "birdc", "-s", spec.ControlSocketPath, "show", "status").CombinedOutput()
	if err != nil {
		t.Fatalf("birdc show status failed: %v\noutput: %s", err, string(birdcOut))
	}
	if !strings.Contains(string(birdcOut), "BIRD") {
		t.Errorf("birdc output missing BIRD identifier:\n%s", string(birdcOut))
	}

	// Stop BIRD via ProcessManager.
	if err := pm.Stop(ctx, spec); err != nil {
		t.Fatalf("ProcessManager.Stop: %v", err)
	}

	// Verify cleanup.
	if pm.IsRunning(ctx) {
		t.Error("BIRD process still running after Stop")
	}
	if _, err := os.Stat(spec.PIDFilePath); !os.IsNotExist(err) {
		t.Errorf("PIDFile still exists after Stop: %v", err)
	}
}

// TestBabelTwoNodeRootSmoke creates two named network namespaces connected
// by a veth pair, starts a BIRD daemon in each running Babel, and verifies
// that Babel neighbors are discovered and a route from one side is learned
// by the other.
func TestBabelTwoNodeRootSmoke(t *testing.T) {
	if os.Getenv("HIGGS_BIRD_SMOKE") != "1" {
		t.Skip("set HIGGS_BIRD_SMOKE=1 to run the root/system BIRD Babel two-node smoke")
	}

	// In container environments, IPv6 Babel may fail due to neighbor
	// resolution limitations. The test uses IPv4 prefixes which are more
	// reliable across container runtimes.
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	nsA := "higgs-bird-a-" + suffix
	nsB := "higgs-bird-b-" + suffix
	vethA := "hgbirda" + suffix[len(suffix)-4:]
	vethB := "hgbirdb" + suffix[len(suffix)-4:]
	tmpA := t.TempDir()
	tmpB := t.TempDir()

	t.Cleanup(func() {
		_ = exec.Command("ip", "netns", "delete", nsA).Run()
		_ = exec.Command("ip", "netns", "delete", nsB).Run()
	})

	// Create namespaces.
	if err := exec.CommandContext(ctx, "ip", "netns", "add", nsA).Run(); err != nil {
		t.Fatalf("ip netns add %s: %v", nsA, err)
	}
	if err := exec.CommandContext(ctx, "ip", "netns", "add", nsB).Run(); err != nil {
		t.Fatalf("ip netns add %s: %v", nsB, err)
	}

	// Create veth pair connecting the namespaces.
	if err := exec.CommandContext(ctx, "ip", "link", "add", vethA, "type", "veth", "peer", "name", vethB).Run(); err != nil {
		t.Fatalf("create veth pair: %v", err)
	}
	exec.CommandContext(ctx, "ip", "netns", "exec", nsA, "ip", "link", "del", vethA).Run()
	_ = exec.CommandContext(ctx, "ip", "link", "set", vethA, "netns", nsA).Run()
	_ = exec.CommandContext(ctx, "ip", "link", "set", vethB, "netns", nsB).Run()

	// Configure interfaces.
	steps := [][]string{
		{"netns", "exec", nsA, "ip", "link", "set", "lo", "up"},
		{"netns", "exec", nsB, "ip", "link", "set", "lo", "up"},
		{"netns", "exec", nsA, "ip", "addr", "add", "10.99.1.1/30", "dev", vethA},
		{"netns", "exec", nsB, "ip", "addr", "add", "10.99.1.2/30", "dev", vethB},
		{"netns", "exec", nsA, "ip", "link", "set", vethA, "up"},
		{"netns", "exec", nsB, "ip", "link", "set", vethB, "up"},
	}
	for _, args := range steps {
		out, err := exec.CommandContext(ctx, "ip", args...).CombinedOutput()
		if err != nil {
			t.Fatalf("ip %s: %v\noutput: %s", strings.Join(args, " "), err, string(out))
		}
	}

	// Prepare BIRD configs for both sides.
	specA := BirdInstanceSpec{
		RouterID:           0x0a630101, // 10.99.1.1
		NetNSName:          nsA,
		Mode:               BirdModeManaged,
		NetNS:              NetNSSpec{Kind: "name", Name: nsA, Create: false},
		ControlSocketPath:  filepath.Join(tmpA, "bird.ctl"),
		PIDFilePath:        filepath.Join(tmpA, "bird.pid"),
		ConfigPath:         filepath.Join(tmpA, "bird.conf"),
		TableID:            "main",
		InterfacePatterns:  []string{vethA},
		MetricBase:         100,
		MetricStaged:       200,
		MetricDraining:     500,
	}
	specB := BirdInstanceSpec{
		RouterID:           0x0a630102, // 10.99.1.2
		NetNSName:          nsB,
		Mode:               BirdModeManaged,
		NetNS:              NetNSSpec{Kind: "name", Name: nsB, Create: false},
		ControlSocketPath:  filepath.Join(tmpB, "bird.ctl"),
		PIDFilePath:        filepath.Join(tmpB, "bird.pid"),
		ConfigPath:         filepath.Join(tmpB, "bird.conf"),
		TableID:            "main",
		InterfacePatterns:  []string{vethB},
		MetricBase:         100,
		MetricStaged:       200,
		MetricDraining:     500,
	}

	// The BIRD config generator normally targets "hgs*" tunnel interfaces.
	// For the root smoke we use a raw config that works with a regular veth.
	// We generate a minimal config manually to avoid the generator's tunnel-
	// specific assumptions.
	cfgA := generateMinimalBabelConfig(specA, vethA, "10.0.1.0/24")
	cfgB := generateMinimalBabelConfig(specB, vethB, "10.0.2.0/24")
	if err := os.WriteFile(specA.ConfigPath, []byte(cfgA), 0644); err != nil {
		t.Fatalf("write config A: %v", err)
	}
	if err := os.WriteFile(specB.ConfigPath, []byte(cfgB), 0644); err != nil {
		t.Fatalf("write config B: %v", err)
	}

	// Start BIRD in each namespace.
	pmA := NewExecProcessManager("")
	pmA.socketWaitTimeout = 5 * time.Second
	pmB := NewExecProcessManager("")
	pmB.socketWaitTimeout = 5 * time.Second

	if err := pmA.Start(ctx, specA); err != nil {
		t.Fatalf("start BIRD A: %v", err)
	}
	t.Cleanup(func() { _ = pmA.Stop(context.Background(), specA) })

	if err := pmB.Start(ctx, specB); err != nil {
		t.Fatalf("start BIRD B: %v", err)
	}
	t.Cleanup(func() { _ = pmB.Stop(context.Background(), specB) })

	// Wait for Babel neighbor to appear.
	dumpOnFail := func() {
		for _, pair := range []struct{ ns, sock string }{
			{nsA, specA.ControlSocketPath},
			{nsB, specB.ControlSocketPath},
		} {
			out, _ := exec.CommandContext(ctx, "birdc", "-s", pair.sock, "show", "protocols", "all").CombinedOutput()
			t.Logf("--- birdc show protocols all in %s ---\n%s", pair.ns, string(out))
			routes, _ := exec.CommandContext(ctx, "birdc", "-s", pair.sock, "show", "route").CombinedOutput()
			t.Logf("--- routes in %s ---\n%s", pair.ns, string(routes))
			links, _ := exec.CommandContext(ctx, "ip", "netns", "exec", pair.ns, "ip", "addr").CombinedOutput()
			t.Logf("--- ip addr in %s ---\n%s", pair.ns, string(links))
		}
	}
	defer func() {
		if t.Failed() {
			dumpOnFail()
		}
	}()

	// Poll for Babel neighbor establishment (up to 20 seconds).
	neighborFound := false
	for i := 0; i < 40; i++ {
		out, err := exec.CommandContext(ctx, "birdc", "-s", specA.ControlSocketPath, "show", "protocols").CombinedOutput()
		if err == nil && strings.Contains(string(out), "babel1") && strings.Contains(string(out), "Running") {
			neighborFound = true
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if !neighborFound {
		t.Fatal("Babel protocol did not reach Running state in namespace A within 20s")
	}

	// Poll for route learning: B should learn 10.0.1.0/24 from A.
	routeLearned := false
	for i := 0; i < 40; i++ {
		out, err := exec.CommandContext(ctx, "birdc", "-s", specB.ControlSocketPath, "show", "route").CombinedOutput()
		if err == nil && strings.Contains(string(out), "10.0.1.0/24") {
			routeLearned = true
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if !routeLearned {
		t.Fatal("BIRD B did not learn route 10.0.1.0/24 from A within 20s")
	}
	t.Logf("Babel two-node root smoke: B learned route 10.0.1.0/24 from A")
}

// generateMinimalBabelConfig produces a minimal BIRD 2.x config that:
// - Uses the given interface for Babel (without type tunnel)
// - Announces the given prefix via protocol static
// - Exports the static route to Babel and imports Babel routes to kernel
func generateMinimalBabelConfig(spec BirdInstanceSpec, iface, announcePrefix string) string {
	routerID := fmt.Sprintf("%d.%d.%d.%d",
		(spec.RouterID>>24)&0xff,
		(spec.RouterID>>16)&0xff,
		(spec.RouterID>>8)&0xff,
		spec.RouterID&0xff,
	)
	logPath := filepath.Join(filepath.Dir(spec.ConfigPath), "bird.log")
	return fmt.Sprintf(`# Minimal Babel config generated by TestBabelTwoNodeRootSmoke
log "%s" all;
debug protocols all;

router id %s;

ipv4 table master4;
ipv6 table master6;

protocol device {
    scan time 5;
}

protocol kernel {
    ipv4 {
        export all;
    };
    learn;
}

protocol kernel {
    ipv6 {
        export all;
    };
    learn;
}

protocol direct {
    ipv4;
    ipv6;
}

protocol static {
    ipv4;
    route %s blackhole;
}

protocol babel {
    ipv4 {
        import all;
        export where source = RTS_BABEL || source = RTS_STATIC || source = RTS_DEVICE;
    };
    ipv6 {
        import all;
        export where source = RTS_BABEL || source = RTS_STATIC || source = RTS_DEVICE;
    };
    interface "%s" {
        type wireless;
    };
}
`, logPath, routerID, announcePrefix, iface)
}