package bird

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// TestExecProcessManagerRootSmoke verifies that ExecProcessManager can
// start and stop a real BIRD daemon inside a named network namespace.
// It requires root or CAP_NET_ADMIN + CAP_SYS_ADMIN and bird/birdc on PATH.
func TestExecProcessManagerRootSmoke(t *testing.T) {
	if os.Getenv("PHOTON_BIRD_SMOKE") != "1" {
		t.Skip("set PHOTON_BIRD_SMOKE=1 to run the root/system BIRD process manager smoke")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	nsName := "photon-bird-pm-" + suffix
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
		RouterID:          0x0a000001, // 10.0.0.1
		NetNSName:         nsName,
		Mode:              BirdModeManaged,
		NetNS:             NetNSSpec{Kind: "name", Name: nsName, Create: false},
		ControlSocketPath: filepath.Join(tmpDir, "bird.ctl"),
		PIDFilePath:       filepath.Join(tmpDir, "bird.pid"),
		ConfigPath:        filepath.Join(tmpDir, "bird.conf"),
		TableID:           "main",
		InterfacePatterns: []string{"phx*"},
		MetricBase:        100,
		MetricStaged:      200,
		MetricDraining:    500,
	}
	spec = withTestBirdOwner(spec)

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
	if os.Getenv("PHOTON_BIRD_SMOKE") != "1" {
		t.Skip("set PHOTON_BIRD_SMOKE=1 to run the root/system BIRD Babel two-node smoke")
	}

	// In container environments, IPv6 Babel may fail due to neighbor
	// resolution limitations. The test uses IPv4 prefixes which are more
	// reliable across container runtimes.
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	nsA := "photon-bird-a-" + suffix
	nsB := "photon-bird-b-" + suffix
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
		RouterID:          0x0a630101, // 10.99.1.1
		NetNSName:         nsA,
		Mode:              BirdModeManaged,
		NetNS:             NetNSSpec{Kind: "name", Name: nsA, Create: false},
		ControlSocketPath: filepath.Join(tmpA, "bird.ctl"),
		PIDFilePath:       filepath.Join(tmpA, "bird.pid"),
		ConfigPath:        filepath.Join(tmpA, "bird.conf"),
		TableID:           "main",
		InterfacePatterns: []string{vethA},
		MetricBase:        100,
		MetricStaged:      200,
		MetricDraining:    500,
	}
	specA = withTestBirdOwner(specA)
	specB := BirdInstanceSpec{
		RouterID:          0x0a630102, // 10.99.1.2
		NetNSName:         nsB,
		Mode:              BirdModeManaged,
		NetNS:             NetNSSpec{Kind: "name", Name: nsB, Create: false},
		ControlSocketPath: filepath.Join(tmpB, "bird.ctl"),
		PIDFilePath:       filepath.Join(tmpB, "bird.pid"),
		ConfigPath:        filepath.Join(tmpB, "bird.conf"),
		TableID:           "main",
		InterfacePatterns: []string{vethB},
		MetricBase:        100,
		MetricStaged:      200,
		MetricDraining:    500,
	}
	specB = withTestBirdOwner(specB)

	// The BIRD config generator normally targets "phx*" tunnel interfaces.
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
	for range 40 {
		out, err := exec.CommandContext(ctx, "birdc", "-s", specA.ControlSocketPath, "show", "protocols").CombinedOutput()
		if err == nil && strings.Contains(string(out), "babel1") && strings.Contains(string(out), "up") {
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
	for range 40 {
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

// TestBabelImportFilterNegativeRootSmoke verifies that a real BIRD/Babel
// import filter accepts an authorized prefix while rejecting an unauthorized
// prefix announced by the same neighbor.
func TestBabelImportFilterNegativeRootSmoke(t *testing.T) {
	if os.Getenv("PHOTON_BIRD_SMOKE") != "1" {
		t.Skip("set PHOTON_BIRD_SMOKE=1 to run the root/system BIRD Babel negative smoke")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	nsA := "photon-bird-neg-a-" + suffix
	nsB := "photon-bird-neg-b-" + suffix
	vethA := "hgnega" + suffix[len(suffix)-4:]
	vethB := "hgnegb" + suffix[len(suffix)-4:]
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
		{"netns", "exec", nsA, "ip", "addr", "add", "10.99.3.1/30", "dev", vethA},
		{"netns", "exec", nsB, "ip", "addr", "add", "10.99.3.2/30", "dev", vethB},
		{"netns", "exec", nsA, "ip", "link", "set", vethA, "up"},
		{"netns", "exec", nsB, "ip", "link", "set", vethB, "up"},
	}
	for _, args := range steps {
		out, err := exec.CommandContext(ctx, "ip", args...).CombinedOutput()
		if err != nil {
			t.Fatalf("ip %s: %v\noutput: %s", strings.Join(args, " "), err, string(out))
		}
	}

	specA := withTestBirdOwner(BirdInstanceSpec{
		RouterID:          0x0a630301,
		NetNSName:         nsA,
		Mode:              BirdModeManaged,
		NetNS:             NetNSSpec{Kind: "name", Name: nsA, Create: false},
		ControlSocketPath: filepath.Join(tmpA, "bird.ctl"),
		PIDFilePath:       filepath.Join(tmpA, "bird.pid"),
		ConfigPath:        filepath.Join(tmpA, "bird.conf"),
		TableID:           "main",
		InterfacePatterns: []string{vethA},
	})
	specB := withTestBirdOwner(BirdInstanceSpec{
		RouterID:          0x0a630302,
		NetNSName:         nsB,
		Mode:              BirdModeManaged,
		NetNS:             NetNSSpec{Kind: "name", Name: nsB, Create: false},
		ControlSocketPath: filepath.Join(tmpB, "bird.ctl"),
		PIDFilePath:       filepath.Join(tmpB, "bird.pid"),
		ConfigPath:        filepath.Join(tmpB, "bird.conf"),
		TableID:           "main",
		InterfacePatterns: []string{vethB},
	})

	allowedPrefix := "10.10.1.0/24"
	rejectedPrefix := "10.10.66.0/24"
	cfgA := generateBabelFilterSmokeConfig(specA, vethA, []string{allowedPrefix, rejectedPrefix}, nil)
	cfgB := generateBabelFilterSmokeConfig(specB, vethB, []string{"10.10.2.0/24"}, []string{allowedPrefix})
	if err := os.WriteFile(specA.ConfigPath, []byte(cfgA), 0644); err != nil {
		t.Fatalf("write config A: %v", err)
	}
	if err := os.WriteFile(specB.ConfigPath, []byte(cfgB), 0644); err != nil {
		t.Fatalf("write config B: %v", err)
	}

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

	dumpOnFail := func() {
		for _, pair := range []struct{ ns, sock string }{
			{nsA, specA.ControlSocketPath},
			{nsB, specB.ControlSocketPath},
		} {
			out, _ := exec.CommandContext(ctx, "birdc", "-s", pair.sock, "show", "protocols", "all").CombinedOutput()
			t.Logf("--- birdc show protocols all in %s ---\n%s", pair.ns, string(out))
			routes, _ := exec.CommandContext(ctx, "birdc", "-s", pair.sock, "show", "route", "all").CombinedOutput()
			t.Logf("--- routes in %s ---\n%s", pair.ns, string(routes))
		}
	}
	defer func() {
		if t.Failed() {
			dumpOnFail()
		}
	}()

	var lastRoutes string
	allowedSeen := false
	for range 40 {
		out, err := exec.CommandContext(ctx, "birdc", "-s", specB.ControlSocketPath, "show", "route").CombinedOutput()
		lastRoutes = string(out)
		if err == nil && strings.Contains(lastRoutes, allowedPrefix) {
			allowedSeen = true
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if !allowedSeen {
		t.Fatalf("authorized prefix %s not learned by B; last routes:\n%s", allowedPrefix, lastRoutes)
	}
	if strings.Contains(lastRoutes, rejectedPrefix) {
		t.Fatalf("unauthorized prefix %s was imported by B; routes:\n%s", rejectedPrefix, lastRoutes)
	}

	time.Sleep(2 * time.Second)
	out, err := exec.CommandContext(ctx, "birdc", "-s", specB.ControlSocketPath, "show", "route").CombinedOutput()
	if err != nil {
		t.Fatalf("birdc show route after negative wait: %v\noutput: %s", err, string(out))
	}
	if strings.Contains(string(out), rejectedPrefix) {
		t.Fatalf("unauthorized prefix %s appeared after filter settle; routes:\n%s", rejectedPrefix, string(out))
	}

	t.Logf("Babel negative root smoke: B accepted %s and rejected %s", allowedPrefix, rejectedPrefix)
}

// TestBabelAnycastFailoverRootSmoke creates a three-node Babel topology where
// two speakers announce the same anycast prefix. It verifies that the receiver
// learns the prefix, then fails over to the remaining speaker after the
// selected speaker is stopped. This intentionally does not assert ECMP: the
// test verifies convergence and failover, not kernel multi-next-hop behavior.
func TestBabelAnycastFailoverRootSmoke(t *testing.T) {
	if os.Getenv("PHOTON_BIRD_SMOKE") != "1" {
		t.Skip("set PHOTON_BIRD_SMOKE=1 to run the root/system BIRD Babel anycast smoke")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	nsR := "photon-bird-any-r-" + suffix
	nsA := "photon-bird-any-a-" + suffix
	nsB := "photon-bird-any-b-" + suffix
	vethRA := "hganyra" + suffix[len(suffix)-4:]
	vethA := "hganya" + suffix[len(suffix)-4:]
	vethRB := "hganyrb" + suffix[len(suffix)-4:]
	vethB := "hganyb" + suffix[len(suffix)-4:]
	tmpR := t.TempDir()
	tmpA := t.TempDir()
	tmpB := t.TempDir()

	t.Cleanup(func() {
		_ = exec.Command("ip", "netns", "delete", nsR).Run()
		_ = exec.Command("ip", "netns", "delete", nsA).Run()
		_ = exec.Command("ip", "netns", "delete", nsB).Run()
	})

	for _, ns := range []string{nsR, nsA, nsB} {
		if err := exec.CommandContext(ctx, "ip", "netns", "add", ns).Run(); err != nil {
			t.Fatalf("ip netns add %s: %v", ns, err)
		}
	}
	if err := exec.CommandContext(ctx, "ip", "link", "add", vethRA, "type", "veth", "peer", "name", vethA).Run(); err != nil {
		t.Fatalf("create receiver/A veth pair: %v", err)
	}
	if err := exec.CommandContext(ctx, "ip", "link", "add", vethRB, "type", "veth", "peer", "name", vethB).Run(); err != nil {
		t.Fatalf("create receiver/B veth pair: %v", err)
	}
	_ = exec.CommandContext(ctx, "ip", "link", "set", vethRA, "netns", nsR).Run()
	_ = exec.CommandContext(ctx, "ip", "link", "set", vethRB, "netns", nsR).Run()
	_ = exec.CommandContext(ctx, "ip", "link", "set", vethA, "netns", nsA).Run()
	_ = exec.CommandContext(ctx, "ip", "link", "set", vethB, "netns", nsB).Run()

	steps := [][]string{
		{"netns", "exec", nsR, "ip", "link", "set", "lo", "up"},
		{"netns", "exec", nsA, "ip", "link", "set", "lo", "up"},
		{"netns", "exec", nsB, "ip", "link", "set", "lo", "up"},
		{"netns", "exec", nsR, "ip", "addr", "add", "10.99.5.1/30", "dev", vethRA},
		{"netns", "exec", nsA, "ip", "addr", "add", "10.99.5.2/30", "dev", vethA},
		{"netns", "exec", nsR, "ip", "addr", "add", "10.99.5.5/30", "dev", vethRB},
		{"netns", "exec", nsB, "ip", "addr", "add", "10.99.5.6/30", "dev", vethB},
		{"netns", "exec", nsR, "ip", "link", "set", vethRA, "up"},
		{"netns", "exec", nsA, "ip", "link", "set", vethA, "up"},
		{"netns", "exec", nsR, "ip", "link", "set", vethRB, "up"},
		{"netns", "exec", nsB, "ip", "link", "set", vethB, "up"},
	}
	for _, args := range steps {
		out, err := exec.CommandContext(ctx, "ip", args...).CombinedOutput()
		if err != nil {
			t.Fatalf("ip %s: %v\noutput: %s", strings.Join(args, " "), err, string(out))
		}
	}

	anycastPrefix := "10.30.0.0/24"
	specR := withTestBirdOwner(BirdInstanceSpec{
		RouterID:          0x0a630501,
		NetNSName:         nsR,
		Mode:              BirdModeManaged,
		NetNS:             NetNSSpec{Kind: "name", Name: nsR, Create: false},
		ControlSocketPath: filepath.Join(tmpR, "bird.ctl"),
		PIDFilePath:       filepath.Join(tmpR, "bird.pid"),
		ConfigPath:        filepath.Join(tmpR, "bird.conf"),
		TableID:           "main",
		InterfacePatterns: []string{vethRA, vethRB},
	})
	specA := withTestBirdOwner(BirdInstanceSpec{
		RouterID:          0x0a630502,
		NetNSName:         nsA,
		Mode:              BirdModeManaged,
		NetNS:             NetNSSpec{Kind: "name", Name: nsA, Create: false},
		ControlSocketPath: filepath.Join(tmpA, "bird.ctl"),
		PIDFilePath:       filepath.Join(tmpA, "bird.pid"),
		ConfigPath:        filepath.Join(tmpA, "bird.conf"),
		TableID:           "main",
		InterfacePatterns: []string{vethA},
	})
	specB := withTestBirdOwner(BirdInstanceSpec{
		RouterID:          0x0a630506,
		NetNSName:         nsB,
		Mode:              BirdModeManaged,
		NetNS:             NetNSSpec{Kind: "name", Name: nsB, Create: false},
		ControlSocketPath: filepath.Join(tmpB, "bird.ctl"),
		PIDFilePath:       filepath.Join(tmpB, "bird.pid"),
		ConfigPath:        filepath.Join(tmpB, "bird.conf"),
		TableID:           "main",
		InterfacePatterns: []string{vethB},
	})

	if err := os.WriteFile(specR.ConfigPath, []byte(generateAnycastBabelConfig(specR, []string{vethRA, vethRB}, "")), 0644); err != nil {
		t.Fatalf("write receiver config: %v", err)
	}
	if err := os.WriteFile(specA.ConfigPath, []byte(generateAnycastBabelConfig(specA, []string{vethA}, anycastPrefix)), 0644); err != nil {
		t.Fatalf("write speaker A config: %v", err)
	}
	if err := os.WriteFile(specB.ConfigPath, []byte(generateAnycastBabelConfig(specB, []string{vethB}, anycastPrefix)), 0644); err != nil {
		t.Fatalf("write speaker B config: %v", err)
	}

	pmR := NewExecProcessManager("")
	pmR.socketWaitTimeout = 5 * time.Second
	pmA := NewExecProcessManager("")
	pmA.socketWaitTimeout = 5 * time.Second
	pmB := NewExecProcessManager("")
	pmB.socketWaitTimeout = 5 * time.Second
	if err := pmR.Start(ctx, specR); err != nil {
		t.Fatalf("start BIRD receiver: %v", err)
	}
	t.Cleanup(func() { _ = pmR.Stop(context.Background(), specR) })
	if err := pmA.Start(ctx, specA); err != nil {
		t.Fatalf("start BIRD speaker A: %v", err)
	}
	t.Cleanup(func() { _ = pmA.Stop(context.Background(), specA) })
	if err := pmB.Start(ctx, specB); err != nil {
		t.Fatalf("start BIRD speaker B: %v", err)
	}
	t.Cleanup(func() { _ = pmB.Stop(context.Background(), specB) })

	dumpOnFail := func() {
		for _, pair := range []struct{ ns, sock string }{
			{nsR, specR.ControlSocketPath},
			{nsA, specA.ControlSocketPath},
			{nsB, specB.ControlSocketPath},
		} {
			out, _ := exec.CommandContext(ctx, "birdc", "-s", pair.sock, "show", "protocols", "all").CombinedOutput()
			t.Logf("--- birdc show protocols all in %s ---\n%s", pair.ns, string(out))
			routes, _ := exec.CommandContext(ctx, "birdc", "-s", pair.sock, "show", "route", "all").CombinedOutput()
			t.Logf("--- routes in %s ---\n%s", pair.ns, string(routes))
		}
	}
	defer func() {
		if t.Failed() {
			dumpOnFail()
		}
	}()

	firstIface, firstRoutes := waitForSelectedAnycastIface(t, ctx, specR.ControlSocketPath, anycastPrefix, []string{vethRA, vethRB}, "")
	var stoppedIface, remainingIface string
	if firstIface == vethRA {
		stoppedIface, remainingIface = vethRA, vethRB
		if err := pmA.Stop(ctx, specA); err != nil {
			t.Fatalf("stop selected speaker A: %v", err)
		}
	} else {
		stoppedIface, remainingIface = vethRB, vethRA
		if err := pmB.Stop(ctx, specB); err != nil {
			t.Fatalf("stop selected speaker B: %v", err)
		}
	}

	afterIface, afterRoutes := waitForSelectedAnycastIface(t, ctx, specR.ControlSocketPath, anycastPrefix, []string{remainingIface}, stoppedIface)
	if afterIface != remainingIface {
		t.Fatalf("selected iface after failover = %q, want %q\nbefore:\n%s\nafter:\n%s", afterIface, remainingIface, firstRoutes, afterRoutes)
	}

	t.Logf("Babel anycast failover root smoke: %s moved from %s to %s after selected speaker stopped", anycastPrefix, stoppedIface, afterIface)
}

// TestBIRDUpstreamBabelRootSmoke tests the 6.1.7 scenario: a veth pair
// connects an overlay netns to the host (main) network, BIRD instances
// on both sides establish a Babel neighbor over the veth, and prefixes
// are exchanged bidirectionally.
//
// Topology:
//
//	host ns (10.99.2.1/30) ←veth→ overlay ns (10.99.2.2/30)
//
// Host announces 172.16.1.0/24, overlay announces 172.16.2.0/24.
// After convergence, both sides should have learned each other's prefix.
func TestBIRDUpstreamBabelRootSmoke(t *testing.T) {
	if os.Getenv("PHOTON_BIRD_SMOKE") != "1" {
		t.Skip("set PHOTON_BIRD_SMOKE=1 to run the root/system BIRD upstream Babel smoke")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	overlayNS := "photon-bird-up-" + suffix
	vethHost := "hguph" + suffix[len(suffix)-4:]
	vethOverlay := "hgupo" + suffix[len(suffix)-4:]
	tmpHost := t.TempDir()
	tmpOverlay := t.TempDir()

	t.Cleanup(func() {
		_ = exec.Command("ip", "netns", "delete", overlayNS).Run()
		_ = exec.Command("ip", "link", "del", vethHost).Run()
	})

	// Create the overlay netns.
	if err := exec.CommandContext(ctx, "ip", "netns", "add", overlayNS).Run(); err != nil {
		t.Fatalf("ip netns add %s: %v", overlayNS, err)
	}

	// Create veth pair: vethHost stays in host ns, vethOverlay goes to overlay ns.
	if err := exec.CommandContext(ctx, "ip", "link", "add", vethHost, "type", "veth", "peer", "name", vethOverlay).Run(); err != nil {
		t.Fatalf("create veth pair: %v", err)
	}
	_ = exec.CommandContext(ctx, "ip", "link", "set", vethOverlay, "netns", overlayNS).Run()

	// Configure interfaces.
	steps := [][]string{
		{"link", "set", "lo", "up"},
		{"addr", "add", "10.99.2.1/30", "dev", vethHost},
		{"link", "set", vethHost, "up"},
		{"netns", "exec", overlayNS, "ip", "link", "set", "lo", "up"},
		{"netns", "exec", overlayNS, "ip", "addr", "add", "10.99.2.2/30", "dev", vethOverlay},
		{"netns", "exec", overlayNS, "ip", "link", "set", vethOverlay, "up"},
	}
	for _, args := range steps {
		out, err := exec.CommandContext(ctx, "ip", args...).CombinedOutput()
		if err != nil {
			t.Fatalf("ip %s: %v\noutput: %s", strings.Join(args, " "), err, string(out))
		}
	}

	// Prepare BIRD config for the host side (runs in host ns directly).
	hostCfgPath := filepath.Join(tmpHost, "bird.conf")
	hostSocketPath := filepath.Join(tmpHost, "bird.ctl")
	hostPIDPath := filepath.Join(tmpHost, "bird.pid")
	hostCfg := generateMinimalBabelConfig(BirdInstanceSpec{
		RouterID:   0x0a630201, // 10.99.2.1
		ConfigPath: hostCfgPath,
	}, vethHost, "172.16.1.0/24")
	if err := os.WriteFile(hostCfgPath, []byte(hostCfg), 0644); err != nil {
		t.Fatalf("write host config: %v", err)
	}

	// Prepare BIRD config for the overlay side (runs inside overlay ns).
	overlayCfgPath := filepath.Join(tmpOverlay, "bird.conf")
	overlaySocketPath := filepath.Join(tmpOverlay, "bird.ctl")
	overlayPIDPath := filepath.Join(tmpOverlay, "bird.pid")
	overlayCfg := generateMinimalBabelConfig(BirdInstanceSpec{
		RouterID:   0x0a630202, // 10.99.2.2
		ConfigPath: overlayCfgPath,
	}, vethOverlay, "172.16.2.0/24")
	if err := os.WriteFile(overlayCfgPath, []byte(overlayCfg), 0644); err != nil {
		t.Fatalf("write overlay config: %v", err)
	}

	// Start BIRD in host ns (directly, not via ExecProcessManager since
	// we're in host ns already).
	hostBird := exec.CommandContext(ctx, "bird",
		"-c", hostCfgPath,
		"-s", hostSocketPath,
		"-P", hostPIDPath,
	)
	if err := hostBird.Start(); err != nil {
		t.Fatalf("start host BIRD: %v", err)
	}
	go func() { _ = hostBird.Wait() }()
	t.Cleanup(func() {
		_ = exec.Command("birdc", "-s", hostSocketPath, "down").Run()
		_ = hostBird.Process.Kill()
		_ = hostBird.Wait()
		_ = os.Remove(hostCfgPath)
		_ = os.Remove(hostSocketPath)
		_ = os.Remove(hostPIDPath)
	})

	// Start BIRD in overlay ns via ip netns exec.
	overlaySpec := BirdInstanceSpec{
		RouterID:          0x0a630202,
		NetNSName:         overlayNS,
		Mode:              BirdModeManaged,
		NetNS:             NetNSSpec{Kind: "name", Name: overlayNS, Create: false},
		ControlSocketPath: overlaySocketPath,
		PIDFilePath:       overlayPIDPath,
		ConfigPath:        overlayCfgPath,
		TableID:           "main",
		InterfacePatterns: []string{vethOverlay},
	}
	overlaySpec = withTestBirdOwner(overlaySpec)
	overlayPM := NewExecProcessManager("")
	overlayPM.socketWaitTimeout = 5 * time.Second
	if err := overlayPM.Start(ctx, overlaySpec); err != nil {
		t.Fatalf("start overlay BIRD: %v", err)
	}
	t.Cleanup(func() { _ = overlayPM.Stop(context.Background(), overlaySpec) })

	// Wait for host BIRD control socket.
	for range 50 {
		if _, err := os.Stat(hostSocketPath); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if _, err := os.Stat(hostSocketPath); err != nil {
		t.Fatalf("host BIRD control socket not found: %v", err)
	}

	// Dump diagnostics on failure.
	dumpOnFail := func() {
		t.Logf("--- host BIRD protocols ---")
		out, _ := exec.CommandContext(ctx, "birdc", "-s", hostSocketPath, "show", "protocols", "all").CombinedOutput()
		t.Logf("%s", string(out))
		routes, _ := exec.CommandContext(ctx, "birdc", "-s", hostSocketPath, "show", "route").CombinedOutput()
		t.Logf("--- host BIRD routes ---\n%s", string(routes))
		t.Logf("--- overlay BIRD protocols ---")
		out2, _ := exec.CommandContext(ctx, "birdc", "-s", overlaySocketPath, "show", "protocols", "all").CombinedOutput()
		t.Logf("%s", string(out2))
		routes2, _ := exec.CommandContext(ctx, "birdc", "-s", overlaySocketPath, "show", "route").CombinedOutput()
		t.Logf("--- overlay BIRD routes ---\n%s", string(routes2))
	}
	defer func() {
		if t.Failed() {
			dumpOnFail()
		}
	}()

	// Poll for host BIRD to learn overlay's prefix 172.16.2.0/24.
	hostLearned := false
	for range 40 {
		out, err := exec.CommandContext(ctx, "birdc", "-s", hostSocketPath, "show", "route").CombinedOutput()
		if err == nil && strings.Contains(string(out), "172.16.2.0/24") {
			hostLearned = true
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if !hostLearned {
		t.Fatal("host BIRD did not learn route 172.16.2.0/24 from overlay within 20s")
	}

	// Poll for overlay BIRD to learn host's prefix 172.16.1.0/24.
	overlayLearned := false
	for range 40 {
		out, err := exec.CommandContext(ctx, "birdc", "-s", overlaySocketPath, "show", "route").CombinedOutput()
		if err == nil && strings.Contains(string(out), "172.16.1.0/24") {
			overlayLearned = true
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if !overlayLearned {
		t.Fatal("overlay BIRD did not learn route 172.16.1.0/24 from host within 20s")
	}

	t.Logf("BIRD upstream Babel root smoke: host learned 172.16.2.0/24, overlay learned 172.16.1.0/24")
}

// TestBabelDualInterfaceCostFailoverRootSmoke is the Phase 7.1.a validation
// experiment. Two nodes have two independent Babel-facing interfaces each.
// It proves that rxcost is directional: a node's configured receive cost is
// advertised to its peer, so each node may prefer a different interface for
// traffic towards the other node. It also proves that the lower-cost interface
// is restored after a link failure without health changing BIRD policy.
func TestBabelDualInterfaceCostFailoverRootSmoke(t *testing.T) {
	if os.Getenv("PHOTON_BIRD_SMOKE") != "1" {
		t.Skip("set PHOTON_BIRD_SMOKE=1 to run the Phase 7.1 dual-interface BIRD/Babel root experiment")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	nsA := "photon-bird-dual-a-" + suffix
	nsB := "photon-bird-dual-b-" + suffix
	aLeft, bLeft := "hgdla"+suffix[len(suffix)-4:], "hgdlb"+suffix[len(suffix)-4:]
	aRight, bRight := "hgdra"+suffix[len(suffix)-4:], "hgdrb"+suffix[len(suffix)-4:]
	tmpA, tmpB := t.TempDir(), t.TempDir()

	t.Cleanup(func() {
		_ = exec.Command("ip", "netns", "delete", nsA).Run()
		_ = exec.Command("ip", "netns", "delete", nsB).Run()
	})
	for _, ns := range []string{nsA, nsB} {
		if out, err := exec.CommandContext(ctx, "ip", "netns", "add", ns).CombinedOutput(); err != nil {
			t.Fatalf("ip netns add %s: %v\noutput: %s", ns, err, out)
		}
	}
	for _, pair := range [][2]string{{aLeft, bLeft}, {aRight, bRight}} {
		if out, err := exec.CommandContext(ctx, "ip", "link", "add", pair[0], "type", "veth", "peer", "name", pair[1]).CombinedOutput(); err != nil {
			t.Fatalf("create veth pair %s/%s: %v\noutput: %s", pair[0], pair[1], err, out)
		}
		if out, err := exec.CommandContext(ctx, "ip", "link", "set", pair[0], "netns", nsA).CombinedOutput(); err != nil {
			t.Fatalf("move %s to %s: %v\noutput: %s", pair[0], nsA, err, out)
		}
		if out, err := exec.CommandContext(ctx, "ip", "link", "set", pair[1], "netns", nsB).CombinedOutput(); err != nil {
			t.Fatalf("move %s to %s: %v\noutput: %s", pair[1], nsB, err, out)
		}
	}
	for _, args := range [][]string{
		{"netns", "exec", nsA, "ip", "link", "set", "lo", "up"},
		{"netns", "exec", nsB, "ip", "link", "set", "lo", "up"},
		{"netns", "exec", nsA, "ip", "addr", "add", "10.99.71.1/30", "dev", aLeft},
		{"netns", "exec", nsB, "ip", "addr", "add", "10.99.71.2/30", "dev", bLeft},
		{"netns", "exec", nsA, "ip", "addr", "add", "10.99.72.1/30", "dev", aRight},
		{"netns", "exec", nsB, "ip", "addr", "add", "10.99.72.2/30", "dev", bRight},
		{"netns", "exec", nsA, "ip", "link", "set", aLeft, "up"},
		{"netns", "exec", nsB, "ip", "link", "set", bLeft, "up"},
		{"netns", "exec", nsA, "ip", "link", "set", aRight, "up"},
		{"netns", "exec", nsB, "ip", "link", "set", bRight, "up"},
	} {
		if out, err := exec.CommandContext(ctx, "ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("ip %s: %v\noutput: %s", strings.Join(args, " "), err, out)
		}
	}

	specA := withTestBirdOwner(BirdInstanceSpec{RouterID: 0x0a634701, NetNSName: nsA, Mode: BirdModeManaged, NetNS: NetNSSpec{Kind: "name", Name: nsA}, ControlSocketPath: filepath.Join(tmpA, "bird.ctl"), PIDFilePath: filepath.Join(tmpA, "bird.pid"), ConfigPath: filepath.Join(tmpA, "bird.conf"), TableID: "main"})
	specB := withTestBirdOwner(BirdInstanceSpec{RouterID: 0x0a634702, NetNSName: nsB, Mode: BirdModeManaged, NetNS: NetNSSpec{Kind: "name", Name: nsB}, ControlSocketPath: filepath.Join(tmpB, "bird.ctl"), PIDFilePath: filepath.Join(tmpB, "bird.pid"), ConfigPath: filepath.Join(tmpB, "bird.conf"), TableID: "main"})
	if err := os.WriteFile(specA.ConfigPath, []byte(generateDualInterfaceBabelConfig(specA, map[string]uint{aLeft: 96, aRight: 160}, "10.71.0.0/24")), 0644); err != nil {
		t.Fatalf("write config A: %v", err)
	}
	if err := os.WriteFile(specB.ConfigPath, []byte(generateDualInterfaceBabelConfig(specB, map[string]uint{bLeft: 160, bRight: 96}, "10.72.0.0/24")), 0644); err != nil {
		t.Fatalf("write config B: %v", err)
	}

	pmA, pmB := NewExecProcessManager(""), NewExecProcessManager("")
	pmA.socketWaitTimeout, pmB.socketWaitTimeout = 5*time.Second, 5*time.Second
	if err := pmA.Start(ctx, specA); err != nil {
		t.Fatalf("start BIRD A: %v", err)
	}
	t.Cleanup(func() { _ = pmA.Stop(context.Background(), specA) })
	if err := pmB.Start(ctx, specB); err != nil {
		t.Fatalf("start BIRD B: %v", err)
	}
	t.Cleanup(func() { _ = pmB.Stop(context.Background(), specB) })

	dumpOnFail := func() {
		for _, pair := range []struct{ ns, socket string }{{nsA, specA.ControlSocketPath}, {nsB, specB.ControlSocketPath}} {
			routes, _ := exec.CommandContext(ctx, "birdc", "-s", pair.socket, "show", "route", "all").CombinedOutput()
			neighbors, _ := exec.CommandContext(ctx, "birdc", "-s", pair.socket, "show", "babel", "neighbors").CombinedOutput()
			t.Logf("--- Babel neighbors in %s ---\n%s", pair.ns, neighbors)
			t.Logf("--- routes in %s ---\n%s", pair.ns, routes)
		}
	}
	defer func() {
		if t.Failed() {
			dumpOnFail()
		}
	}()

	// Do not start judging cost direction until both independently-created
	// links have formed Babel adjacencies. BIRD can discover one veth later
	// than the other during namespace setup; treating that transient state as
	// a cost-selection result made this explicit experiment unnecessarily flaky.
	waitForBabelNeighborsWithin(t, ctx, specA.ControlSocketPath, []string{aLeft, aRight}, 40)
	waitForBabelNeighborsWithin(t, ctx, specB.ControlSocketPath, []string{bLeft, bRight}, 40)

	// rxcost is advertised to the peer: B chooses bLeft because A assigns 96
	// to aLeft, while A chooses aRight because B assigns 96 to bRight.
	waitForSelectedAnycastIfaceWithin(t, ctx, specB.ControlSocketPath, "10.71.0.0/24", []string{bLeft}, "", 20)
	waitForSelectedAnycastIfaceWithin(t, ctx, specA.ControlSocketPath, "10.72.0.0/24", []string{aRight}, "", 20)

	if out, err := exec.CommandContext(ctx, "ip", "netns", "exec", nsB, "ip", "link", "set", bLeft, "down").CombinedOutput(); err != nil {
		t.Fatalf("bring preferred B interface down: %v\noutput: %s", err, out)
	}
	waitForSelectedAnycastIfaceWithin(t, ctx, specB.ControlSocketPath, "10.71.0.0/24", []string{bRight}, bLeft, 20)
	if out, err := exec.CommandContext(ctx, "ip", "netns", "exec", nsB, "ip", "link", "set", bLeft, "up").CombinedOutput(); err != nil {
		t.Fatalf("restore preferred B interface: %v\noutput: %s", err, out)
	}
	waitForSelectedAnycastIfaceWithin(t, ctx, specB.ControlSocketPath, "10.71.0.0/24", []string{bLeft}, "", 20)

	t.Logf("Phase 7.1.a: B preferred %s while A preferred %s; B failed over to %s and recovered %s", bLeft, aRight, bRight, bLeft)
}

// generateMinimalBabelConfig produces a minimal BIRD 2.x config that:
// - Uses the given interface for Babel (without type tunnel)
// - Announces the given prefix via protocol static
// - Exports the static route to Babel and imports Babel routes to kernel
func withTestBirdOwner(spec BirdInstanceSpec) BirdInstanceSpec {
	owner := BirdResourceOwner{
		Manager:    "photon",
		InstanceID: spec.NetNSName,
		NetNSName:  spec.NetNSName,
	}
	owner.Token = OwnerToken(owner.InstanceID, owner.NetNSName)
	owner.ControlSocketToken = ResourceToken(owner, "control_socket")
	owner.PIDFileToken = ResourceToken(owner, "pid_file")
	owner.ConfigFileToken = ResourceToken(owner, "config_file")
	owner.RouteTableToken = ResourceToken(owner, "route_table")
	owner.RuleToken = ResourceToken(owner, "rule")
	spec.Owner = owner
	return spec
}

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

func generateBabelFilterSmokeConfig(spec BirdInstanceSpec, iface string, staticPrefixes, importAllowed []string) string {
	routerID := fmt.Sprintf("%d.%d.%d.%d",
		(spec.RouterID>>24)&0xff,
		(spec.RouterID>>16)&0xff,
		(spec.RouterID>>8)&0xff,
		spec.RouterID&0xff,
	)
	logPath := filepath.Join(filepath.Dir(spec.ConfigPath), "bird.log")

	var staticRoutes strings.Builder
	for _, prefix := range staticPrefixes {
		fmt.Fprintf(&staticRoutes, "    route %s blackhole;\n", prefix)
	}
	if staticRoutes.Len() == 0 {
		staticRoutes.WriteString("    # no static routes announced by this smoke peer\n")
	}

	importFilter := "import all;"
	if len(importAllowed) > 0 {
		var rules strings.Builder
		rules.WriteString("filter photon_import4 {\n")
		for _, prefix := range importAllowed {
			fmt.Fprintf(&rules, "    if net = %s then accept;\n", prefix)
		}
		rules.WriteString("    reject;\n")
		rules.WriteString("}\n\n")
		importFilter = "import filter photon_import4;"
		return fmt.Sprintf(`# Minimal Babel config generated by TestBabelImportFilterNegativeRootSmoke
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

%sprotocol babel {
    ipv4 {
        %s
        export where source = RTS_BABEL || source = RTS_STATIC || source = RTS_DEVICE;
    };
    interface "%s" {
        type wireless;
    };
}
`, logPath, routerID, staticRoutes.String(), rules.String(), importFilter, iface)
	}

	return fmt.Sprintf(`# Minimal Babel config generated by TestBabelImportFilterNegativeRootSmoke
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
        %s
        export where source = RTS_BABEL || source = RTS_STATIC || source = RTS_DEVICE;
    };
    interface "%s" {
        type wireless;
    };
}
	`, logPath, routerID, staticRoutes.String(), importFilter, iface)
}

func generateAnycastBabelConfig(spec BirdInstanceSpec, ifaces []string, announcePrefix string) string {
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
	var ifaceBlocks strings.Builder
	for _, iface := range ifaces {
		fmt.Fprintf(&ifaceBlocks, "    interface %q {\n        type wireless;\n    };\n", iface)
	}
	return fmt.Sprintf(`# Minimal Babel config generated by TestBabelAnycastFailoverRootSmoke
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
%s}
	`, logPath, routerID, staticRoutes, ifaceBlocks.String())
}

func generateDualInterfaceBabelConfig(spec BirdInstanceSpec, interfaceCosts map[string]uint, announcePrefix string) string {
	routerID := fmt.Sprintf("%d.%d.%d.%d", (spec.RouterID>>24)&0xff, (spec.RouterID>>16)&0xff, (spec.RouterID>>8)&0xff, spec.RouterID&0xff)
	logPath := filepath.Join(filepath.Dir(spec.ConfigPath), "bird.log")
	names := make([]string, 0, len(interfaceCosts))
	for name := range interfaceCosts {
		names = append(names, name)
	}
	sort.Strings(names)
	var ifaceBlocks strings.Builder
	for _, iface := range names {
		// Fast intervals keep this isolated convergence experiment bounded while
		// leaving the production BIRD generator's timings unchanged.
		fmt.Fprintf(&ifaceBlocks, "    interface %q {\n        type wireless;\n        rxcost %d;\n        hello interval 1 s;\n        update interval 1 s;\n    };\n", iface, interfaceCosts[iface])
	}
	return fmt.Sprintf(`# Phase 7.1.a dual-interface Babel experiment
log "%s" all;
debug protocols all;

router id %s;

ipv4 table master4;

protocol device { scan time 5; }
protocol kernel { ipv4 { export all; }; learn; }
protocol direct { ipv4; }
protocol static {
    ipv4;
    route %s blackhole;
}
protocol babel {
    ipv4 {
        import all;
        export where source = RTS_BABEL || source = RTS_STATIC || source = RTS_DEVICE;
    };
%s}
`, logPath, routerID, announcePrefix, ifaceBlocks.String())
}

func waitForSelectedAnycastIface(t *testing.T, ctx context.Context, socketPath, prefix string, allowedIfaces []string, forbiddenIface string) (string, string) {
	return waitForSelectedAnycastIfaceWithin(t, ctx, socketPath, prefix, allowedIfaces, forbiddenIface, 60)
}

func waitForBabelNeighborsWithin(t *testing.T, ctx context.Context, socketPath string, expectedIfaces []string, attempts int) {
	t.Helper()
	expected := make(map[string]struct{}, len(expectedIfaces))
	for _, iface := range expectedIfaces {
		expected[iface] = struct{}{}
	}

	var last string
	for range attempts {
		out, err := exec.CommandContext(ctx, "birdc", "-s", socketPath, "show", "babel", "neighbors").CombinedOutput()
		last = string(out)
		if err == nil {
			seen := make(map[string]struct{}, len(expected))
			for _, neighbor := range parseBabelNeighbors(last) {
				if _, ok := expected[neighbor.Interface]; ok {
					seen[neighbor.Interface] = struct{}{}
				}
			}
			if len(seen) == len(expected) {
				return
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("Babel neighbors on interfaces %v did not converge; last neighbor output:\n%s", expectedIfaces, last)
}

func waitForSelectedAnycastIfaceWithin(t *testing.T, ctx context.Context, socketPath, prefix string, allowedIfaces []string, forbiddenIface string, attempts int) (string, string) {
	t.Helper()
	var last string
	for range attempts {
		out, err := exec.CommandContext(ctx, "birdc", "-s", socketPath, "show", "route", "all").CombinedOutput()
		last = string(out)
		if err == nil {
			iface, ok := selectedRouteIface(last, prefix, allowedIfaces)
			if ok && iface != "" && iface != forbiddenIface {
				return iface, last
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("selected route for %s via allowed ifaces %v not found; last route output:\n%s", prefix, allowedIfaces, last)
	return "", last
}

func selectedRouteIface(output, prefix string, allowedIfaces []string) (string, bool) {
	allowed := map[string]bool{}
	for _, iface := range allowedIfaces {
		allowed[iface] = true
	}
	lines := strings.Split(output, "\n")
	inSelectedPrefix := false
	for _, raw := range lines {
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)
		if strings.Contains(line, prefix) {
			inSelectedPrefix = strings.Contains(line, "*")
			if inSelectedPrefix {
				for iface := range allowed {
					if strings.Contains(line, iface) {
						return iface, true
					}
				}
			}
			continue
		}
		if inSelectedPrefix {
			if trimmed == "" {
				continue
			}
			for iface := range allowed {
				if strings.Contains(line, " on "+iface) || strings.Contains(line, iface) {
					return iface, true
				}
			}
			if len(line) > 0 && line[0] != ' ' && line[0] != '\t' {
				inSelectedPrefix = false
			}
		}
	}
	return "", false
}
