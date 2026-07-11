package wireguard

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Catofes/higgs/pkg/routing/bird"
)

// TestWireGuardGREThreeNodeRootSmoke is the Phase 7.1.b validation experiment.
// One shared WireGuard device on node A owns two peers. Each peer has a
// dedicated GRE interface for Babel, while WireGuard AllowedIPs contain only
// transit /32s. Babel learns and forwards service prefixes over the GRE links.
func TestWireGuardGREThreeNodeRootSmoke(t *testing.T) {
	if os.Getenv("HIGGS_WG_GRE_SMOKE") != "1" {
		t.Skip("set HIGGS_WG_GRE_SMOKE=1 to run the Phase 7.1 WireGuard/GRE root experiment")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	wgBinary := os.Getenv("HIGGS_WG_BINARY")
	if wgBinary == "" {
		wgBinary = "wg"
	}
	if _, err := exec.LookPath(wgBinary); err != nil {
		t.Fatalf("locate wg binary %q: %v", wgBinary, err)
	}

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	short := suffix[len(suffix)-4:]
	nsA, nsB, nsC := "higgs-wggre-a-"+suffix, "higgs-wggre-b-"+suffix, "higgs-wggre-c-"+suffix
	aB, bA := "hgwab"+short, "hgwba"+short
	aC, cA := "hgwac"+short, "hgwca"+short
	tmpA, tmpB, tmpC := t.TempDir(), t.TempDir(), t.TempDir()

	var managers []*bird.ExecProcessManager
	var specs []bird.BirdInstanceSpec
	var cleanupOnce sync.Once
	cleanup := func() {
		cleanupOnce.Do(func() {
			for i := len(managers) - 1; i >= 0; i-- {
				_ = managers[i].Stop(context.Background(), specs[i])
			}
			for _, ns := range []string{nsA, nsB, nsC} {
				_ = exec.Command("ip", "netns", "delete", ns).Run()
			}
		})
	}
	t.Cleanup(cleanup)

	for _, ns := range []string{nsA, nsB, nsC} {
		runSmokeCommand(t, ctx, "ip", "netns", "add", ns)
		runSmokeCommand(t, ctx, "ip", "netns", "exec", ns, "ip", "link", "set", "lo", "up")
		runSmokeCommand(t, ctx, "ip", "netns", "exec", ns, "sysctl", "-qw", "net.ipv4.ip_forward=1")
	}
	createVethUnderlay(t, ctx, aB, nsA, "192.0.2.1/30", bA, nsB, "192.0.2.2/30")
	createVethUnderlay(t, ctx, aC, nsA, "192.0.2.5/30", cA, nsC, "192.0.2.6/30")

	privateA, publicA := generateWGKeyPair(t, ctx, wgBinary, filepath.Join(tmpA, "wg.key"))
	privateB, publicB := generateWGKeyPair(t, ctx, wgBinary, filepath.Join(tmpB, "wg.key"))
	privateC, publicC := generateWGKeyPair(t, ctx, wgBinary, filepath.Join(tmpC, "wg.key"))
	configureWGDevice(t, ctx, wgBinary, nsA, privateA, "10.200.0.1/32", []wgPeer{
		{publicKey: publicB, allowedIP: "10.200.0.2/32", endpoint: "192.0.2.2:51820"},
		{publicKey: publicC, allowedIP: "10.200.0.3/32", endpoint: "192.0.2.6:51820"},
	})
	configureWGDevice(t, ctx, wgBinary, nsB, privateB, "10.200.0.2/32", []wgPeer{{publicKey: publicA, allowedIP: "10.200.0.1/32", endpoint: "192.0.2.1:51820"}})
	configureWGDevice(t, ctx, wgBinary, nsC, privateC, "10.200.0.3/32", []wgPeer{{publicKey: publicA, allowedIP: "10.200.0.1/32", endpoint: "192.0.2.5:51820"}})
	for _, route := range []struct{ ns, peer string }{{nsA, "10.200.0.2/32"}, {nsA, "10.200.0.3/32"}, {nsB, "10.200.0.1/32"}, {nsC, "10.200.0.1/32"}} {
		runSmokeCommand(t, ctx, "ip", "netns", "exec", route.ns, "ip", "route", "add", route.peer, "dev", "wg7")
	}

	assertWGPeers(t, ctx, wgBinary, nsA, 2, []string{"10.200.0.2/32", "10.200.0.3/32"})
	assertWGPeers(t, ctx, wgBinary, nsB, 1, []string{"10.200.0.1/32"})
	assertWGPeers(t, ctx, wgBinary, nsC, 1, []string{"10.200.0.1/32"})
	pingSmoke(t, ctx, nsA, "10.200.0.2")
	pingSmoke(t, ctx, nsA, "10.200.0.3")

	configureGRE(t, ctx, nsA, "hgsg-ab", "10.200.0.1", "10.200.0.2", "7101", "10.210.1.1/30", "fe80::1:1/64")
	configureGRE(t, ctx, nsB, "hgsg-ba", "10.200.0.2", "10.200.0.1", "7101", "10.210.1.2/30", "fe80::1:2/64")
	configureGRE(t, ctx, nsA, "hgsg-ac", "10.200.0.1", "10.200.0.3", "7102", "10.210.2.1/30", "fe80::2:1/64")
	configureGRE(t, ctx, nsC, "hgsg-ca", "10.200.0.3", "10.200.0.1", "7102", "10.210.2.2/30", "fe80::2:2/64")
	configureServiceInterface(t, ctx, nsB, "10.220.2.1/24")
	configureServiceInterface(t, ctx, nsC, "10.220.3.1/24")

	for _, item := range []struct {
		ns       string
		tmp      string
		routerID string
	}{
		{nsA, tmpA, "10.71.1.1"},
		{nsB, tmpB, "10.71.1.2"},
		{nsC, tmpC, "10.71.1.3"},
	} {
		spec := experimentBirdSpec(item.ns, item.tmp)
		if err := os.WriteFile(spec.ConfigPath, []byte(wgGREBirdConfig(item.routerID, filepath.Join(item.tmp, "bird.log"))), 0o644); err != nil {
			t.Fatalf("write BIRD config for %s: %v", item.ns, err)
		}
		pm := bird.NewExecProcessManager("")
		if err := pm.Start(ctx, spec); err != nil {
			t.Fatalf("start BIRD in %s: %v", item.ns, err)
		}
		managers = append(managers, pm)
		specs = append(specs, spec)
	}

	waitForBirdRoutes(t, ctx, specs[0].ControlSocketPath, []string{"10.220.2.0/24", "10.220.3.0/24"})
	waitForBirdRoutes(t, ctx, specs[1].ControlSocketPath, []string{"10.220.3.0/24"})
	pingSmokeFrom(t, ctx, nsB, "10.220.2.1", "10.220.3.1")

	for _, item := range []struct{ ns, iface string }{{nsA, "hgsg-ab"}, {nsA, "hgsg-ac"}, {nsB, "hgsg-ba"}, {nsC, "hgsg-ca"}} {
		out := runSmokeCommand(t, ctx, "ip", "netns", "exec", item.ns, "ip", "-o", "link", "show", "dev", item.iface)
		if !strings.Contains(out, "mtu 1360") {
			t.Fatalf("%s/%s MTU mismatch, output: %s", item.ns, item.iface, out)
		}
	}

	cleanup()
	out := runSmokeCommand(t, ctx, "ip", "netns", "list")
	for _, ns := range []string{nsA, nsB, nsC} {
		if strings.Contains(out, ns) {
			t.Fatalf("network namespace %s remained after cleanup", ns)
		}
	}
	t.Log("Phase 7.1.b: shared WG device with two transit-only peers carried independent GRE/Babel links and routed service prefixes; cleanup succeeded")
}

type wgPeer struct {
	publicKey string
	allowedIP string
	endpoint  string
}

func runSmokeCommand(t *testing.T, ctx context.Context, name string, args ...string) string {
	t.Helper()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\noutput: %s", name, strings.Join(args, " "), err, out)
	}
	return string(out)
}

func createVethUnderlay(t *testing.T, ctx context.Context, left, leftNS, leftCIDR, right, rightNS, rightCIDR string) {
	t.Helper()
	runSmokeCommand(t, ctx, "ip", "link", "add", left, "type", "veth", "peer", "name", right)
	runSmokeCommand(t, ctx, "ip", "link", "set", left, "netns", leftNS)
	runSmokeCommand(t, ctx, "ip", "link", "set", right, "netns", rightNS)
	for _, item := range []struct{ ns, iface, cidr string }{{leftNS, left, leftCIDR}, {rightNS, right, rightCIDR}} {
		runSmokeCommand(t, ctx, "ip", "netns", "exec", item.ns, "ip", "addr", "add", item.cidr, "dev", item.iface)
		runSmokeCommand(t, ctx, "ip", "netns", "exec", item.ns, "ip", "link", "set", item.iface, "up")
	}
}

func generateWGKeyPair(t *testing.T, ctx context.Context, wgBinary, privatePath string) (string, string) {
	t.Helper()
	privateKey := strings.TrimSpace(runSmokeCommand(t, ctx, wgBinary, "genkey"))
	if err := os.WriteFile(privatePath, []byte(privateKey+"\n"), 0o600); err != nil {
		t.Fatalf("write WireGuard private key: %v", err)
	}
	cmd := exec.CommandContext(ctx, wgBinary, "pubkey")
	cmd.Stdin = strings.NewReader(privateKey + "\n")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("derive WireGuard public key: %v\noutput: %s", err, out)
	}
	return privatePath, strings.TrimSpace(string(out))
}

func configureWGDevice(t *testing.T, ctx context.Context, wgBinary, ns, privatePath, address string, peers []wgPeer) {
	t.Helper()
	runSmokeCommand(t, ctx, "ip", "netns", "exec", ns, "ip", "link", "add", "wg7", "type", "wireguard")
	runSmokeCommand(t, ctx, "ip", "netns", "exec", ns, "ip", "addr", "add", address, "dev", "wg7")
	args := []string{"netns", "exec", ns, wgBinary, "set", "wg7", "private-key", privatePath, "listen-port", "51820"}
	for _, peer := range peers {
		args = append(args, "peer", peer.publicKey, "allowed-ips", peer.allowedIP, "endpoint", peer.endpoint, "persistent-keepalive", "1")
	}
	runSmokeCommand(t, ctx, "ip", args...)
	runSmokeCommand(t, ctx, "ip", "netns", "exec", ns, "ip", "link", "set", "dev", "wg7", "mtu", "1420", "up")
}

func assertWGPeers(t *testing.T, ctx context.Context, wgBinary, ns string, wantPeers int, wantAllowed []string) {
	t.Helper()
	peers := strings.Fields(runSmokeCommand(t, ctx, "ip", "netns", "exec", ns, wgBinary, "show", "wg7", "peers"))
	if len(peers) != wantPeers {
		t.Fatalf("%s WireGuard peers = %d, want %d", ns, len(peers), wantPeers)
	}
	allowed := runSmokeCommand(t, ctx, "ip", "netns", "exec", ns, wgBinary, "show", "wg7", "allowed-ips")
	for _, prefix := range wantAllowed {
		if !strings.Contains(allowed, prefix) {
			t.Fatalf("%s WireGuard AllowedIPs missing %s: %s", ns, prefix, allowed)
		}
	}
	for _, forbidden := range []string{"10.220.2.0/24", "10.220.3.0/24"} {
		if strings.Contains(allowed, forbidden) {
			t.Fatalf("%s WireGuard AllowedIPs contains business prefix %s: %s", ns, forbidden, allowed)
		}
	}
}

func pingSmoke(t *testing.T, ctx context.Context, ns, target string) {
	t.Helper()
	runSmokeCommand(t, ctx, "ip", "netns", "exec", ns, "ping", "-c", "3", "-W", "1", target)
}

func pingSmokeFrom(t *testing.T, ctx context.Context, ns, source, target string) {
	t.Helper()
	runSmokeCommand(t, ctx, "ip", "netns", "exec", ns, "ping", "-I", source, "-c", "3", "-W", "1", target)
}

func configureGRE(t *testing.T, ctx context.Context, ns, iface, local, remote, key, ipv4, ipv6 string) {
	t.Helper()
	runSmokeCommand(t, ctx, "ip", "netns", "exec", ns, "ip", "link", "add", iface, "type", "gre", "local", local, "remote", remote, "key", key, "ttl", "64")
	runSmokeCommand(t, ctx, "ip", "netns", "exec", ns, "ip", "link", "set", "dev", iface, "mtu", "1360")
	runSmokeCommand(t, ctx, "ip", "netns", "exec", ns, "ip", "addr", "add", ipv4, "dev", iface)
	runSmokeCommand(t, ctx, "ip", "netns", "exec", ns, "ip", "-6", "addr", "add", ipv6, "dev", iface, "nodad")
	runSmokeCommand(t, ctx, "ip", "netns", "exec", ns, "ip", "link", "set", iface, "up")
}

func configureServiceInterface(t *testing.T, ctx context.Context, ns, address string) {
	t.Helper()
	runSmokeCommand(t, ctx, "ip", "netns", "exec", ns, "ip", "link", "add", "svc0", "type", "dummy")
	runSmokeCommand(t, ctx, "ip", "netns", "exec", ns, "ip", "addr", "add", address, "dev", "svc0")
	runSmokeCommand(t, ctx, "ip", "netns", "exec", ns, "ip", "link", "set", "svc0", "up")
}

func experimentBirdSpec(ns, dir string) bird.BirdInstanceSpec {
	return bird.BirdInstanceSpec{
		NetNSName:         ns,
		Mode:              bird.BirdModeManaged,
		NetNS:             bird.NetNSSpec{Kind: "name", Name: ns},
		ControlSocketPath: filepath.Join(dir, "bird.ctl"),
		PIDFilePath:       filepath.Join(dir, "bird.pid"),
		ConfigPath:        filepath.Join(dir, "bird.conf"),
	}
}

func wgGREBirdConfig(routerID, logPath string) string {
	return fmt.Sprintf(`# Phase 7.1.b WireGuard/GRE Babel experiment
log %q all;
debug protocols all;
router id %s;
ipv4 table master4;
protocol device { scan time 1; }
protocol kernel { ipv4 { export all; }; learn; }
protocol direct {
    ipv4;
    interface "svc*";
}
protocol babel {
    ipv4 {
        import all;
        export where source = RTS_BABEL || source = RTS_DEVICE;
    };
    interface "hgsg*" {
        type tunnel;
        hello interval 1 s;
        update interval 1 s;
    };
}
`, logPath, routerID)
}

func waitForBirdRoutes(t *testing.T, ctx context.Context, socketPath string, prefixes []string) {
	t.Helper()
	var last string
	for i := 0; i < 30; i++ {
		out, err := exec.CommandContext(ctx, "birdc", "-s", socketPath, "show", "route").CombinedOutput()
		last = string(out)
		if err == nil {
			all := true
			for _, prefix := range prefixes {
				all = all && strings.Contains(last, prefix)
			}
			if all {
				return
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("BIRD routes %v not learned; last output:\n%s", prefixes, last)
}
