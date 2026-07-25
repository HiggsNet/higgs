package firewall

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestFirewallBackendsRootSmoke(t *testing.T) {
	if os.Getenv("HIGGS_FIREWALL_SMOKE") != "1" {
		t.Skip("set HIGGS_FIREWALL_SMOKE=1 to run the root/system firewall smoke")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	suffix := fmt.Sprintf("%06d", time.Now().UnixNano()%1000000)
	nsName := "hfw" + suffix
	if err := runCmd(ctx, "ip", "netns", "add", nsName); err != nil {
		t.Fatalf("ip netns add %s: %v", nsName, err)
	}
	t.Cleanup(func() {
		_ = exec.Command("ip", "netns", "delete", nsName).Run()
	})
	if err := runCmd(ctx, "ip", "netns", "exec", nsName, "ip", "link", "set", "lo", "up"); err != nil {
		t.Fatalf("set lo up in %s: %v", nsName, err)
	}

	if _, err := exec.LookPath("nft"); err == nil {
		t.Run("nft", func(t *testing.T) {
			runFirewallBackendRootSmoke(t, ctx, nsName, "nft")
		})
	} else {
		t.Log("nft not found; skipping nft backend root smoke")
	}

	_, iptablesErr := exec.LookPath("iptables")
	_, ip6tablesErr := exec.LookPath("ip6tables")
	if iptablesErr == nil && ip6tablesErr == nil {
		t.Run("iptables", func(t *testing.T) {
			runFirewallBackendRootSmoke(t, ctx, nsName, "iptables")
		})
	} else {
		t.Log("iptables/ip6tables not both available; skipping iptables backend root smoke")
	}
}

func runFirewallBackendRootSmoke(t *testing.T, ctx context.Context, nsName, backend string) {
	t.Helper()

	ownerPrefix := "hfn"
	if backend == BackendIptables {
		ownerPrefix = "hfi"
	}
	spec := FirewallInstanceSpec{
		ID:                backend + "-overlay",
		NetNS:             nsName,
		Enabled:           true,
		Mode:              ModeManaged,
		Backend:           backend,
		DefaultPolicy:     DefaultPolicyDrop,
		OwnerPrefix:       ownerPrefix,
		XFRMTunnelPattern: "hgs+",
		LocalServices: []LocalService{
			{Proto: ProtoTCP, Port: 8080},
		},
	}
	inlineWant := []string{}
	switch backend {
	case BackendNFT:
		spec.NativeHooks.NFT.PreInput = []string{
			`ip saddr 198.51.100.7 counter comment "higgs-inline-nft-v4"`,
			`ip6 saddr 2001:db8:ffff::7 counter comment "higgs-inline-nft-v6"`,
		}
		inlineWant = append(inlineWant, "higgs-inline-nft-v4", "higgs-inline-nft-v6")
	case BackendIptables:
		spec.NativeHooks.IPTables.IPv4.PreInput = []string{
			`-s 198.51.100.7/32 -m comment --comment "higgs-inline-iptables-v4" -j ACCEPT`,
		}
		spec.NativeHooks.IPTables.IPv6.PreInput = []string{
			`-s 2001:db8:ffff::7/128 -m comment --comment "higgs-inline-iptables-v6" -j ACCEPT`,
		}
		inlineWant = append(inlineWant, "higgs-inline-iptables-v4", "higgs-inline-iptables-v6")
	}
	input := FirewallPolicyInput{
		LocalAssigned:      []netip.Prefix{mustPrefix(t, "10.42.0.2/32")},
		MeshAuthorized:     []netip.Prefix{mustPrefix(t, "10.42.0.1/32"), mustPrefix(t, "10.43.0.0/24")},
		Revoked:            []netip.Prefix{mustPrefix(t, "10.99.0.0/24")},
		LiveInterfaces:     []string{"hgs0"},
		UpstreamInterfaces: []string{"up0"},
		Forwarding: ForwardingPolicy{
			Transit:       true,
			AllowPrefixes: []netip.Prefix{mustPrefix(t, "10.42.0.1/32"), mustPrefix(t, "10.42.0.2/32")},
		},
	}
	desired, err := BuildDesiredState(spec, input)
	if err != nil {
		t.Fatalf("BuildDesiredState overlay: %v", err)
	}

	cleanupFirewallBackend(t, ctx, nsName, backend, ownerPrefix, spec.NetNS)
	driver := newRootSmokeDriver(backend, nsName)
	observed, err := driver.ListOwned(ctx, Owner{OwnerPrefix: ownerPrefix, InstanceID: spec.NetNS})
	if err != nil {
		t.Fatalf("ListOwned overlay: %v", err)
	}
	plan, err := driver.Plan(ctx, desired, observed)
	if err != nil {
		t.Fatalf("Plan overlay: %v", err)
	}
	result, err := driver.Apply(ctx, plan, desired)
	if err != nil {
		t.Fatalf("Apply overlay failed after %d applied/%d failed: %v\nerrors: %s", result.Applied, result.Failed, err, strings.Join(result.Errors, "\n"))
	}
	assertFirewallBackendState(t, ctx, nsName, backend, ownerPrefix, spec.NetNS, append([]string{"10.42.0.1", "10.43.0.0/24"}, inlineWant...), []string{"10.99.0.0/24"})

	revokedSpec := spec
	revokedSpec.OwnerPrefix = ownerPrefix + "r"
	revokedInput := input
	revokedInput.Revoked = append(revokedInput.Revoked, mustPrefix(t, "10.43.0.0/24"))
	revokedDesired, err := BuildDesiredState(revokedSpec, revokedInput)
	if err != nil {
		t.Fatalf("BuildDesiredState revoked overlay: %v", err)
	}
	cleanupFirewallBackend(t, ctx, nsName, backend, revokedSpec.OwnerPrefix, revokedSpec.NetNS)
	plan, err = driver.Plan(ctx, revokedDesired, FirewallObservedState{})
	if err != nil {
		t.Fatalf("Plan revoked overlay: %v", err)
	}
	result, err = driver.Apply(ctx, plan, revokedDesired)
	if err != nil {
		t.Fatalf("Apply revoked overlay failed after %d applied/%d failed: %v\nerrors: %s", result.Applied, result.Failed, err, strings.Join(result.Errors, "\n"))
	}
	assertFirewallBackendState(t, ctx, nsName, backend, revokedSpec.OwnerPrefix, revokedSpec.NetNS, []string{"10.42.0.1"}, []string{"10.43.0.0/24", "10.99.0.0/24"})

	hostOwnerPrefix := ownerPrefix + "h"
	hostSpec := FirewallInstanceSpec{
		ID:             backend + "-host",
		NetNS:          "host",
		IsHost:         true,
		Enabled:        true,
		Mode:           ModeManaged,
		Backend:        backend,
		OwnerPrefix:    hostOwnerPrefix,
		HostPorts:      HostPortConfig{IKE: true, NATT: true},
		RedirectGrace:  RedirectGrace{Enabled: true},
		ListenAddrs:    []netip.Addr{netip.MustParseAddr("127.0.0.1")},
		CharonIKEPort:  1500,
		CharonNATTPort: 14500,
	}
	hostInlineWant := []string{}
	switch backend {
	case BackendNFT:
		hostSpec.NativeHooks.NFT.HostPreInput = []string{`udp dport 16000 counter comment "higgs-inline-host-input"`}
		hostSpec.NativeHooks.NFT.HostPrePrerouting = []string{`tcp dport 18080 counter comment "higgs-inline-host-prerouting"`}
		hostInlineWant = append(hostInlineWant, "higgs-inline-host-input", "higgs-inline-host-prerouting")
	case BackendIptables:
		hostSpec.NativeHooks.IPTables.IPv4.HostPreInput = []string{`-p udp --dport 16000 -m comment --comment "higgs-inline-host-input"`}
		hostSpec.NativeHooks.IPTables.IPv4.HostPrePrerouting = []string{`-p tcp --dport 18080 -m comment --comment "higgs-inline-host-prerouting"`}
		hostInlineWant = append(hostInlineWant, "higgs-inline-host-input", "higgs-inline-host-prerouting")
	}
	hostInput := FirewallPolicyInput{
		AdvertisedPreviousIKEPorts:  []uint16{500},
		AdvertisedPreviousNATTPorts: []uint16{4500},
	}
	hostDesired, err := BuildDesiredState(hostSpec, hostInput)
	if err != nil {
		t.Fatalf("BuildDesiredState host: %v", err)
	}
	cleanupFirewallBackend(t, ctx, nsName, backend, hostOwnerPrefix, "host")
	hostObserved, err := driver.ListOwned(ctx, Owner{OwnerPrefix: hostOwnerPrefix, InstanceID: "host"})
	if err != nil {
		t.Fatalf("ListOwned host: %v", err)
	}
	hostPlan, err := driver.Plan(ctx, hostDesired, hostObserved)
	if err != nil {
		t.Fatalf("Plan host: %v", err)
	}
	hostResult, err := driver.Apply(ctx, hostPlan, hostDesired)
	if err != nil {
		t.Fatalf("Apply host failed after %d applied/%d failed: %v\nerrors: %s", hostResult.Applied, hostResult.Failed, err, strings.Join(hostResult.Errors, "\n"))
	}
	assertFirewallBackendState(t, ctx, nsName, backend, hostOwnerPrefix, "host", append([]string{"1500", "14500"}, hostInlineWant...), nil)
}

func newRootSmokeDriver(backend, nsName string) FirewallDriver {
	switch backend {
	case BackendNFT:
		return &NFTDriver{NetNS: nsName}
	case BackendIptables:
		return &IPTablesDriver{NetNS: nsName}
	default:
		return NewDryRunDriver()
	}
}

func assertFirewallBackendState(t *testing.T, ctx context.Context, nsName, backend, ownerPrefix, scope string, want, reject []string) {
	t.Helper()
	out := firewallBackendDump(t, ctx, nsName, backend, ownerPrefix, scope)
	for _, needle := range want {
		if !strings.Contains(out, needle) {
			t.Fatalf("%s %s dump missing %q:\n%s", backend, scope, needle, out)
		}
	}
	for _, needle := range reject {
		if strings.Contains(out, needle) {
			t.Fatalf("%s %s dump unexpectedly contains %q:\n%s", backend, scope, needle, out)
		}
	}
}

func firewallBackendDump(t *testing.T, ctx context.Context, nsName, backend, ownerPrefix, scope string) string {
	t.Helper()
	tableName := ownerPrefix + "_" + scope
	switch backend {
	case BackendNFT:
		out, err := exec.CommandContext(ctx, "ip", "netns", "exec", nsName, "nft", "list", "table", "inet", tableName).CombinedOutput()
		if err != nil {
			t.Fatalf("nft list table inet %s: %v\noutput: %s", tableName, err, string(out))
		}
		return string(out)
	case BackendIptables:
		var dumps []string
		for _, binary := range []string{"iptables", "ip6tables"} {
			out, err := exec.CommandContext(ctx, "ip", "netns", "exec", nsName, binary, "-S").CombinedOutput()
			if err != nil {
				t.Fatalf("%s -S: %v\noutput: %s", binary, err, string(out))
			}
			nat, _ := exec.CommandContext(ctx, "ip", "netns", "exec", nsName, binary, "-t", "nat", "-S").CombinedOutput()
			dumps = append(dumps, string(out), string(nat))
		}
		var lines []string
		for _, line := range strings.Split(strings.Join(dumps, "\n"), "\n") {
			if strings.Contains(line, tableName) {
				lines = append(lines, line)
			}
		}
		return strings.Join(lines, "\n")
	default:
		return ""
	}
}

func cleanupFirewallBackend(t *testing.T, ctx context.Context, nsName, backend, ownerPrefix, scope string) {
	t.Helper()
	t.Cleanup(func() {
		cleanupFirewallBackendNow(context.Background(), nsName, backend, ownerPrefix, scope)
	})
	cleanupFirewallBackendNow(ctx, nsName, backend, ownerPrefix, scope)
}

func cleanupFirewallBackendNow(ctx context.Context, nsName, backend, ownerPrefix, scope string) {
	tableName := ownerPrefix + "_" + scope
	switch backend {
	case BackendNFT:
		_ = exec.CommandContext(ctx, "ip", "netns", "exec", nsName, "nft", "delete", "table", "inet", tableName).Run()
	case BackendIptables:
		for _, binary := range []string{"iptables", "ip6tables"} {
			for _, chain := range []string{
				tableName + "_input", tableName + "_forward", tableName + "_output",
				tableName + "_INPUT", tableName + "_FORWARD", tableName + "_OUTPUT",
			} {
				_ = exec.CommandContext(ctx, "ip", "netns", "exec", nsName, binary, "-D", "INPUT", "-j", chain).Run()
				_ = exec.CommandContext(ctx, "ip", "netns", "exec", nsName, binary, "-D", "FORWARD", "-j", chain).Run()
				_ = exec.CommandContext(ctx, "ip", "netns", "exec", nsName, binary, "-D", "OUTPUT", "-j", chain).Run()
				_ = exec.CommandContext(ctx, "ip", "netns", "exec", nsName, binary, "-F", chain).Run()
				_ = exec.CommandContext(ctx, "ip", "netns", "exec", nsName, binary, "-X", chain).Run()
			}
			for _, item := range []struct {
				builtin string
				chain   string
			}{
				{"PREROUTING", tableName + "_prerouting"},
				{"POSTROUTING", tableName + "_postrouting"},
			} {
				_ = exec.CommandContext(ctx, "ip", "netns", "exec", nsName, binary, "-t", "nat", "-D", item.builtin, "-j", item.chain).Run()
				_ = exec.CommandContext(ctx, "ip", "netns", "exec", nsName, binary, "-t", "nat", "-F", item.chain).Run()
				_ = exec.CommandContext(ctx, "ip", "netns", "exec", nsName, binary, "-t", "nat", "-X", item.chain).Run()
			}
		}
		_ = exec.CommandContext(ctx, "ip", "netns", "exec", nsName, "iptables", "-t", "nat", "-D", "PREROUTING", "-p", "udp", "--dport", "500", "-d", "127.0.0.1", "-j", "REDIRECT", "--to-ports", "1500").Run()
		_ = exec.CommandContext(ctx, "ip", "netns", "exec", nsName, "iptables", "-t", "nat", "-D", "PREROUTING", "-p", "udp", "--dport", "4500", "-d", "127.0.0.1", "-j", "REDIRECT", "--to-ports", "14500").Run()
	}
}

func runCmd(ctx context.Context, name string, args ...string) error {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w\noutput: %s", name, strings.Join(args, " "), err, string(out))
	}
	return nil
}
