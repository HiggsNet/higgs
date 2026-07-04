package firewall

import (
	"context"
	"net/netip"
	"strings"
	"testing"
)

func TestIPTablesDriver_Preflight(t *testing.T) {
	runner := &fakeCommandRunner{}
	d := &IPTablesDriver{Command: runner.run}
	pf, err := d.Preflight(context.Background(), FirewallInstanceSpec{ID: "higgstesth2"})
	if err != nil {
		t.Fatalf("Preflight: %v", err)
	}
	if pf.Backend == "" {
		t.Error("backend should be set")
	}
}

func TestIPTablesDriver_ApplyOverlay(t *testing.T) {
	runner := &fakeCommandRunner{}
	d := &IPTablesDriver{Command: runner.run}
	spec := FirewallInstanceSpec{
		ID: "higgstesth2", NetNS: "higgstesth2", Enabled: true, Mode: ModeManaged,
		DefaultPolicy: DefaultPolicyDrop, XFRMTunnelPattern: "hgs*",
		OwnerPrefix: "higgs",
	}
	input := FirewallPolicyInput{
		MeshAuthorized: []netip.Prefix{mustPrefix(t, "10.42.0.0/24")},
	}
	desired, err := BuildDesiredState(spec, input)
	if err != nil {
		t.Fatalf("BuildDesiredState: %v", err)
	}
	plan := PlanDiff("higgstesth2", desired, FirewallObservedState{})
	result, err := d.Apply(context.Background(), plan, desired)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if result.Applied == 0 {
		t.Error("expected non-zero applied count")
	}
	if len(runner.commands) == 0 {
		t.Fatal("expected commands to be executed")
	}
	foundChainCreate := false
	for _, cmd := range runner.commands {
		if cmd.name == "iptables" && len(cmd.args) >= 2 && cmd.args[0] == "-N" {
			foundChainCreate = true
		}
	}
	if !foundChainCreate {
		t.Error("expected iptables -N chain creation")
	}
}

func TestIPTablesDriver_ApplyHostWithNATRedirect(t *testing.T) {
	runner := &fakeCommandRunner{}
	d := &IPTablesDriver{Command: runner.run}
	spec := FirewallInstanceSpec{
		ID: "host", NetNS: "host", IsHost: true, Enabled: true, Mode: ModeManaged,
		OwnerPrefix:   "higgs",
		HostPorts:     HostPortConfig{IKE: true, NATT: true},
		RedirectGrace: RedirectGrace{Enabled: true},
	}
	input := FirewallPolicyInput{
		AdvertisedPreviousIKEPorts:  []uint16{450},
		AdvertisedPreviousNATTPorts: []uint16{5000, 5500},
	}
	desired, err := BuildDesiredState(spec, input)
	if err != nil {
		t.Fatalf("BuildDesiredState: %v", err)
	}
	plan := PlanDiff("host", desired, FirewallObservedState{})
	_, err = d.Apply(context.Background(), plan, desired)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	foundNatRedirect := false
	for _, cmd := range runner.commands {
		argsStr := strings.Join(cmd.args, " ")
		if strings.Contains(argsStr, "REDIRECT") && strings.Contains(argsStr, "--to-ports") {
			foundNatRedirect = true
		}
	}
	if !foundNatRedirect {
		t.Error("expected iptables NAT REDIRECT rule")
	}
}

func TestIPTablesDriver_ApplyHostWithNATSourceRewrite(t *testing.T) {
	runner := &fakeCommandRunner{}
	d := &IPTablesDriver{Command: runner.run}
	spec := FirewallInstanceSpec{
		ID: "host", NetNS: "host", IsHost: true, Enabled: true, Mode: ModeManaged,
		OwnerPrefix:   "higgs",
		HostPorts:     HostPortConfig{IKE: true, NATT: true},
		RedirectGrace: RedirectGrace{Enabled: true},
	}
	input := FirewallPolicyInput{
		AdvertisedCurrentNATTPorts: []uint16{33403},
	}
	desired, err := BuildDesiredState(spec, input)
	if err != nil {
		t.Fatalf("BuildDesiredState: %v", err)
	}
	plan := PlanDiff("host", desired, FirewallObservedState{})
	if _, err := d.Apply(context.Background(), plan, desired); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	assertCommandContains(t, runner.commands, "iptables", "-t nat -A POSTROUTING -p udp --sport 4500 -j MASQUERADE --to-ports 33403")
}

func TestIPTablesDriver_HostAddressFamilyCommands(t *testing.T) {
	runner := &fakeCommandRunner{}
	d := &IPTablesDriver{Command: runner.run}
	spec := FirewallInstanceSpec{
		ID:            "host",
		NetNS:         "host",
		IsHost:        true,
		Enabled:       true,
		Mode:          ModeManaged,
		OwnerPrefix:   "higgs",
		HostPorts:     HostPortConfig{IKE: true},
		RedirectGrace: RedirectGrace{Enabled: true},
		ListenAddrs: []netip.Addr{
			netip.MustParseAddr("192.0.2.10"),
			netip.MustParseAddr("2001:db8::10"),
		},
	}
	input := FirewallPolicyInput{
		AdvertisedCurrentIKEPorts: []uint16{30001},
	}
	desired, err := BuildDesiredState(spec, input)
	if err != nil {
		t.Fatalf("BuildDesiredState: %v", err)
	}
	plan := PlanDiff("host", desired, FirewallObservedState{})
	if _, err := d.Apply(context.Background(), plan, desired); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	for _, cmd := range runner.commands {
		args := strings.Join(cmd.args, " ")
		if cmd.name == "iptables" && strings.Contains(args, "2001:db8::10") {
			t.Fatalf("IPv6 address rendered into iptables command: %s %s", cmd.name, args)
		}
		if cmd.name == "ip6tables" && strings.Contains(args, "192.0.2.10") {
			t.Fatalf("IPv4 address rendered into ip6tables command: %s %s", cmd.name, args)
		}
	}
	assertCommandContains(t, runner.commands, "iptables", "-d 192.0.2.10")
	assertCommandContains(t, runner.commands, "ip6tables", "-d 2001:db8::10")
	assertCommandContains(t, runner.commands, "iptables", "--dport 30001 -d 192.0.2.10")
	assertCommandContains(t, runner.commands, "ip6tables", "--dport 30001 -d 2001:db8::10")
}

func TestIPTablesDriver_ListOwned(t *testing.T) {
	runner := &fakeCommandRunner{}
	d := &IPTablesDriver{Command: runner.run}
	state, err := d.ListOwned(context.Background(), Owner{OwnerPrefix: "higgs", InstanceID: "higgstesth2"})
	if err != nil {
		t.Fatalf("ListOwned: %v", err)
	}
	if len(state.Objects) != 0 {
		t.Errorf("expected 0 objects from empty output, got %d", len(state.Objects))
	}
}

func TestIPTablesDriver_DeleteStale(t *testing.T) {
	runner := &fakeCommandRunner{}
	d := &IPTablesDriver{Command: runner.run}
	refs := []FirewallObjectRef{
		{Kind: "chain", Family: "inet", Name: "higgs_higgstesth2_stale"},
	}
	if err := d.DeleteStale(context.Background(), refs); err != nil {
		t.Fatalf("DeleteStale: %v", err)
	}
	foundFlush := false
	foundDelete := false
	for _, cmd := range runner.commands {
		if len(cmd.args) >= 1 && cmd.args[0] == "-F" {
			foundFlush = true
		}
		if len(cmd.args) >= 1 && cmd.args[0] == "-X" {
			foundDelete = true
		}
	}
	if !foundFlush {
		t.Error("missing iptables -F flush command")
	}
	if !foundDelete {
		t.Error("missing iptables -X delete chain command")
	}
}

func TestParseIPTablesChains(t *testing.T) {
	output := "-N higgs_higgstesth2_INPUT\n-A higgs_higgstesth2_INPUT -p udp --dport 500 -j ACCEPT\n-N higgs_higgstesth2_FORWARD\n-A INPUT -j higgs_higgstesth2_INPUT\n-N other_chain"
	refs := parseIPTablesChains(output, "higgs_higgstesth2", "filter")
	if len(refs) != 2 {
		t.Fatalf("expected 2 higgs-owned chains, got %d", len(refs))
	}
	for _, ref := range refs {
		if !strings.HasPrefix(ref.Name, "higgs_higgstesth2") {
			t.Errorf("non-higgs chain in result: %s", ref.Name)
		}
	}
}

func TestBuildDesiredState_HostRedirectGraceHeuristic(t *testing.T) {
	spec := FirewallInstanceSpec{
		ID:            "host",
		NetNS:         "host",
		IsHost:        true,
		Enabled:       true,
		Mode:          ModeManaged,
		HostPorts:     HostPortConfig{IKE: true, NATT: true},
		RedirectGrace: RedirectGrace{Enabled: true},
	}
	input := FirewallPolicyInput{
		AdvertisedPreviousIKEPorts:  []uint16{450},
		AdvertisedPreviousNATTPorts: []uint16{5000},
	}
	desired, err := BuildDesiredState(spec, input)
	if err != nil {
		t.Fatalf("BuildDesiredState: %v", err)
	}
	if len(desired.NatRedirects) != 2 {
		t.Fatalf("expected 2 NAT redirect rules, got %d", len(desired.NatRedirects))
	}
	foundIKERedirect := false
	foundNATTRedirect := false
	for _, nr := range desired.NatRedirects {
		if nr.OriginalDst == 450 && nr.RedirectTo == 500 {
			foundIKERedirect = true
		}
		if nr.OriginalDst == 5000 && nr.RedirectTo == 4500 {
			foundNATTRedirect = true
		}
	}
	if !foundIKERedirect {
		t.Error("expected IKE redirect 450 -> 500")
	}
	if !foundNATTRedirect {
		t.Error("expected NAT-T redirect 5000 -> 4500")
	}
}

func TestBuildDesiredState_HostRedirectCurrentAndPreviousPorts(t *testing.T) {
	spec := FirewallInstanceSpec{
		ID:            "host",
		NetNS:         "host",
		IsHost:        true,
		Enabled:       true,
		Mode:          ModeManaged,
		HostPorts:     HostPortConfig{IKE: true, NATT: true},
		RedirectGrace: RedirectGrace{Enabled: true},
	}
	input := FirewallPolicyInput{
		AdvertisedCurrentIKEPorts:   []uint16{30001},
		AdvertisedCurrentNATTPorts:  []uint16{30002},
		AdvertisedPreviousIKEPorts:  []uint16{29001},
		AdvertisedPreviousNATTPorts: []uint16{29002},
		AdvertisedPreviousWGPorts:   []uint16{},
	}
	desired, err := BuildDesiredState(spec, input)
	if err != nil {
		t.Fatalf("BuildDesiredState: %v", err)
	}
	if len(desired.NatRedirects) != 4 {
		t.Fatalf("expected 4 NAT redirect rules, got %d: %+v", len(desired.NatRedirects), desired.NatRedirects)
	}
	assertNatRedirect(t, desired, 30001, 500, "redirect current")
	assertNatRedirect(t, desired, 30002, 4500, "redirect current")
	assertNatRedirect(t, desired, 29001, 500, "redirect grace")
	assertNatRedirect(t, desired, 29002, 4500, "redirect grace")
	assertNatSource(t, desired, 500, 30001, "source current")
	assertNatSource(t, desired, 4500, 30002, "source current")
}

func TestBuildDesiredState_HostRedirectCoversAllListenAddrs(t *testing.T) {
	spec := FirewallInstanceSpec{
		ID:            "host",
		NetNS:         "host",
		IsHost:        true,
		Enabled:       true,
		Mode:          ModeManaged,
		HostPorts:     HostPortConfig{IKE: true},
		RedirectGrace: RedirectGrace{Enabled: true},
		ListenAddrs: []netip.Addr{
			netip.MustParseAddr("192.0.2.10"),
			netip.MustParseAddr("192.0.2.11"),
			netip.MustParseAddr("2001:db8::10"),
		},
	}
	input := FirewallPolicyInput{
		AdvertisedCurrentIKEPorts: []uint16{30001},
	}
	desired, err := BuildDesiredState(spec, input)
	if err != nil {
		t.Fatalf("BuildDesiredState: %v", err)
	}
	if len(desired.NatRedirects) != 3 {
		t.Fatalf("expected one redirect per listen addr, got %d: %+v", len(desired.NatRedirects), desired.NatRedirects)
	}
	assertNatRedirectAddr(t, desired, 30001, 500, "192.0.2.10")
	assertNatRedirectAddr(t, desired, 30001, 500, "192.0.2.11")
	assertNatRedirectAddr(t, desired, 30001, 500, "2001:db8::10")
}

func TestBuildDesiredState_HostRedirectGraceSkipCurrentPorts(t *testing.T) {
	spec := FirewallInstanceSpec{
		ID:            "host",
		NetNS:         "host",
		IsHost:        true,
		Enabled:       true,
		Mode:          ModeManaged,
		HostPorts:     HostPortConfig{IKE: true, NATT: true},
		RedirectGrace: RedirectGrace{Enabled: true},
	}
	input := FirewallPolicyInput{
		AdvertisedPreviousIKEPorts:  []uint16{500},
		AdvertisedPreviousNATTPorts: []uint16{4500},
	}
	desired, err := BuildDesiredState(spec, input)
	if err != nil {
		t.Fatalf("BuildDesiredState: %v", err)
	}
	if len(desired.NatRedirects) != 0 {
		t.Errorf("expected 0 redirect rules for current ports, got %d", len(desired.NatRedirects))
	}
	if len(desired.NatSources) != 0 {
		t.Errorf("expected 0 source rewrite rules for current ports, got %d", len(desired.NatSources))
	}
}

func assertCommandContains(t *testing.T, commands []executedCommand, binary, fragment string) {
	t.Helper()
	for _, cmd := range commands {
		if cmd.name == binary && strings.Contains(strings.Join(cmd.args, " "), fragment) {
			return
		}
	}
	t.Fatalf("missing %s command containing %q in %+v", binary, fragment, commands)
}

func assertNatRedirect(t *testing.T, desired *FirewallDesiredState, original, target uint16, comment string) {
	t.Helper()
	for _, nr := range desired.NatRedirects {
		if nr.OriginalDst == original && nr.RedirectTo == target && strings.Contains(nr.Comment, comment) {
			return
		}
	}
	t.Fatalf("missing redirect %d -> %d comment containing %q in %+v", original, target, comment, desired.NatRedirects)
}

func assertNatRedirectAddr(t *testing.T, desired *FirewallDesiredState, original, target uint16, addr string) {
	t.Helper()
	want := netip.MustParseAddr(addr)
	for _, nr := range desired.NatRedirects {
		if nr.OriginalDst == original && nr.RedirectTo == target && nr.DstAddr == want {
			return
		}
	}
	t.Fatalf("missing redirect %d -> %d for %s in %+v", original, target, addr, desired.NatRedirects)
}

func assertNatSource(t *testing.T, desired *FirewallDesiredState, original, target uint16, comment string) {
	t.Helper()
	for _, ns := range desired.NatSources {
		if ns.OriginalSrc == original && ns.RewriteTo == target && strings.Contains(ns.Comment, comment) {
			return
		}
	}
	t.Fatalf("missing source rewrite %d -> %d comment containing %q in %+v", original, target, comment, desired.NatSources)
}
