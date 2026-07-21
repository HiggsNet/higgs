package firewall

import (
	"context"
	"errors"
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
	assertCommandContains(t, runner.commands, "iptables", "-t nat -A higgs_host_s_")
	assertCommandContains(t, runner.commands, "iptables", "-p udp --sport 4500 -j MASQUERADE --to-ports 33403")
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
	runner := &fakeCommandRunner{existingChains: map[string]bool{
		"iptables:filter:higgs_higgstesth2_input":  true,
		"ip6tables:filter:higgs_higgstesth2_input": true,
	}}
	d := &IPTablesDriver{Command: runner.run}
	refs := []FirewallObjectRef{
		{Kind: "chain", Family: "inet", Name: "higgs_higgstesth2_input"},
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
	output := "-N higgs_higgstesth2_INPUT\n-A higgs_higgstesth2_INPUT -p udp --dport 500 -j ACCEPT\n-N higgs_higgstesth2_FORWARD\n-N higgs_higgstesth2_pre_user\n-A INPUT -j higgs_higgstesth2_INPUT\n-N other_chain"
	refs := parseIPTablesChains(output, "higgs_higgstesth2", "filter")
	if len(refs) != 2 {
		t.Fatalf("expected 2 higgs-owned chains, got %d", len(refs))
	}
	for _, ref := range refs {
		if !strings.HasPrefix(ref.Name, "higgs_higgstesth2") {
			t.Errorf("non-higgs chain in result: %s", ref.Name)
		}
	}
	natRefs := parseIPTablesChains(
		"-N higgs_higgstesth2_prerouting\n-N higgs_higgstesth2_postrouting\n-N higgs_higgstesth2_nat_user",
		"higgs_higgstesth2", "nat",
	)
	if len(natRefs) != 2 || natRefs[0].Kind != "nat_redirect" || natRefs[1].Kind != "nat_source" {
		t.Fatalf("nat refs = %+v, want redirect/source managed objects only", natRefs)
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

func TestIPTablesDriver_CtStateCommands(t *testing.T) {
	runner := &fakeCommandRunner{}
	d := &IPTablesDriver{Command: runner.run}
	spec := FirewallInstanceSpec{
		ID: "higgstesth2", NetNS: "higgstesth2", Enabled: true, Mode: ModeManaged,
		DefaultPolicy: DefaultPolicyDrop, XFRMTunnelPattern: "hgs*",
		OwnerPrefix: "higgs",
	}
	desired, err := BuildDesiredState(spec, FirewallPolicyInput{})
	if err != nil {
		t.Fatalf("BuildDesiredState: %v", err)
	}
	plan := PlanDiff("higgstesth2", desired, FirewallObservedState{})
	if _, err := d.Apply(context.Background(), plan, desired); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	// Conntrack rules install for both address families.
	for _, binary := range []string{"iptables", "ip6tables"} {
		assertCommandContains(t, runner.commands, binary, "-m conntrack --ctstate INVALID -j DROP")
		assertCommandContains(t, runner.commands, binary, "--ctstate ESTABLISHED,RELATED -j ACCEPT")
	}
}

func TestIPTablesDriver_FamilyNeutralAndICMPCommands(t *testing.T) {
	runner := &fakeCommandRunner{}
	d := &IPTablesDriver{Command: runner.run}
	spec := FirewallInstanceSpec{
		ID: "higgstesth2", NetNS: "higgstesth2", Enabled: true, Mode: ModeManaged,
		DefaultPolicy: DefaultPolicyDrop, XFRMTunnelPattern: "hgs*",
		OwnerPrefix: "higgs",
	}
	desired, err := BuildDesiredState(spec, FirewallPolicyInput{})
	if err != nil {
		t.Fatalf("BuildDesiredState: %v", err)
	}
	plan := PlanDiff("higgstesth2", desired, FirewallObservedState{})
	if _, err := d.Apply(context.Background(), plan, desired); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	// ICMP rules render per family with an explicit protocol match.
	assertCommandContains(t, runner.commands, "iptables", "-p icmp -j ACCEPT")
	assertCommandContains(t, runner.commands, "ip6tables", "-p icmpv6 -j ACCEPT")

	// Family-neutral rules (loopback, babel control, default policy) install
	// for both address families.
	for _, binary := range []string{"iptables", "ip6tables"} {
		assertCommandContains(t, runner.commands, binary, "-i lo -j ACCEPT")
		assertCommandContains(t, runner.commands, binary, "-p udp --dport 6696 -j ACCEPT")
		assertCommandContains(t, runner.commands, binary, "-i hgs+ -o hgs+ -j DROP")
	}

	// No cross-family ICMP rendering.
	for _, cmd := range runner.commands {
		args := strings.Join(cmd.args, " ")
		if cmd.name == "iptables" && strings.Contains(args, "-p icmpv6") {
			t.Fatalf("icmpv6 rendered into iptables command: %s %s", cmd.name, args)
		}
		if cmd.name == "ip6tables" && strings.Contains(args, "-p icmp ") {
			t.Fatalf("icmp rendered into ip6tables command: %s %s", cmd.name, args)
		}
	}

	// Every accept rule in the overlay INPUT chain must carry at least one
	// match; an unconditional accept before the default policy would nullify
	// the default drop.
	chain := "higgs_higgstesth2_input"
	for _, cmd := range runner.commands {
		args := strings.Join(cmd.args, " ")
		if !strings.Contains(args, "-A "+chain) || !strings.Contains(args, "-j ACCEPT") {
			continue
		}
		matched := false
		for _, flag := range []string{"-p ", "-i ", "-o ", "-s ", "-d ", "-m "} {
			if strings.Contains(args, flag) {
				matched = true
				break
			}
		}
		if !matched {
			t.Fatalf("unconditional accept in %s: %s %s", chain, cmd.name, args)
		}
	}
}

func TestIPTablesDriverInlineHooksKeepFamiliesAndOrderSeparate(t *testing.T) {
	runner := &fakeCommandRunner{}
	driver := &IPTablesDriver{Command: runner.run}
	desired, err := BuildDesiredState(FirewallInstanceSpec{
		ID: "h2", NetNS: "h2", Mode: ModeManaged, Backend: BackendIptables, OwnerPrefix: "higgs",
		NativeHooks: NativeHooks{IPTables: IPTablesInlineHooks{
			IPv4: InlineHookRules{PreInput: []string{
				`-s 10.20.0.0/16 -p tcp --dport 22 -j ACCEPT`,
				`-s 10.30.0.0/16 -p tcp --dport 443 -j ACCEPT`,
			}},
			IPv6: InlineHookRules{PreInput: []string{
				`-s 2001:db8:20::/48 -p tcp --dport 22 -j ACCEPT`,
			}},
		}},
	}, FirewallPolicyInput{})
	if err != nil {
		t.Fatalf("BuildDesiredState: %v", err)
	}
	if _, err := driver.Apply(context.Background(), PlanDiff("h2", desired, FirewallObservedState{}), desired); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	first := commandIndex(runner.commands, "iptables", "-s 10.20.0.0/16")
	second := commandIndex(runner.commands, "iptables", "-s 10.30.0.0/16")
	if first < 0 || second < 0 || first >= second {
		t.Fatalf("IPv4 inline rule order incorrect: first=%d second=%d", first, second)
	}
	assertCommandContains(t, runner.commands, "ip6tables", "-s 2001:db8:20::/48")
	for _, command := range runner.commands {
		args := strings.Join(command.args, " ")
		if command.name == "ip6tables" && (strings.Contains(args, "10.20.0.0/16") || strings.Contains(args, "10.30.0.0/16")) {
			t.Fatalf("IPv4 inline rule copied to ip6tables: %s", args)
		}
		if command.name == "iptables" && strings.Contains(args, "2001:db8:20::/48") {
			t.Fatalf("IPv6 inline rule copied to iptables: %s", args)
		}
	}
}

func TestIPTablesDriverHostPreroutingInlineRuleUsesNATTable(t *testing.T) {
	runner := &fakeCommandRunner{}
	driver := &IPTablesDriver{Command: runner.run}
	desired, err := BuildDesiredState(FirewallInstanceSpec{
		ID: "host", NetNS: "host", IsHost: true, Mode: ModeManaged, Backend: BackendIptables, OwnerPrefix: "higgs",
		NativeHooks: NativeHooks{IPTables: IPTablesInlineHooks{
			IPv4: InlineHookRules{HostPrePrerouting: []string{`-p tcp --dport 8080 -j ACCEPT`}},
		}},
	}, FirewallPolicyInput{})
	if err != nil {
		t.Fatalf("BuildDesiredState: %v", err)
	}
	if _, err := driver.Apply(context.Background(), PlanDiff("host", desired, FirewallObservedState{}), desired); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	assertCommandContains(t, runner.commands, "iptables", "-t nat -A higgs_host_r_")
	assertCommandContains(t, runner.commands, "iptables", "-p tcp --dport 8080 -j ACCEPT")
}

func TestIPTablesDriver_ReconcileExistingManagedChains(t *testing.T) {
	runner := &fakeCommandRunner{}
	d := &IPTablesDriver{Command: runner.run}
	spec := FirewallInstanceSpec{
		ID: "higgstesth2", NetNS: "higgstesth2", Enabled: true, Mode: ModeManaged,
		DefaultPolicy: DefaultPolicyDrop, XFRMTunnelPattern: "hgs*",
		OwnerPrefix: "higgs",
	}
	desired, err := BuildDesiredState(spec, FirewallPolicyInput{})
	if err != nil {
		t.Fatalf("BuildDesiredState: %v", err)
	}
	firstPlan := PlanDiff(spec.ID, desired, FirewallObservedState{})
	if _, err := d.Apply(context.Background(), firstPlan, desired); err != nil {
		t.Fatalf("first Apply: %v", err)
	}

	observed, err := d.ListOwned(context.Background(), Owner{OwnerPrefix: "higgs", InstanceID: spec.NetNS})
	if err != nil {
		t.Fatalf("ListOwned after first apply: %v", err)
	}
	if len(observed.Objects) != len(DesiredObjects(desired)) {
		t.Fatalf("observed = %+v, want canonical desired objects %+v", observed.Objects, DesiredObjects(desired))
	}

	runner.commands = nil
	secondPlan := PlanDiff(spec.ID, desired, observed)
	if _, err := d.Apply(context.Background(), secondPlan, desired); err != nil {
		t.Fatalf("second Apply: %v", err)
	}

	tableName := iptablesTableName(desired)
	hash := DesiredStateHash(desired)
	oldInput := iptablesGenerationChain(tableName, "i", hash, 'a')
	newInput := iptablesGenerationChain(tableName, "i", hash, 'b')
	populateAt := commandIndex(runner.commands, "iptables", "-A "+newInput)
	activateAt := commandIndex(runner.commands, "iptables", "-I INPUT -j "+newInput)
	removeOldAt := commandIndex(runner.commands, "iptables", "-D INPUT -j "+oldInput)
	flushOldAt := commandIndex(runner.commands, "iptables", "-F "+oldInput)
	if populateAt < 0 || activateAt < 0 || removeOldAt < 0 || flushOldAt < 0 {
		t.Fatalf("missing generation cutover commands: %+v", runner.commands)
	}
	if !(populateAt < activateAt && activateAt < removeOldAt && removeOldAt < flushOldAt) {
		t.Fatalf("unsafe cutover order: populate=%d activate=%d removeOld=%d flushOld=%d", populateAt, activateAt, removeOldAt, flushOldAt)
	}
	for _, binary := range []string{"iptables", "ip6tables"} {
		oldKey := binary + ":filter:" + oldInput
		newKey := binary + ":filter:" + newInput
		if runner.existingChains[oldKey] {
			t.Errorf("%s old generation still exists after cutover", binary)
		}
		if !runner.existingChains[newKey] {
			t.Errorf("%s new generation missing after cutover", binary)
		}
	}
	assertCommandContains(t, runner.commands, "iptables", "--ctstate ESTABLISHED,RELATED -j ACCEPT")
}

func TestIPTablesDriver_PrepareFailureKeepsActiveGeneration(t *testing.T) {
	runner := &fakeCommandRunner{}
	driver := &IPTablesDriver{Command: runner.run}
	spec := FirewallInstanceSpec{
		ID: "higgstesth2", NetNS: "higgstesth2", Enabled: true, Mode: ModeManaged,
		DefaultPolicy: DefaultPolicyDrop, XFRMTunnelPattern: "hgs*", OwnerPrefix: "higgs",
	}
	desired, err := BuildDesiredState(spec, FirewallPolicyInput{})
	if err != nil {
		t.Fatalf("BuildDesiredState: %v", err)
	}
	plan := PlanDiff(spec.ID, desired, FirewallObservedState{})
	if _, err := driver.Apply(context.Background(), plan, desired); err != nil {
		t.Fatalf("first Apply: %v", err)
	}

	tableName := iptablesTableName(desired)
	hash := DesiredStateHash(desired)
	activeInput := iptablesGenerationChain(tableName, "i", hash, 'a')
	stagingInput := iptablesGenerationChain(tableName, "i", hash, 'b')
	runner.commands = nil
	runner.failContains = "--ctstate ESTABLISHED,RELATED"
	result, err := driver.Apply(context.Background(), plan, desired)
	if err == nil {
		t.Fatal("second Apply succeeded despite injected staging failure")
	}
	if result.Failed == 0 {
		t.Fatalf("result = %+v, want a reported failure", result)
	}
	for _, binary := range []string{"iptables", "ip6tables"} {
		if !runner.existingChains[binary+":filter:"+activeInput] {
			t.Errorf("%s active generation was removed after staging failure", binary)
		}
		jump := []string{"INPUT", "-j", activeInput, "-m", "comment", "--comment", "higgs-higgstesth2"}
		key := binary + ":filter:" + strings.Join(jump, "\x00")
		if !runner.existingRules[key] {
			t.Errorf("%s active jump was removed after staging failure", binary)
		}
		if runner.existingChains[binary+":filter:"+stagingInput] {
			t.Errorf("%s failed staging generation was not discarded", binary)
		}
	}
	if commandIndex(runner.commands, "iptables", "-I INPUT -j "+stagingInput) >= 0 {
		t.Fatal("failed staging generation was activated")
	}
}

func TestIPTablesDriver_ActivationFailureRollsBackOtherFamily(t *testing.T) {
	runner := &fakeCommandRunner{}
	driver := &IPTablesDriver{Command: runner.run}
	desired, err := BuildDesiredState(FirewallInstanceSpec{
		ID: "higgstesth2", NetNS: "higgstesth2", Enabled: true, Mode: ModeManaged,
		DefaultPolicy: DefaultPolicyDrop, XFRMTunnelPattern: "hgs*", OwnerPrefix: "higgs",
	}, FirewallPolicyInput{})
	if err != nil {
		t.Fatalf("BuildDesiredState: %v", err)
	}
	plan := PlanDiff(desired.Instance.ID, desired, FirewallObservedState{})
	if _, err := driver.Apply(context.Background(), plan, desired); err != nil {
		t.Fatalf("first Apply: %v", err)
	}

	tableName := iptablesTableName(desired)
	hash := DesiredStateHash(desired)
	activeInput := iptablesGenerationChain(tableName, "i", hash, 'a')
	stagingInput := iptablesGenerationChain(tableName, "i", hash, 'b')
	runner.commands = nil
	failed := false
	driver.Command = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if !failed && name == "ip6tables" && strings.Contains(strings.Join(args, " "), "-I INPUT -j "+stagingInput) {
			failed = true
			runner.commands = append(runner.commands, executedCommand{name: name, args: append([]string(nil), args...)})
			return nil, errors.New("injected activation failure")
		}
		return runner.run(ctx, name, args...)
	}
	if _, err := driver.Apply(context.Background(), plan, desired); err == nil {
		t.Fatal("second Apply succeeded despite injected activation failure")
	}
	if !failed {
		t.Fatal("activation failure was not injected")
	}
	for _, binary := range []string{"iptables", "ip6tables"} {
		activeJump := []string{"INPUT", "-j", activeInput, "-m", "comment", "--comment", "higgs-higgstesth2"}
		if !runner.existingRules[binary+":filter:"+strings.Join(activeJump, "\x00")] {
			t.Errorf("%s old active jump missing after activation rollback", binary)
		}
		stagingJump := []string{"INPUT", "-j", stagingInput, "-m", "comment", "--comment", "higgs-higgstesth2"}
		if runner.existingRules[binary+":filter:"+strings.Join(stagingJump, "\x00")] {
			t.Errorf("%s staging jump remained after activation rollback", binary)
		}
		if runner.existingChains[binary+":filter:"+stagingInput] {
			t.Errorf("%s staging chain remained after activation rollback", binary)
		}
	}
}

func TestIPTablesDriver_MigrationDrainsAllLegacyDuplicateJumps(t *testing.T) {
	runner := &fakeCommandRunner{}
	const duplicates = 12
	legacy := "higgs_higgstesth2_INPUT"
	jump := []string{"INPUT", "-j", legacy, "-m", "comment", "--comment", "higgs-higgstesth2"}
	for _, binary := range []string{"iptables", "ip6tables"} {
		runner.seedIPTablesChain(binary, "filter", legacy)
		for i := 0; i < duplicates; i++ {
			runner.seedIPTablesRule(binary, "filter", jump)
		}
	}
	driver := &IPTablesDriver{Command: runner.run}
	desired, err := BuildDesiredState(FirewallInstanceSpec{
		ID: "higgstesth2", NetNS: "higgstesth2", Enabled: true, Mode: ModeManaged,
		DefaultPolicy: DefaultPolicyDrop, XFRMTunnelPattern: "hgs*", OwnerPrefix: "higgs",
	}, FirewallPolicyInput{})
	if err != nil {
		t.Fatalf("BuildDesiredState: %v", err)
	}
	if _, err := driver.Apply(context.Background(), PlanDiff(desired.Instance.ID, desired, FirewallObservedState{}), desired); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	for _, binary := range []string{"iptables", "ip6tables"} {
		if runner.existingChains[binary+":filter:"+legacy] {
			t.Errorf("%s legacy chain remains after migration", binary)
		}
		deletes := 0
		for _, command := range runner.commands {
			if command.name == binary && strings.Contains(strings.Join(command.args, " "), "-D INPUT -j "+legacy) {
				deletes++
			}
		}
		// One final failed delete terminates the drain loop.
		if deletes != duplicates+1 {
			t.Errorf("%s attempted %d duplicate-jump deletes, want %d", binary, deletes, duplicates+1)
		}
	}
}

func TestIPTablesGenerationChainNameIsBoundedAndRecognized(t *testing.T) {
	tableName := "higgs_a_very_long_network_namespace_name"
	chain := iptablesGenerationChain(tableName, "i", "0123456789abcdef", 'a')
	if len(chain) > 28 {
		t.Fatalf("generation chain %q has length %d, want <= 28", chain, len(chain))
	}
	ref, builtin, ok := managedIPTablesChainIdentity(tableName, "filter", chain)
	if !ok || builtin != "INPUT" {
		t.Fatalf("generation chain identity = (%+v, %q, %v)", ref, builtin, ok)
	}
	if ref.Name != tableName+"_input" {
		t.Fatalf("logical ref = %q, want %q", ref.Name, tableName+"_input")
	}
}

func commandIndex(commands []executedCommand, binary, fragment string) int {
	for i, command := range commands {
		if command.name == binary && strings.Contains(strings.Join(command.args, " "), fragment) {
			return i
		}
	}
	return -1
}

func TestIPTablesMatchArgSetsSkipsCrossFamilyPairs(t *testing.T) {
	rule := Rule{
		Action: ActionAccept,
		Src: []netip.Prefix{
			netip.MustParsePrefix("10.0.0.0/8"),
			netip.MustParsePrefix("2001:db8::/32"),
		},
		Dst: []netip.Prefix{
			netip.MustParsePrefix("192.0.2.0/24"),
			netip.MustParsePrefix("2001:db8:1::/48"),
		},
	}
	matches := iptablesMatchArgSets(rule)
	if len(matches) != 2 {
		t.Fatalf("match sets = %v, want two same-family pairs", matches)
	}
	for _, match := range matches {
		var src, dst netip.Prefix
		for i := 0; i+1 < len(match); i++ {
			switch match[i] {
			case "-s":
				src = netip.MustParsePrefix(match[i+1])
			case "-d":
				dst = netip.MustParsePrefix(match[i+1])
			}
		}
		if !src.IsValid() || !dst.IsValid() || src.Addr().Is4() != dst.Addr().Is4() {
			t.Fatalf("cross-family or incomplete match generated: %v", match)
		}
	}
}

func TestPlanDiffKeepsObservedNATChains(t *testing.T) {
	spec := FirewallInstanceSpec{
		ID: "host", NetNS: "host", IsHost: true, Enabled: true, Mode: ModeManaged,
		OwnerPrefix: "higgs", RedirectGrace: RedirectGrace{Enabled: true},
	}
	desired, err := BuildDesiredState(spec, FirewallPolicyInput{
		AdvertisedCurrentNATTPorts: []uint16{33403},
	})
	if err != nil {
		t.Fatalf("BuildDesiredState: %v", err)
	}
	observed := FirewallObservedState{Objects: []FirewallObjectRef{
		{Kind: "table", Family: "inet", Name: "higgs_host"},
		{Kind: "chain", Family: "inet", Name: "higgs_host_input"},
		{Kind: "nat_redirect", Family: "inet", Name: "higgs_host_prerouting"},
		{Kind: "nat_source", Family: "inet", Name: "higgs_host_postrouting"},
	}}
	for _, action := range PlanDiff(spec.ID, desired, observed).Actions {
		if action.Action == "delete" {
			t.Fatalf("current NAT object planned for deletion: %+v", action)
		}
	}
}

func TestIPTablesApplyRemovesDisabledNATChainsFromNATTable(t *testing.T) {
	spec := FirewallInstanceSpec{
		ID: "host", NetNS: "host", IsHost: true, Enabled: true, Mode: ModeManaged,
		OwnerPrefix: "higgs",
	}
	desired, err := BuildDesiredState(spec, FirewallPolicyInput{})
	if err != nil {
		t.Fatalf("BuildDesiredState: %v", err)
	}
	runner := &fakeCommandRunner{}
	for _, binary := range []string{"iptables", "ip6tables"} {
		runner.seedIPTablesChain(binary, "nat", "higgs_host_prerouting")
		runner.seedIPTablesRule(binary, "nat", []string{"PREROUTING", "-j", "higgs_host_prerouting", "-m", "comment", "--comment", "higgs-host"})
		runner.seedIPTablesChain(binary, "nat", "higgs_host_postrouting")
		runner.seedIPTablesRule(binary, "nat", []string{"POSTROUTING", "-j", "higgs_host_postrouting", "-m", "comment", "--comment", "higgs-host"})
	}
	driver := &IPTablesDriver{Command: runner.run}
	if _, err := driver.Apply(context.Background(), FirewallPlan{}, desired); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	for _, want := range []string{
		"-t nat -D PREROUTING -j higgs_host_prerouting",
		"-t nat -F higgs_host_prerouting",
		"-t nat -X higgs_host_prerouting",
		"-t nat -D POSTROUTING -j higgs_host_postrouting",
		"-t nat -F higgs_host_postrouting",
		"-t nat -X higgs_host_postrouting",
	} {
		found := false
		for _, cmd := range runner.commands {
			if strings.Contains(strings.Join(cmd.args, " "), want) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing NAT stale cleanup containing %q in %+v", want, runner.commands)
		}
	}
}

func TestLegacyNATRuleNumbersDescending(t *testing.T) {
	output := `Chain PREROUTING (policy ACCEPT)
num  target     prot opt source destination
1    REDIRECT   udp  --  0.0.0.0/0 0.0.0.0/0 /* other */ redir ports 500
2    REDIRECT   udp  --  0.0.0.0/0 0.0.0.0/0 /* higgs-host:old one */ redir ports 500
5    REDIRECT   udp  --  0.0.0.0/0 0.0.0.0/0 /* higgs-host:old two */ redir ports 4500`
	got := legacyNATRuleNumbers(output, "higgs-host")
	if len(got) != 2 || got[0] != 5 || got[1] != 2 {
		t.Fatalf("legacy rule numbers = %v, want [5 2]", got)
	}
}
