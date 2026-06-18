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
	pf, err := d.Preflight(context.Background(), FirewallInstanceSpec{ID: "h2"})
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
		ID: "h2", NetNS: "h2", Enabled: true, Mode: ModeManaged,
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
	plan := PlanDiff("h2", desired, FirewallObservedState{})
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

func TestIPTablesDriver_ListOwned(t *testing.T) {
	runner := &fakeCommandRunner{}
	d := &IPTablesDriver{Command: runner.run}
	state, err := d.ListOwned(context.Background(), Owner{OwnerPrefix: "higgs", InstanceID: "h2"})
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
		{Kind: "chain", Family: "inet", Name: "higgs_h2_stale"},
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
	output := "-N higgs_h2_INPUT\n-A higgs_h2_INPUT -p udp --dport 500 -j ACCEPT\n-N higgs_h2_FORWARD\n-A INPUT -j higgs_h2_INPUT\n-N other_chain"
	refs := parseIPTablesChains(output, "higgs_h2", "filter")
	if len(refs) != 2 {
		t.Fatalf("expected 2 higgs-owned chains, got %d", len(refs))
	}
	for _, ref := range refs {
		if !strings.HasPrefix(ref.Name, "higgs_h2") {
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
}
