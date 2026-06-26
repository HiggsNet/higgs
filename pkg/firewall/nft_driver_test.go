package firewall

import (
	"context"
	"net/netip"
	"strings"
	"testing"
)

// fakeCommandRunner captures all commands executed by a driver for assertions.
type fakeCommandRunner struct {
	commands []executedCommand
}

type executedCommand struct {
	name string
	args []string
}

func (f *fakeCommandRunner) run(ctx context.Context, name string, args ...string) ([]byte, error) {
	f.commands = append(f.commands, executedCommand{name: name, args: args})
	// Simulate `nft list tables` returning empty (no owned objects).
	if len(args) >= 1 && args[0] == "list" {
		return []byte(""), nil
	}
	return []byte(""), nil
}

func TestNFTDriver_Preflight(t *testing.T) {
	runner := &fakeCommandRunner{}
	d := &NFTDriver{Command: runner.run}
	pf, err := d.Preflight(context.Background(), FirewallInstanceSpec{ID: "h2"})
	if err != nil {
		t.Fatalf("Preflight: %v", err)
	}
	if pf.Backend == "" {
		t.Error("backend should be set")
	}
}

func TestNFTDriver_ApplyOverlay(t *testing.T) {
	runner := &fakeCommandRunner{}
	d := &NFTDriver{Command: runner.run}
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
	// Empty observed state -> all objects are create.
	plan := PlanDiff("h2", desired, FirewallObservedState{})
	result, err := d.Apply(context.Background(), plan, desired)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if result.Applied == 0 {
		t.Error("expected non-zero applied count")
	}
	// Verify some nft commands were generated.
	if len(runner.commands) == 0 {
		t.Fatal("expected commands to be executed")
	}
	// Check for table creation.
	foundAddTable := false
	for _, cmd := range runner.commands {
		if cmd.name == "nft" && len(cmd.args) >= 2 && cmd.args[0] == "add" && cmd.args[1] == "table" {
			foundAddTable = true
		}
	}
	if !foundAddTable {
		t.Error("expected 'add table' command")
	}
}

func TestNFTDriver_ApplyHostWithNATRedirect(t *testing.T) {
	runner := &fakeCommandRunner{}
	d := &NFTDriver{Command: runner.run}
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
	if len(desired.NatRedirects) != 3 {
		t.Fatalf("expected 3 NAT redirect rules, got %d", len(desired.NatRedirects))
	}
	plan := PlanDiff("host", desired, FirewallObservedState{})
	result, err := d.Apply(context.Background(), plan, desired)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if result.Applied == 0 {
		t.Error("expected non-zero applied count")
	}
	// Check for nat prerouting chain creation.
	foundNatChain := false
	for _, cmd := range runner.commands {
		argsStr := strings.Join(cmd.args, " ")
		if strings.Contains(argsStr, "prerouting") && strings.Contains(argsStr, "nat") {
			foundNatChain = true
		}
	}
	if !foundNatChain {
		t.Error("expected NAT prerouting chain creation")
	}
}

func TestNFTDriver_ApplyHostWithNATSourceRewrite(t *testing.T) {
	runner := &fakeCommandRunner{}
	d := &NFTDriver{Command: runner.run}
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
	foundPostrouting := false
	foundMasquerade := false
	for _, cmd := range runner.commands {
		argsStr := strings.Join(cmd.args, " ")
		if strings.Contains(argsStr, "postrouting") && strings.Contains(argsStr, "srcnat") {
			foundPostrouting = true
		}
		if strings.Contains(argsStr, "sport 4500") && strings.Contains(argsStr, "masquerade to :33403") {
			foundMasquerade = true
		}
	}
	if !foundPostrouting {
		t.Error("expected NAT postrouting chain creation")
	}
	if !foundMasquerade {
		t.Error("expected NAT source-port rewrite rule")
	}
}

func TestNFTDriver_ApplyRebuildsObservedTable(t *testing.T) {
	runner := &fakeCommandRunner{}
	d := &NFTDriver{Command: runner.run}
	spec := FirewallInstanceSpec{
		ID: "host-ipsec", NetNS: "host", IsHost: true, Enabled: true, Mode: ModeManaged,
		OwnerPrefix: "higgs",
		HostPorts:   HostPortConfig{IKE: true, NATT: true},
	}
	desired, err := BuildDesiredState(spec, FirewallPolicyInput{})
	if err != nil {
		t.Fatalf("BuildDesiredState: %v", err)
	}
	plan := PlanDiff("host-ipsec", desired, FirewallObservedState{Objects: []FirewallObjectRef{
		{Kind: "table", Family: "inet", Name: "higgs_host"},
		{Kind: "chain", Family: "inet", Name: "higgs_host_input"},
	}})
	if _, err := d.Apply(context.Background(), plan, desired); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(runner.commands) < 2 {
		t.Fatalf("commands = %v, want delete table then add table", runner.commands)
	}
	first := strings.Join(runner.commands[0].args, " ")
	if first != "delete table inet higgs_host" {
		t.Fatalf("first command = %q, want table delete", first)
	}
	foundAdd := false
	for _, cmd := range runner.commands[1:] {
		if strings.Join(cmd.args, " ") == "add table inet higgs_host" {
			foundAdd = true
			break
		}
	}
	if !foundAdd {
		t.Fatalf("missing table rebuild command: %+v", runner.commands)
	}
}

func TestNFTDriver_ListOwned(t *testing.T) {
	// Simulate nft list table output.
	output := `table inet higgs_h2 {
	chain higgs_h2_input { type filter hook input priority 0; policy accept; }
	chain higgs_h2_forward { type filter hook forward priority 0; policy accept; }
	set higgs_h2_mesh_v4 { type ipv4_addr; }
}`
	state := parseNFTListOutput(output, "higgs_h2")
	if len(state.Objects) == 0 {
		t.Fatal("expected owned objects")
	}
	foundTable := false
	foundChain := false
	foundSet := false
	for _, obj := range state.Objects {
		switch obj.Kind {
		case "table":
			foundTable = true
		case "chain":
			foundChain = true
		case "set":
			foundSet = true
		}
	}
	if !foundTable {
		t.Error("missing table object")
	}
	if !foundChain {
		t.Error("missing chain object")
	}
	if !foundSet {
		t.Error("missing set object")
	}
}

func TestNFTDriver_NetNSExecution(t *testing.T) {
	runner := &fakeCommandRunner{}
	d := &NFTDriver{Command: runner.run, NetNS: "h2"}
	_, _ = d.run(context.Background(), "list", "tables")
	if len(runner.commands) == 0 {
		t.Fatal("expected command execution")
	}
	cmd := runner.commands[0]
	if cmd.name != "ip" {
		t.Errorf("expected ip command for netns exec, got %s", cmd.name)
	}
	if len(cmd.args) < 4 || cmd.args[0] != "netns" || cmd.args[1] != "exec" || cmd.args[2] != "h2" {
		t.Errorf("expected ip netns exec h2 nft, got %v", cmd.args)
	}
}

func TestNFTDriver_DeleteStale(t *testing.T) {
	runner := &fakeCommandRunner{}
	d := &NFTDriver{Command: runner.run}
	refs := []FirewallObjectRef{
		{Kind: "chain", Family: "inet", Name: "higgs_h2_stale"},
		{Kind: "table", Family: "inet", Name: "higgs_old"},
	}
	if err := d.DeleteStale(context.Background(), refs); err != nil {
		t.Fatalf("DeleteStale: %v", err)
	}
	foundDeleteChain := false
	foundDeleteTable := false
	for _, cmd := range runner.commands {
		if len(cmd.args) >= 1 && cmd.args[0] == "delete" {
			if len(cmd.args) >= 2 && cmd.args[1] == "chain" {
				foundDeleteChain = true
			}
			if len(cmd.args) >= 2 && cmd.args[1] == "table" {
				foundDeleteTable = true
			}
		}
	}
	if !foundDeleteChain {
		t.Error("missing delete chain command")
	}
	if !foundDeleteTable {
		t.Error("missing delete table command")
	}
}
