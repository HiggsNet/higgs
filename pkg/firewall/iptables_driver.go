package firewall

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// IPTablesDriver implements FirewallDriver using iptables/ip6tables CLI.
// It is the fallback backend for Phase 6.3.6 when nftables is not available.
//
// Design:
//   - All Higgs-owned rules use a comment marker "higgs-<scope>" for ownership tracking.
//   - Chains are created with a Higgs-specific name prefix.
//   - ListOwned parses `iptables -S` / `iptables -t nat -S` output.
//   - Apply uses sequential iptables commands.
//
// The driver is designed to be testable by injecting CommandRunner.
type IPTablesDriver struct {
	Command CommandRunner
	NetNS   string
}

// NewIPTablesDriver creates an IPTablesDriver with the default command runner.
func NewIPTablesDriver() *IPTablesDriver {
	return &IPTablesDriver{Command: nftExecCommand}
}

func (d *IPTablesDriver) runner() CommandRunner {
	if d.Command != nil {
		return d.Command
	}
	return nftExecCommand
}

func (d *IPTablesDriver) run(ctx context.Context, binary string, args ...string) ([]byte, error) {
	runner := d.runner()
	if d.NetNS != "" {
		full := append([]string{"netns", "exec", d.NetNS, binary}, args...)
		return runner(ctx, "ip", full...)
	}
	return runner(ctx, binary, args...)
}

func (d *IPTablesDriver) Preflight(ctx context.Context, spec FirewallInstanceSpec) (FirewallPreflight, error) {
	pf := PreflightProbe(ctx)
	if pf.Iptables == "available" {
		if _, err := d.run(ctx, "iptables", "-L", "INPUT"); err != nil {
			pf.Iptables = "permission_denied"
			if pf.Backend == BackendIptables {
				pf.Backend = BackendNone
			}
		}
	}
	return pf, nil
}

func (d *IPTablesDriver) Plan(ctx context.Context, desired *FirewallDesiredState, observed FirewallObservedState) (FirewallPlan, error) {
	if desired == nil {
		return FirewallPlan{}, fmt.Errorf("desired state is nil")
	}
	return PlanDiff(desired.Instance.ID, desired, observed), nil
}

func (d *IPTablesDriver) Apply(ctx context.Context, plan FirewallPlan, desired *FirewallDesiredState) (FirewallApplyResult, error) {
	result := FirewallApplyResult{}
	if desired == nil {
		return result, fmt.Errorf("desired state is nil")
	}
	commands := buildIPTablesApplyCommands(plan, desired)
	var errs []string
	for _, cmd := range commands {
		binary := cmd.binary
		args := cmd.args
		if _, err := d.run(ctx, binary, args...); err != nil {
			errs = append(errs, fmt.Sprintf("%s %v: %v", binary, args, err))
			result.Failed++
		} else {
			result.Applied++
		}
	}
	result.Errors = errs
	result.Generation = 1
	if len(errs) > 0 {
		return result, fmt.Errorf("iptables apply had %d errors", len(errs))
	}
	return result, nil
}

func (d *IPTablesDriver) ListOwned(ctx context.Context, owner Owner) (FirewallObservedState, error) {
	prefix := owner.OwnerPrefix
	if prefix == "" {
		prefix = "higgs"
	}
	tableName := prefix + "_" + owner.InstanceID
	var state FirewallObservedState

	// Check filter table chains.
	out, _ := d.run(ctx, "iptables", "-S")
	state.Objects = append(state.Objects, parseIPTablesChains(string(out), tableName, "filter")...)

	out6, _ := d.run(ctx, "ip6tables", "-S")
	state.Objects = append(state.Objects, parseIPTablesChains(string(out6), tableName, "filter")...)

	// Check nat table chains.
	outNat, _ := d.run(ctx, "iptables", "-t", "nat", "-S")
	state.Objects = append(state.Objects, parseIPTablesChains(string(outNat), tableName, "nat")...)

	outNat6, _ := d.run(ctx, "ip6tables", "-t", "nat", "-S")
	state.Objects = append(state.Objects, parseIPTablesChains(string(outNat6), tableName, "nat")...)

	// Always report the table ref if any owned objects exist.
	if len(state.Objects) > 0 {
		state.Objects = append([]FirewallObjectRef{{Kind: "table", Family: "inet", Name: tableName}}, state.Objects...)
	}
	return state, nil
}

func (d *IPTablesDriver) DeleteStale(ctx context.Context, refs []FirewallObjectRef) error {
	for _, ref := range refs {
		switch ref.Kind {
		case "chain":
			// Flush and delete the chain.
			_, _ = d.run(ctx, "iptables", "-F", ref.Name)
			_, _ = d.run(ctx, "iptables", "-X", ref.Name)
		case "table":
			// iptables doesn't delete tables; just flush Higgs chains.
		}
	}
	return nil
}

// iptablesCommand represents a single iptables/ip6tables invocation.
type iptablesCommand struct {
	binary string
	args   []string
}

// buildIPTablesApplyCommands generates sequential iptables commands.
func buildIPTablesApplyCommands(plan FirewallPlan, desired *FirewallDesiredState) []iptablesCommand {
	prefix := desired.Instance.OwnerPrefix
	if prefix == "" {
		prefix = "higgs"
	}
	scope := desired.Instance.NetNS
	if desired.Instance.IsHost {
		scope = "host"
	}
	tableName := prefix + "_" + scope
	marker := "higgs-" + scope

	var commands []iptablesCommand

	// Delete stale chains.
	for _, a := range plan.Actions {
		if a.Action != "delete" {
			continue
		}
		switch a.Object.Kind {
		case "chain":
			commands = append(commands, iptablesCommand{"iptables", []string{"-F", a.Object.Name}})
			commands = append(commands, iptablesCommand{"iptables", []string{"-X", a.Object.Name}})
		}
	}

	// Check if we need to create anything.
	needCreate := false
	for _, a := range plan.Actions {
		if (a.Action == "create" || a.Action == "update") && a.Object.Kind == "table" {
			needCreate = true
			break
		}
	}
	if !needCreate {
		return commands
	}

	// Create overlay or host rules.
	if desired.Instance.IsHost {
		commands = append(commands, buildIPTablesHostCommands(tableName, marker, desired)...)
	} else {
		commands = append(commands, buildIPTablesOverlayCommands(tableName, marker, desired)...)
	}

	return commands
}

func buildIPTablesOverlayCommands(tableName, marker string, desired *FirewallDesiredState) []iptablesCommand {
	var commands []iptablesCommand

	chainName := tableName + "_INPUT"
	commands = append(commands, iptablesCommand{"iptables", []string{"-N", chainName, "-m", "comment", "--comment", marker}})
	for _, r := range desired.InputRules {
		commands = append(commands, iptablesCommand{"iptables", iptablesRuleArgs(chainName, r, marker)})
	}
	// Jump from INPUT to Higgs chain.
	commands = append(commands, iptablesCommand{"iptables", []string{"-I", "INPUT", "-j", chainName, "-m", "comment", "--comment", marker}})

	fwdChain := tableName + "_FORWARD"
	commands = append(commands, iptablesCommand{"iptables", []string{"-N", fwdChain, "-m", "comment", "--comment", marker}})
	for _, r := range desired.ForwardRules {
		args := append([]string{"-A", fwdChain}, iptablesMatchArgs(r)...)
		args = append(args, "-j", strings.ToUpper(r.Action), "-m", "comment", "--comment", marker+":"+r.Comment)
		commands = append(commands, iptablesCommand{"iptables", args})
	}
	commands = append(commands, iptablesCommand{"iptables", []string{"-I", "FORWARD", "-j", fwdChain, "-m", "comment", "--comment", marker}})

	outChain := tableName + "_OUTPUT"
	commands = append(commands, iptablesCommand{"iptables", []string{"-N", outChain, "-m", "comment", "--comment", marker}})
	for _, r := range desired.OutputRules {
		args := append([]string{"-A", outChain}, iptablesMatchArgs(r)...)
		args = append(args, "-j", strings.ToUpper(r.Action), "-m", "comment", "--comment", marker+":"+r.Comment)
		commands = append(commands, iptablesCommand{"iptables", args})
	}
	commands = append(commands, iptablesCommand{"iptables", []string{"-I", "OUTPUT", "-j", outChain, "-m", "comment", "--comment", marker}})

	return commands
}

func buildIPTablesHostCommands(tableName, marker string, desired *FirewallDesiredState) []iptablesCommand {
	var commands []iptablesCommand

	chainName := tableName + "_INPUT"
	commands = append(commands, iptablesCommand{"iptables", []string{"-N", chainName, "-m", "comment", "--comment", marker}})
	for _, hi := range desired.HostIngress {
		args := []string{"-A", chainName, "-p", iptablesProto(hi.Proto)}
		if hi.Port > 0 {
			args = append(args, "--dport", fmt.Sprintf("%d", hi.Port))
		}
		if hi.DstAddr.IsValid() {
			args = append(args, "-d", hi.DstAddr.String())
		}
		args = append(args, "-j", "ACCEPT", "-m", "comment", "--comment", marker+":"+hi.Comment)
		commands = append(commands, iptablesCommand{"iptables", args})
	}
	commands = append(commands, iptablesCommand{"iptables", []string{"-I", "INPUT", "-j", chainName, "-m", "comment", "--comment", marker}})

	// NAT redirect rules.
	for _, nr := range desired.NatRedirects {
		args := []string{"-t", "nat", "-A", "PREROUTING", "-p", iptablesProto(nr.Proto)}
		if nr.OriginalDst > 0 {
			args = append(args, "--dport", fmt.Sprintf("%d", nr.OriginalDst))
		}
		if nr.DstAddr.IsValid() {
			args = append(args, "-d", nr.DstAddr.String())
		}
		args = append(args, "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", nr.RedirectTo), "-m", "comment", "--comment", marker+":"+nr.Comment)
		commands = append(commands, iptablesCommand{"iptables", args})
	}

	return commands
}

func iptablesRuleArgs(chain string, r Rule, marker string) []string {
	args := []string{"-A", chain}
	args = append(args, iptablesMatchArgs(r)...)
	args = append(args, "-j", strings.ToUpper(r.Action))
	args = append(args, "-m", "comment", "--comment", marker+":"+r.Comment)
	return args
}

func iptablesMatchArgs(r Rule) []string {
	var args []string
	if r.Proto != "" && r.Proto != "icmp" && r.Proto != "ipv6-icmp" {
		args = append(args, "-p", iptablesProto(r.Proto))
	}
	if r.Port > 0 && r.Proto != "icmp" && r.Proto != "ipv6-icmp" {
		args = append(args, "--dport", fmt.Sprintf("%d", r.Port))
	}
	if r.IfaceIn != "" {
		args = append(args, "-i", r.IfaceIn)
	}
	if r.IfaceOut != "" {
		args = append(args, "-o", r.IfaceOut)
	}
	for _, p := range r.Src {
		args = append(args, "-s", p.String())
		break
	}
	for _, p := range r.Dst {
		args = append(args, "-d", p.String())
		break
	}
	return args
}

func iptablesProto(proto string) string {
	switch proto {
	case ProtoICMP:
		return "icmp"
	case ProtoICMPv6:
		return "icmpv6"
	}
	return proto
}

// parseIPTablesChains parses `iptables -S` output to find Higgs-owned chains.
func parseIPTablesChains(output, tableName, table string) []FirewallObjectRef {
	var refs []FirewallObjectRef
	seen := make(map[string]bool)
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		// Lines like "-N higgs_h2_INPUT" or "-A higgs_h2_INPUT ..."
		if !strings.HasPrefix(line, "-N ") && !strings.HasPrefix(line, "-A ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		chainName := fields[1]
		if !strings.HasPrefix(chainName, tableName) {
			continue
		}
		if seen[chainName] {
			continue
		}
		seen[chainName] = true
		refs = append(refs, FirewallObjectRef{
			Kind: "chain", Family: "inet", Name: chainName,
		})
	}
	return refs
}

// Ensure exec import is used.
var _ = exec.LookPath
