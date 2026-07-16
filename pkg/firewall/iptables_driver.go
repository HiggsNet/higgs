package firewall

import (
	"context"
	"fmt"
	"net/netip"
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
			// Flush and delete the chain from both iptables and ip6tables.
			_, _ = d.run(ctx, "iptables", "-F", ref.Name)
			_, _ = d.run(ctx, "iptables", "-X", ref.Name)
			_, _ = d.run(ctx, "ip6tables", "-F", ref.Name)
			_, _ = d.run(ctx, "ip6tables", "-X", ref.Name)
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
			// Delete chain from both iptables and ip6tables.
			commands = append(commands, iptablesCommand{"iptables", []string{"-F", a.Object.Name}})
			commands = append(commands, iptablesCommand{"iptables", []string{"-X", a.Object.Name}})
			commands = append(commands, iptablesCommand{"ip6tables", []string{"-F", a.Object.Name}})
			commands = append(commands, iptablesCommand{"ip6tables", []string{"-X", a.Object.Name}})
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
	// Create INPUT chain for both iptables and ip6tables.
	commands = append(commands, iptablesCommand{"iptables", []string{"-N", chainName}})
	commands = append(commands, iptablesCommand{"ip6tables", []string{"-N", chainName}})

	for _, r := range desired.InputRules {
		commands = append(commands, iptablesRuleCommands(chainName, r, marker)...)
	}
	// Jump from INPUT to Higgs chain.
	commands = append(commands, iptablesCommand{"iptables", []string{"-I", "INPUT", "-j", chainName, "-m", "comment", "--comment", marker}})
	commands = append(commands, iptablesCommand{"ip6tables", []string{"-I", "INPUT", "-j", chainName, "-m", "comment", "--comment", marker}})

	fwdChain := tableName + "_FORWARD"
	// Create FORWARD chain for both iptables and ip6tables.
	commands = append(commands, iptablesCommand{"iptables", []string{"-N", fwdChain}})
	commands = append(commands, iptablesCommand{"ip6tables", []string{"-N", fwdChain}})

	for _, r := range desired.ForwardRules {
		commands = append(commands, iptablesRuleCommands(fwdChain, r, marker)...)
	}
	commands = append(commands, iptablesCommand{"iptables", []string{"-I", "FORWARD", "-j", fwdChain, "-m", "comment", "--comment", marker}})
	commands = append(commands, iptablesCommand{"ip6tables", []string{"-I", "FORWARD", "-j", fwdChain, "-m", "comment", "--comment", marker}})

	outChain := tableName + "_OUTPUT"
	// Create OUTPUT chain for both iptables and ip6tables.
	commands = append(commands, iptablesCommand{"iptables", []string{"-N", outChain}})
	commands = append(commands, iptablesCommand{"ip6tables", []string{"-N", outChain}})

	for _, r := range desired.OutputRules {
		commands = append(commands, iptablesRuleCommands(outChain, r, marker)...)
	}
	commands = append(commands, iptablesCommand{"iptables", []string{"-I", "OUTPUT", "-j", outChain, "-m", "comment", "--comment", marker}})
	commands = append(commands, iptablesCommand{"ip6tables", []string{"-I", "OUTPUT", "-j", outChain, "-m", "comment", "--comment", marker}})

	return commands
}

func buildIPTablesHostCommands(tableName, marker string, desired *FirewallDesiredState) []iptablesCommand {
	var commands []iptablesCommand

	chainName := tableName + "_INPUT"

	// Create INPUT chain for both iptables and ip6tables.
	commands = append(commands, iptablesCommand{"iptables", []string{"-N", chainName}})
	commands = append(commands, iptablesCommand{"ip6tables", []string{"-N", chainName}})

	for _, hi := range desired.HostIngress {
		args := []string{"-A", chainName, "-p", iptablesProto(hi.Proto)}
		if hi.Port > 0 {
			args = append(args, "--dport", fmt.Sprintf("%d", hi.Port))
		}
		if hi.DstAddr.IsValid() {
			args = append(args, "-d", hi.DstAddr.String())
		}
		acceptArgs := append(args, "-j", "ACCEPT", "-m", "comment", "--comment", marker+":"+hi.Comment)

		for _, binary := range iptablesBinariesForAddr(hi.DstAddr) {
			commands = append(commands, iptablesCommand{binary, acceptArgs})
		}
	}

	// Jump from INPUT to Higgs chain.
	commands = append(commands, iptablesCommand{"iptables", []string{"-I", "INPUT", "-j", chainName, "-m", "comment", "--comment", marker}})
	commands = append(commands, iptablesCommand{"ip6tables", []string{"-I", "INPUT", "-j", chainName, "-m", "comment", "--comment", marker}})
	if len(desired.ForwardRules) > 0 {
		forwardChain := tableName + "_FORWARD"
		commands = append(commands, iptablesCommand{"iptables", []string{"-N", forwardChain}})
		commands = append(commands, iptablesCommand{"ip6tables", []string{"-N", forwardChain}})
		for _, rule := range desired.ForwardRules {
			commands = append(commands, iptablesRuleCommands(forwardChain, rule, marker)...)
		}
		commands = append(commands, iptablesCommand{"iptables", []string{"-I", "FORWARD", "-j", forwardChain, "-m", "comment", "--comment", marker}})
		commands = append(commands, iptablesCommand{"ip6tables", []string{"-I", "FORWARD", "-j", forwardChain, "-m", "comment", "--comment", marker}})
	}

	// NAT redirect rules for both IPv4 and IPv6.
	for _, nr := range desired.NatRedirects {
		args := []string{"-t", "nat", "-A", "PREROUTING", "-p", iptablesProto(nr.Proto)}
		if nr.OriginalDst > 0 {
			args = append(args, "--dport", fmt.Sprintf("%d", nr.OriginalDst))
		}
		if nr.DstAddr.IsValid() {
			args = append(args, "-d", nr.DstAddr.String())
		}
		args = append(args, "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", nr.RedirectTo), "-m", "comment", "--comment", marker+":"+nr.Comment)

		for _, binary := range iptablesBinariesForAddr(nr.DstAddr) {
			commands = append(commands, iptablesCommand{binary, args})
		}
	}

	// NAT source port rewrite rules for host-originated charon traffic.
	for _, ns := range desired.NatSources {
		args := []string{"-t", "nat", "-A", "POSTROUTING", "-p", iptablesProto(ns.Proto)}
		if ns.OriginalSrc > 0 {
			args = append(args, "--sport", fmt.Sprintf("%d", ns.OriginalSrc))
		}
		if ns.DstPort > 0 {
			args = append(args, "--dport", fmt.Sprintf("%d", ns.DstPort))
		}
		if ns.DstAddr.IsValid() {
			args = append(args, "-d", ns.DstAddr.String())
		}
		args = append(args, "-j", "MASQUERADE", "--to-ports", fmt.Sprintf("%d", ns.RewriteTo), "-m", "comment", "--comment", marker+":"+ns.Comment)

		for _, binary := range iptablesBinariesForAddr(ns.DstAddr) {
			commands = append(commands, iptablesCommand{binary, args})
		}
	}

	return commands
}

func iptablesRuleCommands(chain string, r Rule, marker string) []iptablesCommand {
	var commands []iptablesCommand
	for _, match := range iptablesMatchArgSets(r) {
		args := append([]string{"-A", chain}, match...)
		args = append(args, "-j", strings.ToUpper(r.Action))
		args = append(args, "-m", "comment", "--comment", marker+":"+r.Comment)

		// Determine if this rule is for IPv4, IPv6, or both.
		// If the rule contains ICMPv6 protocol, it's IPv6-only.
		// Otherwise, check source/destination addresses.
		binary := selectIPTablesBinaryForMatch(r, match)

		commands = append(commands, iptablesCommand{binary, args})
	}
	return commands
}

// selectIPTablesBinaryForMatch determines whether to use iptables or ip6tables
// based on the rule protocol and address match parameters.
func selectIPTablesBinaryForMatch(r Rule, match []string) string {
	// If the rule explicitly specifies ICMPv6, use ip6tables.
	if r.Proto == ProtoICMPv6 || r.Proto == "ipv6-icmp" {
		return "ip6tables"
	}

	// Check source/destination addresses in match args.
	for i := 0; i < len(match)-1; i++ {
		if match[i] == "-s" || match[i] == "-d" {
			addr := match[i+1]
			if ip, err := netip.ParseAddr(addr); err == nil {
				if ip.Is6() {
					return "ip6tables"
				}
			}
			// If it's a prefix, check the address.
			if prefix, err := netip.ParsePrefix(addr); err == nil {
				if prefix.Addr().Is6() {
					return "ip6tables"
				}
			}
		}
	}

	// Default to iptables for IPv4 or dual-stack (inet semantics).
	return "iptables"
}

func iptablesBinariesForAddr(addr netip.Addr) []string {
	if !addr.IsValid() {
		return []string{"iptables", "ip6tables"}
	}
	if addr.Is6() {
		return []string{"ip6tables"}
	}
	return []string{"iptables"}
}

func iptablesMatchArgSets(r Rule) [][]string {
	base := iptablesBaseMatchArgs(r)
	srcs := r.Src
	dsts := r.Dst
	if len(srcs) == 0 {
		srcs = []netip.Prefix{netip.Prefix{}}
	}
	if len(dsts) == 0 {
		dsts = []netip.Prefix{netip.Prefix{}}
	}

	var out [][]string
	for _, src := range srcs {
		for _, dst := range dsts {
			args := append([]string{}, base...)
			if src.IsValid() {
				args = append(args, "-s", src.String())
			}
			if dst.IsValid() {
				args = append(args, "-d", dst.String())
			}
			out = append(out, args)
		}
	}
	return out
}

func iptablesBaseMatchArgs(r Rule) []string {
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
