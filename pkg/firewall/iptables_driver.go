package firewall

import (
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"sort"
	"strconv"
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
	// Migrate rules written directly into built-in NAT chains by older
	// versions. Dedicated managed chains below replace this layout.
	legacyApplied, legacyErrs := d.deleteLegacyNATBaseRules(ctx, iptablesOwnerMarker(desired))
	result.Applied += legacyApplied
	commands := buildIPTablesApplyCommands(plan, desired)
	errs := append([]string(nil), legacyErrs...)
	for _, cmd := range commands {
		binary := cmd.binary
		args := cmd.args
		if len(cmd.skipIfSucceeds) > 0 {
			if _, err := d.run(ctx, binary, cmd.skipIfSucceeds...); err == nil {
				// Object/rule already present; nothing to do.
				continue
			}
		}
		if len(cmd.skipUnlessSucceeds) > 0 {
			if _, err := d.run(ctx, binary, cmd.skipUnlessSucceeds...); err != nil {
				continue
			}
		}
		if cmd.repeatUntilFail {
			// Drain (possibly duplicated) references; the final failure just
			// means "no more references" and is expected.
			for i := 0; i < 8; i++ {
				if _, err := d.run(ctx, binary, args...); err != nil {
					break
				}
				result.Applied++
			}
			continue
		}
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

func iptablesOwnerMarker(desired *FirewallDesiredState) string {
	scope := desired.Instance.NetNS
	if desired.Instance.IsHost {
		scope = "host"
	}
	return "higgs-" + scope
}

func (d *IPTablesDriver) deleteLegacyNATBaseRules(ctx context.Context, marker string) (int, []string) {
	applied := 0
	var errs []string
	for _, binary := range []string{"iptables", "ip6tables"} {
		for _, chain := range []string{"PREROUTING", "POSTROUTING"} {
			out, err := d.run(ctx, binary, "-t", "nat", "-L", chain, "--line-numbers", "-n")
			if err != nil {
				// Some installations do not expose IPv6 NAT. Lack of a list
				// result cannot imply that a legacy rule exists.
				continue
			}
			for _, number := range legacyNATRuleNumbers(string(out), marker) {
				if _, err := d.run(ctx, binary, "-t", "nat", "-D", chain, strconv.Itoa(number)); err != nil {
					errs = append(errs, fmt.Sprintf("%s delete legacy nat %s rule %d: %v", binary, chain, number, err))
					continue
				}
				applied++
			}
		}
	}
	return applied, errs
}

func legacyNATRuleNumbers(output, marker string) []int {
	var numbers []int
	for _, line := range strings.Split(output, "\n") {
		if !strings.Contains(line, marker+":") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		number, err := strconv.Atoi(fields[0])
		if err == nil {
			numbers = append(numbers, number)
		}
	}
	sort.Sort(sort.Reverse(sort.IntSlice(numbers)))
	return numbers
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

	state.Objects = dedupFirewallObjectRefs(state.Objects)
	// Always report the synthetic table ref if any owned objects exist.
	if len(state.Objects) > 0 {
		state.Objects = append([]FirewallObjectRef{{Kind: "table", Family: "inet", Name: tableName}}, state.Objects...)
	}
	return state, nil
}

func (d *IPTablesDriver) DeleteStale(ctx context.Context, refs []FirewallObjectRef) error {
	for _, ref := range refs {
		table, builtin, ok := iptablesObjectLocation(ref)
		if !ok {
			continue
		}
		for _, binary := range []string{"iptables", "ip6tables"} {
			for i := 0; i < 8; i++ {
				if _, err := d.run(ctx, binary, iptablesArgs(table, "-D", builtin, "-j", ref.Name)...); err != nil {
					break
				}
			}
			if _, err := d.run(ctx, binary, iptablesArgs(table, "-S", ref.Name)...); err != nil {
				continue
			}
			_, _ = d.run(ctx, binary, iptablesArgs(table, "-F", ref.Name)...)
			_, _ = d.run(ctx, binary, iptablesArgs(table, "-X", ref.Name)...)
		}
	}
	return nil
}

// iptablesCommand represents a single iptables/ip6tables invocation.
type iptablesCommand struct {
	binary string
	args   []string
	// skipIfSucceeds, when set, is run first with the same binary; if it
	// exits 0 the main command is skipped (idempotent create/insert).
	skipIfSucceeds []string
	// skipUnlessSucceeds, when set, is run first with the same binary; if it
	// fails the main command is skipped (conditional cleanup).
	skipUnlessSucceeds []string
	// repeatUntilFail runs the command until it fails (bounded); the final
	// failure is expected and tolerated. Used to drain duplicate references.
	repeatUntilFail bool
}

// buildIPTablesApplyCommands generates sequential iptables commands.
//
// The apply model is an idempotent full rebuild: managed chains are created
// when missing, flushed, and refilled from desired state on every apply, and
// jumps from built-in chains are inserted once (guarded by -C checks). This
// keeps the backend convergent across reconciles without tracking per-rule
// diffs, mirroring the nft backend's delete-and-recreate semantics.
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
	marker := iptablesOwnerMarker(desired)

	var commands []iptablesCommand

	// Delete stale chains (e.g. legacy uppercase chains from older naming):
	// drain references from built-in chains first so -X can succeed, then
	// flush and delete.
	for _, a := range plan.Actions {
		if a.Action != "delete" {
			continue
		}
		table, builtin, ok := iptablesObjectLocation(a.Object)
		if !ok {
			continue
		}
		for _, binary := range []string{"iptables", "ip6tables"} {
			commands = append(commands, iptablesCommand{
				binary:          binary,
				args:            iptablesArgs(table, "-D", builtin, "-j", a.Object.Name, "-m", "comment", "--comment", marker),
				repeatUntilFail: true,
			})
			exists := iptablesArgs(table, "-S", a.Object.Name)
			commands = append(commands, iptablesCommand{
				binary: binary, args: iptablesArgs(table, "-F", a.Object.Name),
				skipUnlessSucceeds: exists,
			})
			commands = append(commands, iptablesCommand{
				binary: binary, args: iptablesArgs(table, "-X", a.Object.Name),
				skipUnlessSucceeds: exists,
			})
		}
	}

	if desired.Instance.IsHost {
		commands = append(commands, buildIPTablesHostCommands(tableName, marker, desired)...)
	} else {
		commands = append(commands, buildIPTablesOverlayCommands(tableName, marker, desired)...)
	}

	return commands
}

// jumpOnce inserts a jump from a built-in chain to a Higgs chain, guarded by
// a -C check so the jump is only inserted once. table may be "" (filter).
func jumpOnce(binary, table, builtin, chain, marker string) iptablesCommand {
	full := func(op string) []string {
		var args []string
		if table != "" {
			args = append(args, "-t", table)
		}
		return append(args, op, builtin, "-j", chain, "-m", "comment", "--comment", marker)
	}
	return iptablesCommand{binary: binary, args: full("-I"), skipIfSucceeds: full("-C")}
}

// ensureChain creates a chain when missing, then flushes it for refill.
// table may be "" (filter).
func ensureChain(binary, table, chain string) []iptablesCommand {
	full := func(op string) []string {
		var args []string
		if table != "" {
			args = append(args, "-t", table)
		}
		return append(args, op, chain)
	}
	return []iptablesCommand{
		{binary: binary, args: full("-N"), skipIfSucceeds: full("-S")},
		{binary: binary, args: full("-F")},
	}
}

func buildIPTablesOverlayCommands(tableName, marker string, desired *FirewallDesiredState) []iptablesCommand {
	var commands []iptablesCommand
	binaries := []string{"iptables", "ip6tables"}

	// Hook jump-target chains are admin-owned: create them when missing so
	// jump rules never reference a missing chain, but never flush them.
	for _, target := range jumpTargets(desired) {
		for _, binary := range binaries {
			commands = append(commands, iptablesCommand{binary: binary, args: []string{"-N", target}, skipIfSucceeds: []string{"-S", target}})
		}
	}

	chains := []struct {
		name    string
		builtin string
		rules   []Rule
	}{
		{tableName + "_input", "INPUT", desired.InputRules},
		{tableName + "_forward", "FORWARD", desired.ForwardRules},
		{tableName + "_output", "OUTPUT", desired.OutputRules},
	}
	for _, c := range chains {
		for _, binary := range binaries {
			commands = append(commands, ensureChain(binary, "", c.name)...)
		}
		for _, r := range c.rules {
			commands = append(commands, iptablesRuleCommands(c.name, r, marker)...)
		}
		for _, binary := range binaries {
			commands = append(commands, jumpOnce(binary, "", c.builtin, c.name, marker))
		}
	}

	return commands
}

func buildIPTablesHostCommands(tableName, marker string, desired *FirewallDesiredState) []iptablesCommand {
	var commands []iptablesCommand
	binaries := []string{"iptables", "ip6tables"}

	inputChain := tableName + "_input"
	for _, binary := range binaries {
		commands = append(commands, ensureChain(binary, "", inputChain)...)
	}

	for _, hi := range desired.HostIngress {
		args := []string{"-A", inputChain, "-p", iptablesProto(hi.Proto)}
		if hi.Port > 0 {
			args = append(args, "--dport", fmt.Sprintf("%d", hi.Port))
		}
		if hi.DstAddr.IsValid() {
			args = append(args, "-d", hi.DstAddr.String())
		}
		acceptArgs := append(args, "-j", "ACCEPT", "-m", "comment", "--comment", marker+":"+hi.Comment)

		for _, binary := range iptablesBinariesForAddr(hi.DstAddr) {
			commands = append(commands, iptablesCommand{binary: binary, args: acceptArgs})
		}
	}

	for _, binary := range binaries {
		commands = append(commands, jumpOnce(binary, "", "INPUT", inputChain, marker))
	}

	if len(desired.ForwardRules) > 0 {
		forwardChain := tableName + "_forward"
		for _, binary := range binaries {
			commands = append(commands, ensureChain(binary, "", forwardChain)...)
		}
		for _, rule := range desired.ForwardRules {
			commands = append(commands, iptablesRuleCommands(forwardChain, rule, marker)...)
		}
		for _, binary := range binaries {
			commands = append(commands, jumpOnce(binary, "", "FORWARD", forwardChain, marker))
		}
	}

	// NAT redirect rules live in a dedicated nat prerouting chain so each
	// apply can flush and refill them idempotently.
	if len(desired.NatRedirects) > 0 {
		preChain := tableName + "_prerouting"
		for _, binary := range binaries {
			commands = append(commands, ensureChain(binary, "nat", preChain)...)
		}
		for _, nr := range desired.NatRedirects {
			args := []string{"-t", "nat", "-A", preChain, "-p", iptablesProto(nr.Proto)}
			if nr.OriginalDst > 0 {
				args = append(args, "--dport", fmt.Sprintf("%d", nr.OriginalDst))
			}
			if nr.DstAddr.IsValid() {
				args = append(args, "-d", nr.DstAddr.String())
			}
			args = append(args, "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", nr.RedirectTo), "-m", "comment", "--comment", marker+":"+nr.Comment)

			for _, binary := range iptablesBinariesForAddr(nr.DstAddr) {
				commands = append(commands, iptablesCommand{binary: binary, args: args})
			}
		}
		for _, binary := range binaries {
			commands = append(commands, jumpOnce(binary, "nat", "PREROUTING", preChain, marker))
		}
	}

	// NAT source port rewrite rules for host-originated charon traffic.
	if len(desired.NatSources) > 0 {
		postChain := tableName + "_postrouting"
		for _, binary := range binaries {
			commands = append(commands, ensureChain(binary, "nat", postChain)...)
		}
		for _, ns := range desired.NatSources {
			args := []string{"-t", "nat", "-A", postChain, "-p", iptablesProto(ns.Proto)}
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
				commands = append(commands, iptablesCommand{binary: binary, args: args})
			}
		}
		for _, binary := range binaries {
			commands = append(commands, jumpOnce(binary, "nat", "POSTROUTING", postChain, marker))
		}
	}

	return commands
}

func iptablesRuleCommands(chain string, r Rule, marker string) []iptablesCommand {
	var commands []iptablesCommand
	for _, match := range iptablesMatchArgSets(r) {
		args := append([]string{"-A", chain}, match...)
		if r.Action == ActionJump {
			args = append(args, "-j", r.JumpTarget)
		} else {
			args = append(args, "-j", strings.ToUpper(r.Action))
		}
		args = append(args, "-m", "comment", "--comment", marker+":"+r.Comment)

		// Determine if this rule is for IPv4, IPv6, or both.
		// If the rule contains ICMPv6 protocol, it's IPv6-only.
		// Otherwise, check source/destination addresses.
		binary := selectIPTablesBinaryForMatch(r, match)
		binaries := []string{binary}
		// Rules without any address-family-specific match (no icmp/icmpv6
		// protocol, no v4/v6 prefixes) apply to both families; install them
		// for both iptables and ip6tables.
		if (r.Proto == "" || r.Proto == ProtoTCP || r.Proto == ProtoUDP) && len(r.Src) == 0 && len(r.Dst) == 0 {
			binaries = []string{"iptables", "ip6tables"}
		}
		for _, bin := range binaries {
			commands = append(commands, iptablesCommand{binary: bin, args: args})
		}
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
			if src.IsValid() && dst.IsValid() && src.Addr().Is4() != dst.Addr().Is4() {
				// A single iptables/ip6tables rule cannot mix address
				// families. Such a pair can never match and is invalid CLI.
				continue
			}
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
	if r.Proto != "" {
		args = append(args, "-p", iptablesProto(r.Proto))
	}
	if r.Port > 0 && r.Proto != "icmp" && r.Proto != "ipv6-icmp" {
		args = append(args, "--dport", fmt.Sprintf("%d", r.Port))
	}
	if r.IfaceIn != "" {
		args = append(args, "-i", iptablesIfacePattern(r.IfaceIn))
	}
	if r.IfaceOut != "" {
		args = append(args, "-o", iptablesIfacePattern(r.IfaceOut))
	}
	if len(r.CtStates) > 0 {
		args = append(args, "-m", "conntrack", "--ctstate", strings.ToUpper(strings.Join(r.CtStates, ",")))
	}
	return args
}

func iptablesIfacePattern(pattern string) string {
	// nft uses shell-style trailing '*', while xtables expresses an interface
	// prefix wildcard with trailing '+'.
	if strings.HasSuffix(pattern, "*") && strings.Count(pattern, "*") == 1 {
		return strings.TrimSuffix(pattern, "*") + "+"
	}
	return pattern
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

// parseIPTablesChains parses `iptables -S` output and returns only exact
// Higgs-managed chain names. Prefix matching is intentionally insufficient:
// administrator-owned hook chains commonly share the instance prefix.
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
		ref, ok := managedIPTablesObject(tableName, table, chainName)
		if !ok {
			continue
		}
		if seen[chainName] {
			continue
		}
		seen[chainName] = true
		refs = append(refs, ref)
	}
	return refs
}

func managedIPTablesObject(tableName, table, chainName string) (FirewallObjectRef, bool) {
	kind := ""
	switch table {
	case "", "filter":
		switch chainName {
		case tableName + "_input", tableName + "_forward", tableName + "_output",
			tableName + "_INPUT", tableName + "_FORWARD", tableName + "_OUTPUT":
			kind = "chain"
		}
	case "nat":
		switch chainName {
		case tableName + "_prerouting":
			kind = "nat_redirect"
		case tableName + "_postrouting":
			kind = "nat_source"
		}
	}
	if kind == "" {
		return FirewallObjectRef{}, false
	}
	return FirewallObjectRef{Kind: kind, Family: "inet", Name: chainName}, true
}

func dedupFirewallObjectRefs(refs []FirewallObjectRef) []FirewallObjectRef {
	seen := make(map[string]bool, len(refs))
	out := make([]FirewallObjectRef, 0, len(refs))
	for _, ref := range refs {
		key := objKey(ref)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, ref)
	}
	sort.Slice(out, func(i, j int) bool {
		return objKey(out[i]) < objKey(out[j])
	})
	return out
}

func iptablesObjectLocation(ref FirewallObjectRef) (table, builtin string, ok bool) {
	switch ref.Kind {
	case "chain":
		lower := strings.ToLower(ref.Name)
		switch {
		case strings.HasSuffix(lower, "_input"):
			return "", "INPUT", true
		case strings.HasSuffix(lower, "_forward"):
			return "", "FORWARD", true
		case strings.HasSuffix(lower, "_output"):
			return "", "OUTPUT", true
		}
	case "nat_redirect":
		return "nat", "PREROUTING", true
	case "nat_source":
		return "nat", "POSTROUTING", true
	}
	return "", "", false
}

func iptablesArgs(table string, args ...string) []string {
	if table == "" {
		return append([]string(nil), args...)
	}
	out := []string{"-t", table}
	return append(out, args...)
}

// Ensure exec import is used.
var _ = exec.LookPath
