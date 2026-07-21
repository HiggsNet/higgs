package firewall

import (
	"context"
	"fmt"
	"net/netip"
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
//   - Apply populates an inactive generation chain before switching the
//     built-in-chain jump, so preparation failures keep the old policy active.
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
	_ = plan // generation-chain apply converges from the live kernel state.

	marker := iptablesOwnerMarker(desired)
	tableName := iptablesTableName(desired)
	hash := DesiredStateHash(desired)
	specs := buildIPTablesManagedChainSpecs(desired, marker)
	var prepared []preparedIPTablesChain

	// Admin hook targets must exist before staging rules that jump to them.
	// They are never flushed or otherwise treated as Higgs-owned policy.
	for _, target := range jumpTargets(desired) {
		for _, binary := range []string{"iptables", "ip6tables"} {
			if _, err := d.run(ctx, binary, "-S", target); err == nil {
				continue
			}
			if _, err := d.run(ctx, binary, "-N", target); err != nil {
				return iptablesApplyFailure(result, fmt.Sprintf("%s create hook target %s: %v", binary, target, err))
			}
			result.Applied++
		}
	}

	// Build every inactive generation chain completely before changing a
	// built-in-chain jump. A preparation error leaves the active generation
	// untouched and therefore cannot create a fail-open window.
	for _, spec := range specs {
		for _, binary := range []string{"iptables", "ip6tables"} {
			item, applied, err := d.prepareIPTablesGeneration(ctx, binary, tableName, marker, hash, spec)
			result.Applied += applied
			if err != nil {
				d.discardPreparedIPTablesChains(ctx, append(prepared, item))
				return iptablesApplyFailure(result, err.Error())
			}
			prepared = append(prepared, item)
		}
	}

	// Cut over only after all IPv4 and IPv6 staging chains are complete. New
	// jumps are inserted before old jumps, so a cutover failure leaves at
	// least the old policy (and possibly the new policy) active.
	for i := range prepared {
		item := &prepared[i]
		args := iptablesArgs(item.spec.table, "-I", item.spec.builtin, "-j", item.generation, "-m", "comment", "--comment", marker)
		if _, err := d.run(ctx, item.binary, args...); err != nil {
			return iptablesApplyFailure(result, fmt.Sprintf("%s activate %s: %v", item.binary, item.generation, err))
		}
		item.activated = true
		result.Applied++
	}

	active := make(map[string]bool, len(prepared))
	for _, item := range prepared {
		active[iptablesChainKey(item.binary, item.spec.table, item.generation)] = true
	}
	cleaned, cleanupErrs := d.cleanupOldIPTablesGenerations(ctx, tableName, marker, active)
	result.Applied += cleaned

	// Migrate rules written directly into built-in NAT chains only after the
	// replacement NAT generation is active.
	legacyApplied, legacyErrs := d.deleteLegacyNATBaseRules(ctx, marker)
	result.Applied += legacyApplied
	cleanupErrs = append(cleanupErrs, legacyErrs...)
	if len(cleanupErrs) > 0 {
		result.Failed += len(cleanupErrs)
		result.Errors = cleanupErrs
		result.Generation = 1
		return result, fmt.Errorf("iptables apply cleanup had %d errors", len(cleanupErrs))
	}
	result.Generation = 1
	return result, nil
}

type iptablesManagedChainSpec struct {
	table     string
	builtin   string
	canonical string
	code      string
	rules     func(chain string) []iptablesCommand
}

type preparedIPTablesChain struct {
	binary     string
	spec       iptablesManagedChainSpec
	generation string
	activated  bool
}

func iptablesApplyFailure(result FirewallApplyResult, message string) (FirewallApplyResult, error) {
	result.Failed++
	result.Errors = append(result.Errors, message)
	result.Generation = 1
	return result, fmt.Errorf("iptables apply failed: %s", message)
}

func iptablesTableName(desired *FirewallDesiredState) string {
	prefix := desired.Instance.OwnerPrefix
	if prefix == "" {
		prefix = "higgs"
	}
	scope := desired.Instance.NetNS
	if desired.Instance.IsHost {
		scope = "host"
	}
	return prefix + "_" + scope
}

func buildIPTablesManagedChainSpecs(desired *FirewallDesiredState, marker string) []iptablesManagedChainSpec {
	if desired.Instance.Mode == ModeDisabled {
		return nil
	}
	tableName := iptablesTableName(desired)
	ruleBuilder := func(rules []Rule) func(string) []iptablesCommand {
		return func(chain string) []iptablesCommand {
			var commands []iptablesCommand
			for _, rule := range rules {
				commands = append(commands, iptablesRuleCommands(chain, rule, marker)...)
			}
			return commands
		}
	}

	if !desired.Instance.IsHost {
		return []iptablesManagedChainSpec{
			{builtin: "INPUT", canonical: tableName + "_input", code: "i", rules: ruleBuilder(desired.InputRules)},
			{builtin: "FORWARD", canonical: tableName + "_forward", code: "f", rules: ruleBuilder(desired.ForwardRules)},
			{builtin: "OUTPUT", canonical: tableName + "_output", code: "o", rules: ruleBuilder(desired.OutputRules)},
		}
	}

	inputRules := func(chain string) []iptablesCommand {
		var commands []iptablesCommand
		for _, hi := range desired.HostIngress {
			args := []string{"-A", chain, "-p", iptablesProto(hi.Proto)}
			if hi.Port > 0 {
				args = append(args, "--dport", fmt.Sprintf("%d", hi.Port))
			}
			if hi.DstAddr.IsValid() {
				args = append(args, "-d", hi.DstAddr.String())
			}
			args = append(args, "-j", "ACCEPT", "-m", "comment", "--comment", marker+":"+hi.Comment)
			for _, binary := range iptablesBinariesForAddr(hi.DstAddr) {
				commands = append(commands, iptablesCommand{binary: binary, args: args})
			}
		}
		return commands
	}
	specs := []iptablesManagedChainSpec{
		{builtin: "INPUT", canonical: tableName + "_input", code: "i", rules: inputRules},
	}
	if len(desired.ForwardRules) > 0 {
		specs = append(specs, iptablesManagedChainSpec{
			builtin: "FORWARD", canonical: tableName + "_forward", code: "f", rules: ruleBuilder(desired.ForwardRules),
		})
	}
	if len(desired.NatRedirects) > 0 {
		specs = append(specs, iptablesManagedChainSpec{
			table: "nat", builtin: "PREROUTING", canonical: tableName + "_prerouting", code: "r",
			rules: func(chain string) []iptablesCommand {
				var commands []iptablesCommand
				for _, nr := range desired.NatRedirects {
					args := []string{"-t", "nat", "-A", chain, "-p", iptablesProto(nr.Proto)}
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
				return commands
			},
		})
	}
	if len(desired.NatSources) > 0 {
		specs = append(specs, iptablesManagedChainSpec{
			table: "nat", builtin: "POSTROUTING", canonical: tableName + "_postrouting", code: "s",
			rules: func(chain string) []iptablesCommand {
				var commands []iptablesCommand
				for _, ns := range desired.NatSources {
					args := []string{"-t", "nat", "-A", chain, "-p", iptablesProto(ns.Proto)}
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
				return commands
			},
		})
	}
	return specs
}

func iptablesGenerationChain(tableName, code, hash string, slot byte) string {
	const generationHashLength = 12
	if len(hash) > generationHashLength {
		hash = hash[:generationHashLength]
	}
	suffix := "_" + code + "_" + hash + string(slot)
	const maxChainName = 28
	prefixLen := maxChainName - len(suffix)
	if prefixLen < 1 {
		prefixLen = 1
	}
	prefix := tableName
	if len(prefix) > prefixLen {
		prefix = prefix[:prefixLen]
	}
	return prefix + suffix
}

func (d *IPTablesDriver) prepareIPTablesGeneration(
	ctx context.Context,
	binary, tableName, marker, hash string,
	spec iptablesManagedChainSpec,
) (preparedIPTablesChain, int, error) {
	a := iptablesGenerationChain(tableName, spec.code, hash, 'a')
	b := iptablesGenerationChain(tableName, spec.code, hash, 'b')
	aActive := d.iptablesJumpExists(ctx, binary, spec.table, spec.builtin, a, marker)
	bActive := d.iptablesJumpExists(ctx, binary, spec.table, spec.builtin, b, marker)
	if aActive && bActive {
		// Both slots represent the same desired hash. Keep a active while b is
		// rebuilt, then normal cleanup removes the duplicate a jump.
		if _, err := d.run(ctx, binary, iptablesArgs(spec.table, "-D", spec.builtin, "-j", b, "-m", "comment", "--comment", marker)...); err != nil {
			return preparedIPTablesChain{}, 0, fmt.Errorf("%s remove duplicate active slot %s: %w", binary, b, err)
		}
		bActive = false
	}
	generation := a
	if aActive {
		generation = b
	} else if bActive {
		generation = a
	}
	item := preparedIPTablesChain{binary: binary, spec: spec, generation: generation}
	applied := 0

	existsArgs := iptablesArgs(spec.table, "-S", generation)
	if _, err := d.run(ctx, binary, existsArgs...); err == nil {
		if _, err := d.run(ctx, binary, iptablesArgs(spec.table, "-F", generation)...); err != nil {
			return item, applied, fmt.Errorf("%s flush inactive generation %s: %w", binary, generation, err)
		}
		applied++
	} else {
		if _, err := d.run(ctx, binary, iptablesArgs(spec.table, "-N", generation)...); err != nil {
			return item, applied, fmt.Errorf("%s create generation %s: %w", binary, generation, err)
		}
		applied++
	}

	for _, command := range spec.rules(generation) {
		if command.binary != binary {
			continue
		}
		if _, err := d.run(ctx, binary, command.args...); err != nil {
			return item, applied, fmt.Errorf("%s populate generation %s: %w", binary, generation, err)
		}
		applied++
	}
	return item, applied, nil
}

func (d *IPTablesDriver) iptablesJumpExists(ctx context.Context, binary, table, builtin, target, marker string) bool {
	_, err := d.run(ctx, binary, iptablesArgs(table, "-C", builtin, "-j", target, "-m", "comment", "--comment", marker)...)
	return err == nil
}

func (d *IPTablesDriver) discardPreparedIPTablesChains(ctx context.Context, prepared []preparedIPTablesChain) {
	for _, item := range prepared {
		if item.activated {
			continue
		}
		_, _ = d.run(ctx, item.binary, iptablesArgs(item.spec.table, "-F", item.generation)...)
		_, _ = d.run(ctx, item.binary, iptablesArgs(item.spec.table, "-X", item.generation)...)
	}
}

func iptablesChainKey(binary, table, chain string) string {
	if table == "" {
		table = "filter"
	}
	return binary + ":" + table + ":" + chain
}

func (d *IPTablesDriver) cleanupOldIPTablesGenerations(
	ctx context.Context,
	tableName, marker string,
	active map[string]bool,
) (int, []string) {
	applied := 0
	var errs []string
	for _, binary := range []string{"iptables", "ip6tables"} {
		for _, table := range []string{"", "nat"} {
			out, err := d.run(ctx, binary, iptablesArgs(table, "-S")...)
			if err != nil {
				errs = append(errs, fmt.Sprintf("%s list %s table for cleanup: %v", binary, iptablesTableLabel(table), err))
				continue
			}
			for _, chain := range parseManagedIPTablesActualChains(string(out), tableName, table) {
				if active[iptablesChainKey(binary, table, chain.name)] {
					continue
				}
				deleteArgs := iptablesArgs(table, "-D", chain.builtin, "-j", chain.name, "-m", "comment", "--comment", marker)
				for attempts := 0; attempts < 4096; attempts++ {
					if _, err := d.run(ctx, binary, deleteArgs...); err != nil {
						break
					}
					applied++
				}
				if d.iptablesJumpExists(ctx, binary, table, chain.builtin, chain.name, marker) {
					errs = append(errs, fmt.Sprintf("%s too many references to stale chain %s", binary, chain.name))
					continue
				}
				after, err := d.run(ctx, binary, iptablesArgs(table, "-S")...)
				if err != nil {
					errs = append(errs, fmt.Sprintf("%s verify references to stale chain %s: %v", binary, chain.name, err))
					continue
				}
				if iptablesChainReferenced(string(after), chain.name) {
					errs = append(errs, fmt.Sprintf("%s stale chain %s still has non-Higgs references", binary, chain.name))
					continue
				}
				if _, err := d.run(ctx, binary, iptablesArgs(table, "-F", chain.name)...); err != nil {
					errs = append(errs, fmt.Sprintf("%s flush stale chain %s: %v", binary, chain.name, err))
					continue
				}
				applied++
				if _, err := d.run(ctx, binary, iptablesArgs(table, "-X", chain.name)...); err != nil {
					errs = append(errs, fmt.Sprintf("%s delete stale chain %s: %v", binary, chain.name, err))
					continue
				}
				applied++
			}
		}
	}
	return applied, errs
}

func iptablesTableLabel(table string) string {
	if table == "" {
		return "filter"
	}
	return table
}

type managedIPTablesActualChain struct {
	name    string
	builtin string
}

func parseManagedIPTablesActualChains(output, tableName, table string) []managedIPTablesActualChain {
	seen := make(map[string]bool)
	var chains []managedIPTablesActualChain
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) != 2 || fields[0] != "-N" {
			continue
		}
		name := fields[1]
		_, builtin, ok := managedIPTablesChainIdentity(tableName, table, name)
		if !ok || seen[name] {
			continue
		}
		seen[name] = true
		chains = append(chains, managedIPTablesActualChain{name: name, builtin: builtin})
	}
	sort.Slice(chains, func(i, j int) bool { return chains[i].name < chains[j].name })
	return chains
}

func iptablesChainReferenced(output, target string) bool {
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		for i := 0; i+1 < len(fields); i++ {
			if fields[i] == "-j" && fields[i+1] == target {
				return true
			}
		}
	}
	return false
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
	wanted := make(map[string]map[string]bool)
	for _, ref := range refs {
		tableName, ok := iptablesObjectTableName(ref)
		if !ok {
			continue
		}
		if wanted[tableName] == nil {
			wanted[tableName] = make(map[string]bool)
		}
		wanted[tableName][objKey(ref)] = true
	}
	var errs []string
	for tableName, keys := range wanted {
		for _, binary := range []string{"iptables", "ip6tables"} {
			for _, table := range []string{"", "nat"} {
				out, err := d.run(ctx, binary, iptablesArgs(table, "-S")...)
				if err != nil {
					errs = append(errs, fmt.Sprintf("%s list %s table: %v", binary, iptablesTableLabel(table), err))
					continue
				}
				for _, chain := range parseManagedIPTablesActualChains(string(out), tableName, table) {
					ref, _, ok := managedIPTablesChainIdentity(tableName, table, chain.name)
					if !ok {
						continue
					}
					if !keys[objKey(ref)] && !keys[objKey(FirewallObjectRef{Kind: ref.Kind, Family: "inet", Name: chain.name})] {
						continue
					}
					for _, args := range matchingIPTablesJumpDeletes(string(out), chain.builtin, chain.name) {
						if _, err := d.run(ctx, binary, iptablesArgs(table, args...)...); err != nil {
							errs = append(errs, fmt.Sprintf("%s remove jump to %s: %v", binary, chain.name, err))
						}
					}
					if _, err := d.run(ctx, binary, iptablesArgs(table, "-F", chain.name)...); err != nil {
						errs = append(errs, fmt.Sprintf("%s flush %s: %v", binary, chain.name, err))
						continue
					}
					if _, err := d.run(ctx, binary, iptablesArgs(table, "-X", chain.name)...); err != nil {
						errs = append(errs, fmt.Sprintf("%s delete %s: %v", binary, chain.name, err))
					}
				}
			}
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("iptables stale cleanup: %s", strings.Join(errs, "; "))
	}
	return nil
}

func iptablesObjectTableName(ref FirewallObjectRef) (string, bool) {
	suffixes := []string{"_prerouting", "_postrouting", "_forward", "_output", "_input"}
	lower := strings.ToLower(ref.Name)
	for _, suffix := range suffixes {
		if strings.HasSuffix(lower, suffix) {
			return ref.Name[:len(ref.Name)-len(suffix)], true
		}
	}
	return "", false
}

func matchingIPTablesJumpDeletes(output, builtin, target string) [][]string {
	var deletes [][]string
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 4 || fields[0] != "-A" || fields[1] != builtin {
			continue
		}
		matches := false
		for i := 2; i+1 < len(fields); i++ {
			if fields[i] == "-j" && fields[i+1] == target {
				matches = true
				break
			}
		}
		if !matches {
			continue
		}
		fields[0] = "-D"
		deletes = append(deletes, fields)
	}
	return deletes
}

// iptablesCommand represents a single iptables/ip6tables invocation.
type iptablesCommand struct {
	binary string
	args   []string
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
	ref, _, ok := managedIPTablesChainIdentity(tableName, table, chainName)
	if !ok {
		return FirewallObjectRef{}, false
	}
	return ref, true
}

func managedIPTablesChainIdentity(tableName, table, chainName string) (FirewallObjectRef, string, bool) {
	type identity struct {
		code      string
		kind      string
		suffix    string
		builtin   string
		legacyCap string
	}
	var identities []identity
	switch table {
	case "", "filter":
		identities = []identity{
			{code: "i", kind: "chain", suffix: "_input", builtin: "INPUT", legacyCap: "_INPUT"},
			{code: "f", kind: "chain", suffix: "_forward", builtin: "FORWARD", legacyCap: "_FORWARD"},
			{code: "o", kind: "chain", suffix: "_output", builtin: "OUTPUT", legacyCap: "_OUTPUT"},
		}
	case "nat":
		identities = []identity{
			{code: "r", kind: "nat_redirect", suffix: "_prerouting", builtin: "PREROUTING"},
			{code: "s", kind: "nat_source", suffix: "_postrouting", builtin: "POSTROUTING"},
		}
	default:
		return FirewallObjectRef{}, "", false
	}
	for _, id := range identities {
		canonical := tableName + id.suffix
		if chainName == canonical {
			return FirewallObjectRef{Kind: id.kind, Family: "inet", Name: canonical}, id.builtin, true
		}
		if id.legacyCap != "" && chainName == tableName+id.legacyCap {
			// Preserve the actual uppercase name so Plan reports it as stale.
			return FirewallObjectRef{Kind: id.kind, Family: "inet", Name: chainName}, id.builtin, true
		}
		if isIPTablesGenerationChain(tableName, id.code, chainName) {
			// Generation chains implement the canonical desired object. Hide
			// the active slot/hash from the backend-neutral planner.
			return FirewallObjectRef{Kind: id.kind, Family: "inet", Name: canonical}, id.builtin, true
		}
	}
	return FirewallObjectRef{}, "", false
}

func isIPTablesGenerationChain(tableName, code, chainName string) bool {
	// Generation names use a twelve-hex desired hash plus an a/b staging slot.
	const hashLength = 12
	hashPlaceholder := strings.Repeat("0", hashLength)
	example := iptablesGenerationChain(tableName, code, hashPlaceholder, 'a')
	prefix := strings.TrimSuffix(example, hashPlaceholder+"a")
	if !strings.HasPrefix(chainName, prefix) {
		return false
	}
	tail := strings.TrimPrefix(chainName, prefix)
	if len(tail) != hashLength+1 || (tail[hashLength] != 'a' && tail[hashLength] != 'b') {
		return false
	}
	for _, c := range tail[:hashLength] {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
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

func iptablesArgs(table string, args ...string) []string {
	if table == "" {
		return append([]string(nil), args...)
	}
	out := []string{"-t", table}
	return append(out, args...)
}
