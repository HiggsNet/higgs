package firewall

import (
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"sort"
	"strings"
)

// CommandRunner executes a command and returns combined output.
type CommandRunner func(ctx context.Context, name string, args ...string) ([]byte, error)

// NFTDriver implements FirewallDriver using the `nft` CLI (nftables).
// It is the primary backend for Phase 6.3.6.
//
// Design:
//   - All Higgs-owned objects live in an inet table named "<prefix>_<scope>".
//   - Chains within the table handle input/forward/output/prerouting.
//   - Prefix sets are nft sets; rules reference them.
//   - ListOwned parses `nft list table` output for Higgs-owned objects.
//   - Apply uses sequential nft commands.
//
// The driver is designed to be testable by injecting CommandRunner.
type NFTDriver struct {
	// Command executes an external command. Defaults to exec.CommandContext.
	Command CommandRunner
	// NetNS overrides the network namespace for `nft` execution (via ip netns exec).
	NetNS string
}

// NewNFTDriver creates an NFTDriver with the default command runner.
func NewNFTDriver() *NFTDriver {
	return &NFTDriver{Command: nftExecCommand}
}

func nftExecCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

func (d *NFTDriver) runner() CommandRunner {
	if d.Command != nil {
		return d.Command
	}
	return nftExecCommand
}

func (d *NFTDriver) run(ctx context.Context, args ...string) ([]byte, error) {
	runner := d.runner()
	if d.NetNS != "" {
		full := append([]string{"netns", "exec", d.NetNS, "nft"}, args...)
		return runner(ctx, "ip", full...)
	}
	return runner(ctx, "nft", args...)
}

func (d *NFTDriver) Preflight(ctx context.Context, spec FirewallInstanceSpec) (FirewallPreflight, error) {
	pf := PreflightProbe(ctx)
	if pf.NFTNetlink == "ok" {
		if _, err := d.run(ctx, "list", "tables"); err != nil {
			pf.NFTNetlink = "permission_denied"
			pf.Backend = BackendNone
		}
	}
	_ = spec
	return pf, nil
}

func (d *NFTDriver) Plan(ctx context.Context, desired *FirewallDesiredState, observed FirewallObservedState) (FirewallPlan, error) {
	if desired == nil {
		return FirewallPlan{}, fmt.Errorf("desired state is nil")
	}
	return PlanDiff(desired.Instance.ID, desired, observed), nil
}

func (d *NFTDriver) Apply(ctx context.Context, plan FirewallPlan, desired *FirewallDesiredState) (FirewallApplyResult, error) {
	result := FirewallApplyResult{}
	if desired == nil {
		return result, fmt.Errorf("desired state is nil")
	}
	commands := buildNFTApplyCommands(plan, desired)
	var errs []string
	for _, cmd := range commands {
		if _, err := d.run(ctx, cmd...); err != nil {
			errs = append(errs, fmt.Sprintf("nft %v: %v", cmd, err))
			result.Failed++
		} else {
			result.Applied++
		}
	}
	result.Errors = errs
	result.Generation = 1
	if len(errs) > 0 {
		return result, fmt.Errorf("nft apply had %d errors", len(errs))
	}
	return result, nil
}

func (d *NFTDriver) ListOwned(ctx context.Context, owner Owner) (FirewallObservedState, error) {
	prefix := owner.OwnerPrefix
	if prefix == "" {
		prefix = "higgs"
	}
	scope := owner.InstanceID
	tableName := prefix + "_" + scope
	out, err := d.run(ctx, "list", "table", "inet", tableName)
	if err != nil {
		return FirewallObservedState{}, nil
	}
	return parseNFTListOutput(string(out), tableName), nil
}

func (d *NFTDriver) DeleteStale(ctx context.Context, refs []FirewallObjectRef) error {
	for _, ref := range refs {
		var args []string
		switch ref.Kind {
		case "table":
			args = []string{"delete", "table", ref.Family, ref.Name}
		case "chain":
			args = []string{"delete", "chain", ref.Family, ref.Name}
		case "set":
			args = []string{"delete", "set", ref.Family, ref.Name}
		default:
			continue
		}
		_, _ = d.run(ctx, args...)
	}
	return nil
}

// buildNFTApplyCommands generates sequential nft CLI commands to realize a plan.
func buildNFTApplyCommands(plan FirewallPlan, desired *FirewallDesiredState) [][]string {
	prefix := desired.Instance.OwnerPrefix
	if prefix == "" {
		prefix = "higgs"
	}
	scope := desired.Instance.NetNS
	if desired.Instance.IsHost {
		scope = "host"
	}
	tableName := prefix + "_" + scope

	var commands [][]string

	// Process deletes first.
	for _, a := range plan.Actions {
		if a.Action != "delete" {
			continue
		}
		switch a.Object.Kind {
		case "table":
			commands = append(commands, []string{"delete", "table", a.Object.Family, a.Object.Name})
		case "chain":
			commands = append(commands, []string{"delete", "chain", a.Object.Family, a.Object.Name})
		case "set":
			commands = append(commands, []string{"delete", "set", a.Object.Family, a.Object.Name})
		}
	}

	// Check if we need to create the table.
	needTable := false
	for _, a := range plan.Actions {
		if (a.Action == "create" || a.Action == "update") && a.Object.Kind == "table" {
			needTable = true
			break
		}
	}
	if !needTable {
		return commands
	}

	// Create table.
	commands = append(commands, []string{"add", "table", "inet", tableName})

	// Create sets for mesh prefixes.
	if len(desired.Prefixes.MeshAuthorizedV4) > 0 {
		commands = append(commands, []string{"add", "set", "inet", tableName, tableName + "_mesh_v4", "{ type ipv4_addr; }"})
		for _, p := range desired.Prefixes.MeshAuthorizedV4 {
			commands = append(commands, []string{"add", "element", "inet", tableName, tableName + "_mesh_v4", "{ " + p.String() + " }"})
		}
	}
	if len(desired.Prefixes.MeshAuthorizedV6) > 0 {
		commands = append(commands, []string{"add", "set", "inet", tableName, tableName + "_mesh_v6", "{ type ipv6_addr; }"})
		for _, p := range desired.Prefixes.MeshAuthorizedV6 {
			commands = append(commands, []string{"add", "element", "inet", tableName, tableName + "_mesh_v6", "{ " + p.String() + " }"})
		}
	}

	// Render chains.
	if desired.Instance.IsHost {
		commands = append(commands, buildNFTHostChainCommands(tableName, desired)...)
	} else {
		commands = append(commands, buildNFTOverlayChainCommands(tableName, desired)...)
	}

	return commands
}

func buildNFTOverlayChainCommands(tableName string, desired *FirewallDesiredState) [][]string {
	var commands [][]string

	inputChain := tableName + "_input"
	forwardChain := tableName + "_forward"
	outputChain := tableName + "_output"

	commands = append(commands, []string{"add", "chain", "inet", tableName, inputChain})
	for _, r := range desired.InputRules {
		commands = append(commands, []string{"add", "rule", "inet", tableName, inputChain, renderNFTRule(r)})
	}

	commands = append(commands, []string{"add", "chain", "inet", tableName, forwardChain})
	for _, r := range desired.ForwardRules {
		commands = append(commands, []string{"add", "rule", "inet", tableName, forwardChain, renderNFTRule(r)})
	}

	commands = append(commands, []string{"add", "chain", "inet", tableName, outputChain})
	for _, r := range desired.OutputRules {
		commands = append(commands, []string{"add", "rule", "inet", tableName, outputChain, renderNFTRule(r)})
	}

	return commands
}

func buildNFTHostChainCommands(tableName string, desired *FirewallDesiredState) [][]string {
	var commands [][]string

	inputChain := tableName + "_input"
	commands = append(commands, []string{"add", "chain", "inet", tableName, inputChain})
	for _, hi := range desired.HostIngress {
		rule := renderNFTHostIngressRule(hi)
		commands = append(commands, []string{"add", "rule", "inet", tableName, inputChain, rule})
	}

	if len(desired.NatRedirects) > 0 {
		preroutingChain := tableName + "_prerouting"
		commands = append(commands, []string{"add", "chain", "inet", tableName, preroutingChain, "{ type nat hook prerouting priority dstnat; }"})
		for _, nr := range desired.NatRedirects {
			rule := renderNFTNatRedirectRule(nr)
			commands = append(commands, []string{"add", "rule", "inet", tableName, preroutingChain, rule})
		}
	}

	return commands
}

func renderNFTRule(r Rule) string {
	var parts []string
	if r.IfaceIn != "" {
		parts = append(parts, "iifname", quoteNFTVal(r.IfaceIn))
	}
	if r.IfaceOut != "" {
		parts = append(parts, "oifname", quoteNFTVal(r.IfaceOut))
	}
	switch r.Proto {
	case ProtoTCP:
		parts = append(parts, "tcp")
	case ProtoUDP:
		parts = append(parts, "udp")
	case ProtoICMP:
		parts = append(parts, "icmp")
	case ProtoICMPv6:
		parts = append(parts, "icmpv6")
	}
	if r.Port > 0 && (r.Proto == ProtoTCP || r.Proto == ProtoUDP) {
		parts = append(parts, fmt.Sprintf("dport %d", r.Port))
	}
	if len(r.Src) > 0 {
		parts = append(parts, prefixNFTMatch("saddr", r.Src))
	}
	if len(r.Dst) > 0 {
		parts = append(parts, prefixNFTMatch("daddr", r.Dst))
	}
	parts = append(parts, r.Action)
	if r.Comment != "" {
		parts = append(parts, fmt.Sprintf("comment %s", quoteNFTVal(r.Comment)))
	}
	return strings.Join(parts, " ")
}

func renderNFTHostIngressRule(hi HostIngressRule) string {
	var parts []string
	parts = append(parts, nftProtoName(hi.Proto))
	if hi.Port > 0 {
		parts = append(parts, fmt.Sprintf("dport %d", hi.Port))
	}
	if hi.DstAddr.IsValid() {
		if hi.DstAddr.Is4() {
			parts = append(parts, fmt.Sprintf("ip daddr %s", hi.DstAddr.String()))
		} else {
			parts = append(parts, fmt.Sprintf("ip6 daddr %s", hi.DstAddr.String()))
		}
	}
	parts = append(parts, "accept")
	if hi.Comment != "" {
		parts = append(parts, fmt.Sprintf("comment %s", quoteNFTVal(hi.Comment)))
	}
	return strings.Join(parts, " ")
}

func renderNFTNatRedirectRule(nr NatRedirectRule) string {
	var parts []string
	parts = append(parts, nftProtoName(nr.Proto))
	if nr.OriginalDst > 0 {
		parts = append(parts, fmt.Sprintf("dport %d", nr.OriginalDst))
	}
	if nr.DstAddr.IsValid() {
		if nr.DstAddr.Is4() {
			parts = append(parts, fmt.Sprintf("ip daddr %s", nr.DstAddr.String()))
		} else {
			parts = append(parts, fmt.Sprintf("ip6 daddr %s", nr.DstAddr.String()))
		}
	}
	parts = append(parts, fmt.Sprintf("redirect to :%d", nr.RedirectTo))
	if nr.Comment != "" {
		parts = append(parts, fmt.Sprintf("comment %s", quoteNFTVal(nr.Comment)))
	}
	return strings.Join(parts, " ")
}

func prefixNFTMatch(direction string, prefixes []netip.Prefix) string {
	var v4, v6 []string
	for _, p := range prefixes {
		if p.Addr().Is4() {
			v4 = append(v4, p.String())
		} else {
			v6 = append(v6, p.String())
		}
	}
	var parts []string
	if len(v4) > 0 {
		parts = append(parts, fmt.Sprintf("ip %s { %s }", direction, strings.Join(v4, ", ")))
	}
	if len(v6) > 0 {
		parts = append(parts, fmt.Sprintf("ip6 %s { %s }", direction, strings.Join(v6, ", ")))
	}
	return strings.Join(parts, " ")
}

func nftProtoName(proto string) string {
	switch proto {
	case ProtoTCP:
		return "tcp"
	case ProtoUDP:
		return "udp"
	case ProtoICMP:
		return "icmp"
	case ProtoICMPv6:
		return "icmpv6"
	}
	return proto
}

func quoteNFTVal(s string) string {
	if strings.ContainsAny(s, " *?\"") {
		return "\"" + strings.ReplaceAll(s, "\"", "\\\"") + "\""
	}
	return s
}

// parseNFTListOutput parses `nft list table` output to extract owned objects.
func parseNFTListOutput(output, tableName string) FirewallObservedState {
	var state FirewallObservedState
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "table ") {
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				state.Objects = append(state.Objects, FirewallObjectRef{
					Kind: "table", Family: fields[1], Name: fields[2],
				})
			}
		}
		if strings.HasPrefix(line, "chain ") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				state.Objects = append(state.Objects, FirewallObjectRef{
					Kind: "chain", Family: "inet", Name: fields[1],
				})
			}
		}
		if strings.HasPrefix(line, "set ") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				state.Objects = append(state.Objects, FirewallObjectRef{
					Kind: "set", Family: "inet", Name: fields[1],
				})
			}
		}
	}
	sort.Slice(state.Objects, func(i, j int) bool {
		return objKey(state.Objects[i]) < objKey(state.Objects[j])
	})
	return state
}
