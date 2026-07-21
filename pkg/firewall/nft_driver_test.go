package firewall

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"sort"
	"strings"
	"testing"
)

// fakeCommandRunner captures all commands executed by a driver for assertions.
type fakeCommandRunner struct {
	commands []executedCommand
	// failOnNew lists chain names whose `-N` creation should fail, simulating
	// an already-existing chain.
	failOnNew      map[string]bool
	existingChains map[string]bool
	existingRules  map[string]bool
	ruleArgs       map[string][]string
	ruleCounts     map[string]int
	failContains   string
	nftBatchErr    error
}

type executedCommand struct {
	name string
	args []string
	// input contains the nft batch file contents for `nft -f <path>`.
	input string
}

func (f *fakeCommandRunner) run(ctx context.Context, name string, args ...string) ([]byte, error) {
	command := executedCommand{name: name, args: args}
	if name == "nft" && len(args) == 2 && args[0] == "-f" {
		contents, err := os.ReadFile(args[1])
		if err != nil {
			return nil, err
		}
		command.input = string(contents)
		f.commands = append(f.commands, command)
		if f.nftBatchErr != nil {
			return []byte("batch rejected"), f.nftBatchErr
		}
		return []byte(""), nil
	}
	f.commands = append(f.commands, command)
	if name == "iptables" || name == "ip6tables" {
		return f.runIPTables(name, args)
	}
	// Simulate `nft list tables` returning empty (no owned objects).
	if len(args) >= 1 && args[0] == "list" {
		return []byte(""), nil
	}
	return []byte(""), nil
}

func commandText(command executedCommand) string {
	return strings.TrimSpace(strings.Join(command.args, " ") + "\n" + command.input)
}

func (f *fakeCommandRunner) seedIPTablesChain(binary, table, chain string) {
	if f.existingChains == nil {
		f.existingChains = make(map[string]bool)
	}
	f.existingChains[binary+":"+table+":"+chain] = true
}

func (f *fakeCommandRunner) seedIPTablesRule(binary, table string, args []string) {
	if f.existingRules == nil {
		f.existingRules = make(map[string]bool)
	}
	if f.ruleArgs == nil {
		f.ruleArgs = make(map[string][]string)
	}
	if f.ruleCounts == nil {
		f.ruleCounts = make(map[string]int)
	}
	key := binary + ":" + table + ":" + strings.Join(args, "\x00")
	f.existingRules[key] = true
	f.ruleArgs[key] = append([]string(nil), args...)
	f.ruleCounts[key]++
}

func (f *fakeCommandRunner) runIPTables(binary string, args []string) ([]byte, error) {
	if f.existingChains == nil {
		f.existingChains = make(map[string]bool)
	}
	if f.existingRules == nil {
		f.existingRules = make(map[string]bool)
	}
	if f.ruleArgs == nil {
		f.ruleArgs = make(map[string][]string)
	}
	if f.ruleCounts == nil {
		f.ruleCounts = make(map[string]int)
	}
	table := "filter"
	opIndex := 0
	if len(args) >= 2 && args[0] == "-t" {
		table = args[1]
		opIndex = 2
	}
	if opIndex >= len(args) {
		return []byte(""), nil
	}
	op := args[opIndex]
	rest := args[opIndex+1:]
	chainKey := func(chain string) string { return binary + ":" + table + ":" + chain }
	switch op {
	case "-S":
		if len(rest) == 0 {
			var lines []string
			prefix := binary + ":" + table + ":"
			for key := range f.existingChains {
				if strings.HasPrefix(key, prefix) {
					lines = append(lines, "-N "+strings.TrimPrefix(key, prefix))
				}
			}
			for key, args := range f.ruleArgs {
				if strings.HasPrefix(key, prefix) {
					count := f.ruleCounts[key]
					if count == 0 && f.existingRules[key] {
						count = 1
					}
					for i := 0; i < count; i++ {
						lines = append(lines, "-A "+strings.Join(args, " "))
					}
				}
			}
			sort.Strings(lines)
			return []byte(strings.Join(lines, "\n")), nil
		}
		if f.existingChains[chainKey(rest[0])] {
			lines := []string{"-N " + rest[0]}
			prefix := binary + ":" + table + ":"
			for key, args := range f.ruleArgs {
				if strings.HasPrefix(key, prefix) && len(args) > 0 && args[0] == rest[0] {
					count := f.ruleCounts[key]
					if count == 0 && f.existingRules[key] {
						count = 1
					}
					for i := 0; i < count; i++ {
						lines = append(lines, "-A "+strings.Join(args, " "))
					}
				}
			}
			sort.Strings(lines)
			return []byte(strings.Join(lines, "\n")), nil
		}
		return nil, errors.New("chain does not exist")
	case "-N":
		if len(rest) == 0 {
			return nil, errors.New("missing chain")
		}
		if f.failOnNew[rest[0]] || f.existingChains[chainKey(rest[0])] {
			return nil, errors.New("chain already exists")
		}
		f.existingChains[chainKey(rest[0])] = true
	case "-F":
		if len(rest) > 0 && !f.existingChains[chainKey(rest[0])] {
			return nil, errors.New("chain does not exist")
		}
		if len(rest) > 0 {
			prefix := binary + ":" + table + ":"
			for key, args := range f.ruleArgs {
				if strings.HasPrefix(key, prefix) && len(args) > 0 && args[0] == rest[0] {
					delete(f.ruleArgs, key)
					delete(f.existingRules, key)
					delete(f.ruleCounts, key)
				}
			}
		}
	case "-X":
		if len(rest) > 0 && !f.existingChains[chainKey(rest[0])] {
			return nil, errors.New("chain does not exist")
		}
		prefix := binary + ":" + table + ":"
		for key, args := range f.ruleArgs {
			if !strings.HasPrefix(key, prefix) {
				continue
			}
			for i := 0; i+1 < len(args); i++ {
				if args[i] == "-j" && args[i+1] == rest[0] {
					return nil, errors.New("chain is referenced")
				}
			}
		}
		if len(rest) > 0 {
			delete(f.existingChains, chainKey(rest[0]))
		}
	case "-C":
		key := binary + ":" + table + ":" + strings.Join(rest, "\x00")
		if !f.existingRules[key] && f.ruleCounts[key] == 0 {
			return nil, errors.New("rule does not exist")
		}
	case "-A", "-I":
		if f.failContains != "" && strings.Contains(strings.Join(rest, " "), f.failContains) {
			return nil, errors.New("injected rule failure")
		}
		key := binary + ":" + table + ":" + strings.Join(rest, "\x00")
		f.existingRules[key] = true
		f.ruleArgs[key] = append([]string(nil), rest...)
		f.ruleCounts[key]++
	case "-D":
		key := binary + ":" + table + ":" + strings.Join(rest, "\x00")
		count := f.ruleCounts[key]
		if count == 0 && f.existingRules[key] {
			count = 1
		}
		if count == 0 {
			return nil, errors.New("rule does not exist")
		}
		count--
		if count == 0 {
			delete(f.existingRules, key)
			delete(f.ruleArgs, key)
			delete(f.ruleCounts, key)
		} else {
			f.ruleCounts[key] = count
		}
	}
	return []byte(""), nil
}

func TestNFTDriver_Preflight(t *testing.T) {
	runner := &fakeCommandRunner{}
	d := &NFTDriver{Command: runner.run}
	pf, err := d.Preflight(context.Background(), FirewallInstanceSpec{ID: "higgstesth2"})
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
	// Empty observed state -> all objects are create.
	plan := PlanDiff("higgstesth2", desired, FirewallObservedState{})
	result, err := d.Apply(context.Background(), plan, desired)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if result.Applied == 0 {
		t.Error("expected non-zero applied count")
	}
	if len(runner.commands) != 1 {
		t.Fatalf("commands = %v, want one atomic nft transaction", runner.commands)
	}
	batch := commandText(runner.commands[0])
	if !strings.Contains(batch, "add table inet higgs_higgstesth2") {
		t.Errorf("expected table creation in nft batch:\n%s", batch)
	}
	for _, want := range []string{
		"hook input",
		"hook forward",
		"hook output",
	} {
		if !strings.Contains(batch, want) {
			t.Errorf("expected nft overlay chain with %s hook", want)
		}
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
	// Check for host input and nat prerouting base-chain creation.
	foundNatChain := false
	foundInputChain := false
	for _, cmd := range runner.commands {
		argsStr := commandText(cmd)
		if strings.Contains(argsStr, "prerouting") && strings.Contains(argsStr, "nat") {
			foundNatChain = true
		}
		if strings.Contains(argsStr, "higgs_host_input") && strings.Contains(argsStr, "hook input") {
			foundInputChain = true
		}
	}
	if !foundNatChain {
		t.Error("expected NAT prerouting chain creation")
	}
	if !foundInputChain {
		t.Error("expected host input base-chain creation")
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
		argsStr := commandText(cmd)
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
	if len(runner.commands) != 1 {
		t.Fatalf("commands = %v, want one atomic nft transaction", runner.commands)
	}
	batch := runner.commands[0].input
	if !strings.HasPrefix(batch, "delete table inet higgs_host\n") {
		t.Fatalf("batch = %q, want table delete first", batch)
	}
	if !strings.Contains(batch, "add table inet higgs_host\n") {
		t.Fatalf("missing table rebuild in transaction:\n%s", batch)
	}
}

func TestNFTDriver_ApplyTransactionFailureReportsNoAppliedCommands(t *testing.T) {
	runner := &fakeCommandRunner{nftBatchErr: errors.New("syntax error")}
	d := &NFTDriver{Command: runner.run}
	desired, err := BuildDesiredState(FirewallInstanceSpec{
		ID: "higgstesth2", NetNS: "higgstesth2", Enabled: true, Mode: ModeManaged,
		DefaultPolicy: DefaultPolicyDrop, XFRMTunnelPattern: "hgs*",
	}, FirewallPolicyInput{})
	if err != nil {
		t.Fatalf("BuildDesiredState: %v", err)
	}
	result, err := d.Apply(context.Background(), PlanDiff(desired.Instance.ID, desired, FirewallObservedState{}), desired)
	if err == nil {
		t.Fatal("Apply succeeded despite rejected nft transaction")
	}
	if result.Applied != 0 || result.Failed != 1 {
		t.Fatalf("result = %+v, want zero applied and one failed transaction", result)
	}
	if len(runner.commands) != 1 {
		t.Fatalf("commands = %v, want exactly one transaction attempt", runner.commands)
	}
}

func TestNFTDriver_ListOwned(t *testing.T) {
	// Simulate nft list table output.
	output := `table inet higgs_higgstesth2 {
	chain higgs_higgstesth2_input { type filter hook input priority 0; policy accept; }
	chain higgs_higgstesth2_forward { type filter hook forward priority 0; policy accept; }
	set higgs_higgstesth2_mesh_v4 { type ipv4_addr; }
}`
	state := parseNFTListOutput(output, "higgs_higgstesth2")
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
	d := &NFTDriver{Command: runner.run, NetNS: "higgstesth2"}
	_, _ = d.run(context.Background(), "list", "tables")
	if len(runner.commands) == 0 {
		t.Fatal("expected command execution")
	}
	cmd := runner.commands[0]
	if cmd.name != "ip" {
		t.Errorf("expected ip command for netns exec, got %s", cmd.name)
	}
	if len(cmd.args) < 4 || cmd.args[0] != "netns" || cmd.args[1] != "exec" || cmd.args[2] != "higgstesth2" {
		t.Errorf("expected ip netns exec higgstesth2 nft, got %v", cmd.args)
	}
}

func TestNFTDriver_DeleteStale(t *testing.T) {
	runner := &fakeCommandRunner{}
	d := &NFTDriver{Command: runner.run}
	refs := []FirewallObjectRef{
		{Kind: "chain", Family: "inet", Name: "higgs_higgstesth2_stale"},
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

func TestRenderNFTRuleCtStateAndJump(t *testing.T) {
	invalid := renderNFTRule(Rule{Action: ActionDrop, CtStates: []string{CtStateInvalid}, Comment: "invalid drop"})
	if !strings.Contains(invalid, "ct state invalid drop") {
		t.Errorf("invalid drop rendered as %q", invalid)
	}
	est := renderNFTRule(Rule{Action: ActionAccept, CtStates: []string{CtStateEstablished, CtStateRelated}, Comment: "established related"})
	if !strings.Contains(est, "ct state { established, related } accept") {
		t.Errorf("established/related rendered as %q", est)
	}
	jump := renderNFTRule(Rule{Action: ActionJump, JumpTarget: "my_pre_input", Comment: "pre_input hook"})
	if !strings.Contains(jump, "jump my_pre_input") {
		t.Errorf("hook jump rendered as %q", jump)
	}
	if strings.Contains(jump, "iifname") || strings.Contains(jump, "oifname") {
		t.Errorf("hook jump must not render an iface match: %q", jump)
	}
}

func TestBuildDesiredStateRejectsNFTHooks(t *testing.T) {
	spec := FirewallInstanceSpec{
		ID: "higgstesth2", NetNS: "higgstesth2", Enabled: true, Mode: ModeManaged,
		Backend: BackendNFT, DefaultPolicy: DefaultPolicyDrop, XFRMTunnelPattern: "hgs*",
		OwnerPrefix: "higgs",
		Hooks:       Hooks{PreInput: "my_pre_input", PostOutput: "my_post_output"},
	}
	if _, err := BuildDesiredState(spec, FirewallPolicyInput{}); err == nil || !strings.Contains(err.Error(), "nft backend does not support hooks") {
		t.Fatalf("BuildDesiredState error = %v, want nft hooks rejection", err)
	}
}

func TestNFTDriverInlineHooksAreRenderedInPlannerOrder(t *testing.T) {
	runner := &fakeCommandRunner{}
	driver := &NFTDriver{Command: runner.run}
	desired, err := BuildDesiredState(FirewallInstanceSpec{
		ID: "h2", NetNS: "h2", Mode: ModeManaged, Backend: BackendNFT, OwnerPrefix: "higgs",
		NativeHooks: NativeHooks{NFT: InlineHookRules{
			PreInput:  []string{`tcp dport 2222 accept comment "native-pre"`},
			PostInput: []string{`counter comment "native-post"`},
		}},
	}, FirewallPolicyInput{})
	if err != nil {
		t.Fatalf("BuildDesiredState: %v", err)
	}
	if _, err := driver.Apply(context.Background(), PlanDiff("h2", desired, FirewallObservedState{}), desired); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	var batch string
	for _, command := range runner.commands {
		if command.name == "nft" && command.input != "" {
			batch = command.input
		}
	}
	if batch == "" {
		t.Fatal("nft batch not captured")
	}
	invalid := strings.Index(batch, "ct state invalid drop")
	loopback := strings.Index(batch, `iifname lo accept`)
	pre := strings.Index(batch, `tcp dport 2222 accept comment "native-pre"`)
	babel := strings.Index(batch, "udp dport 6696 accept")
	post := strings.Index(batch, `counter comment "native-post"`)
	defaultDrop := strings.LastIndex(batch, "drop comment \"default policy\"")
	if !(invalid >= 0 && invalid < loopback && loopback < pre && pre < babel) {
		t.Fatalf("pre_input order incorrect: invalid=%d loopback=%d pre=%d babel=%d\n%s", invalid, loopback, pre, babel, batch)
	}
	if !(post >= 0 && defaultDrop >= 0 && post < defaultDrop) {
		t.Fatalf("post_input order incorrect: post=%d default=%d\n%s", post, defaultDrop, batch)
	}
}
