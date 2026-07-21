package firewall

import (
	"strings"
	"testing"
)

func TestBuildDesiredStateInlineHookPositionsAndHash(t *testing.T) {
	spec := FirewallInstanceSpec{
		ID: "h2", NetNS: "h2", Mode: ModeManaged, Backend: BackendAuto,
		NativeHooks: NativeHooks{NFT: InlineHookRules{
			PreInput:    []string{"tcp dport 22 accept"},
			PostInput:   []string{"counter"},
			PreForward:  []string{"counter"},
			PostForward: []string{"counter"},
			PreOutput:   []string{"counter"},
			PostOutput:  []string{"counter"},
		}},
	}
	desired, err := BuildDesiredState(spec, FirewallPolicyInput{})
	if err != nil {
		t.Fatalf("BuildDesiredState: %v", err)
	}
	if desired.HookPositions.PreInput != 2 {
		t.Fatalf("pre_input index = %d, want 2 after invalid and loopback", desired.HookPositions.PreInput)
	}
	if desired.HookPositions.PostInput != len(desired.InputRules)-1 {
		t.Fatalf("post_input index = %d, want immediately before default rule", desired.HookPositions.PostInput)
	}
	if desired.HookPositions.PreForward != 2 || desired.HookPositions.PostForward != len(desired.ForwardRules)-1 {
		t.Fatalf("forward hook indexes = (%d,%d), rules=%d", desired.HookPositions.PreForward, desired.HookPositions.PostForward, len(desired.ForwardRules))
	}
	if desired.HookPositions.PreOutput != 0 || desired.HookPositions.PostOutput != len(desired.OutputRules)-1 {
		t.Fatalf("output hook indexes = (%d,%d), rules=%d", desired.HookPositions.PreOutput, desired.HookPositions.PostOutput, len(desired.OutputRules))
	}

	withoutHooks := spec
	withoutHooks.NativeHooks = NativeHooks{}
	other, err := BuildDesiredState(withoutHooks, FirewallPolicyInput{})
	if err != nil {
		t.Fatalf("BuildDesiredState without hooks: %v", err)
	}
	if DesiredStateHash(desired) == DesiredStateHash(other) {
		t.Fatal("native hook expression must change desired-state hash")
	}
}

func TestBuildDesiredStateRejectsInvalidInlineHooks(t *testing.T) {
	tests := []struct {
		name    string
		spec    FirewallInstanceSpec
		wantErr string
	}{
		{
			name: "nft object command",
			spec: FirewallInstanceSpec{ID: "h2", NetNS: "h2", Mode: ModeManaged, NativeHooks: NativeHooks{
				NFT: InlineHookRules{PreInput: []string{"add table inet escaped"}},
			}},
			wantErr: "expression body",
		},
		{
			name: "iptables chain operation",
			spec: FirewallInstanceSpec{ID: "h2", NetNS: "h2", Mode: ModeManaged, NativeHooks: NativeHooks{
				IPTables: IPTablesInlineHooks{IPv4: InlineHookRules{PreInput: []string{"-A INPUT -j ACCEPT"}}},
			}},
			wantErr: "may manage rules",
		},
		{
			name: "host point on overlay",
			spec: FirewallInstanceSpec{ID: "h2", NetNS: "h2", Mode: ModeManaged, NativeHooks: NativeHooks{
				NFT: InlineHookRules{HostPreInput: []string{"counter"}},
			}},
			wantErr: "host inline hooks require a host instance",
		},
		{
			name: "explicit backend mismatch",
			spec: FirewallInstanceSpec{ID: "h2", NetNS: "h2", Mode: ModeManaged, Backend: BackendNFT,
				NativeHooks: NativeHooks{IPTables: IPTablesInlineHooks{IPv4: InlineHookRules{PreInput: []string{"-j ACCEPT"}}}},
			},
			wantErr: "only iptables_hooks",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := BuildDesiredState(tt.spec, FirewallPolicyInput{})
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("BuildDesiredState error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestSplitIPTablesRulePreservesQuotedArgument(t *testing.T) {
	args, err := splitIPTablesRule(`-m comment --comment "two words" -j LOG`)
	if err != nil {
		t.Fatalf("splitIPTablesRule: %v", err)
	}
	want := []string{"-m", "comment", "--comment", "two words", "-j", "LOG"}
	if strings.Join(args, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("args = %#v, want %#v", args, want)
	}
}

func TestHostInlinePreroutingCreatesManagedObject(t *testing.T) {
	desired, err := BuildDesiredState(FirewallInstanceSpec{
		ID: "host", NetNS: "host", IsHost: true, Mode: ModeManaged,
		NativeHooks: NativeHooks{NFT: InlineHookRules{HostPrePrerouting: []string{"counter"}}},
	}, FirewallPolicyInput{})
	if err != nil {
		t.Fatalf("BuildDesiredState: %v", err)
	}
	for _, ref := range DesiredObjects(desired) {
		if ref.Kind == "nat_redirect" && strings.HasSuffix(ref.Name, "_prerouting") {
			return
		}
	}
	t.Fatalf("host prerouting object missing from %+v", DesiredObjects(desired))
}

func TestResolveBackendForInstanceHonorsInlineHookBackend(t *testing.T) {
	pf := FirewallPreflight{Backend: BackendNFT, NFTNetlink: "ok", Iptables: "available"}
	iptablesOnly := FirewallInstanceSpec{
		ID: "h2", Backend: BackendAuto,
		NativeHooks: NativeHooks{IPTables: IPTablesInlineHooks{IPv4: InlineHookRules{PreInput: []string{"-j ACCEPT"}}}},
	}
	got, err := ResolveBackendForInstance(iptablesOnly, pf)
	if err != nil || got != BackendIptables {
		t.Fatalf("iptables-only hooks resolved to (%q, %v), want iptables", got, err)
	}

	nftOnly := FirewallInstanceSpec{
		ID: "h2", Backend: BackendAuto,
		NativeHooks: NativeHooks{NFT: InlineHookRules{PreInput: []string{"counter"}}},
	}
	got, err = ResolveBackendForInstance(nftOnly, pf)
	if err != nil || got != BackendNFT {
		t.Fatalf("nft-only hooks resolved to (%q, %v), want nft", got, err)
	}

	both := nftOnly
	both.NativeHooks.IPTables.IPv4.PreInput = []string{"-j ACCEPT"}
	got, err = ResolveBackendForInstance(both, pf)
	if err != nil || got != BackendNFT {
		t.Fatalf("dual hooks resolved to (%q, %v), want normal nft preference", got, err)
	}

	pf.Iptables = "unavailable"
	if _, err := ResolveBackendForInstance(iptablesOnly, pf); err == nil || !strings.Contains(err.Error(), "iptables_hooks require iptables") {
		t.Fatalf("iptables-only unavailable error = %v", err)
	}
}
