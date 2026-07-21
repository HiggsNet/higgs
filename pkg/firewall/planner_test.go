package firewall

import (
	"context"
	"net/netip"
	"testing"
)

func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatalf("invalid prefix %q: %v", s, err)
	}
	return p.Masked()
}

func TestBuildDesiredStateHostEndpointACLAllowThenDrop(t *testing.T) {
	desired, err := BuildDesiredState(FirewallInstanceSpec{
		ID: "host", NetNS: "host", IsHost: true, Mode: ModeManaged,
		EndpointServices: []EndpointService{{
			Name: "egress-cn", Proto: ProtoTCP, Port: 3128,
			Destination: netip.MustParseAddr("fd42::20"),
			Sources:     []netip.Prefix{netip.MustParsePrefix("fd10::/64")},
		}},
	}, FirewallPolicyInput{})
	if err != nil {
		t.Fatalf("BuildDesiredState: %v", err)
	}
	if len(desired.ForwardRules) != 2 {
		t.Fatalf("forward rules = %+v", desired.ForwardRules)
	}
	if desired.ForwardRules[0].Action != ActionAccept || desired.ForwardRules[1].Action != ActionDrop {
		t.Fatalf("forward rule order = %+v", desired.ForwardRules)
	}
	if got := desired.ForwardRules[1].Dst[0].String(); got != "fd42::20/128" {
		t.Fatalf("drop destination = %s", got)
	}
}

func TestBuildDesiredStateHostEndpointACLEmptySourcesOnlyDrops(t *testing.T) {
	desired, err := BuildDesiredState(FirewallInstanceSpec{
		ID: "host", NetNS: "host", IsHost: true, Mode: ModeManaged,
		EndpointServices: []EndpointService{{Name: "closed", Proto: ProtoTCP, Port: 3128, Destination: netip.MustParseAddr("10.0.0.20")}},
	}, FirewallPolicyInput{})
	if err != nil {
		t.Fatalf("BuildDesiredState: %v", err)
	}
	if len(desired.ForwardRules) != 1 || desired.ForwardRules[0].Action != ActionDrop {
		t.Fatalf("forward rules = %+v", desired.ForwardRules)
	}
}

func TestBuildDesiredState_OverlayInput(t *testing.T) {
	spec := FirewallInstanceSpec{
		ID:                "higgstesth2",
		NetNS:             "higgstesth2",
		Enabled:           true,
		Mode:              ModeManaged,
		Backend:           BackendAuto,
		DefaultPolicy:     DefaultPolicyDrop,
		XFRMTunnelPattern: "hgs*",
	}
	input := FirewallPolicyInput{
		LocalAssigned:      []netip.Prefix{mustPrefix(t, "10.42.0.0/24")},
		MeshAuthorized:     []netip.Prefix{mustPrefix(t, "10.42.0.0/24"), mustPrefix(t, "10.43.0.0/24")},
		AssignmentPrefixes: []netip.Prefix{mustPrefix(t, "10.42.0.0/24")},
		Forwarding:         ForwardingPolicy{Transit: false},
	}
	desired, err := BuildDesiredState(spec, input)
	if err != nil {
		t.Fatalf("BuildDesiredState: %v", err)
	}
	if desired == nil {
		t.Fatal("desired state is nil")
	}
	if len(desired.Prefixes.LocalAssignedV4) != 1 {
		t.Errorf("expected 1 local assigned v4 prefix, got %d", len(desired.Prefixes.LocalAssignedV4))
	}
	if len(desired.Prefixes.MeshAuthorizedV4) != 2 {
		t.Errorf("expected 2 mesh authorized v4 prefixes, got %d", len(desired.Prefixes.MeshAuthorizedV4))
	}
	if len(desired.InputRules) == 0 {
		t.Error("expected input rules")
	}
	if len(desired.ForwardRules) == 0 {
		t.Error("expected forward rules")
	}
	if len(desired.OutputRules) == 0 {
		t.Error("expected output rules")
	}

	// Non-transit must drop XFRM-to-XFRM
	foundNonTransitDrop := false
	for _, r := range desired.ForwardRules {
		if r.Action == ActionDrop && r.Comment == "non-transit drop" {
			foundNonTransitDrop = true
		}
	}
	if !foundNonTransitDrop {
		t.Error("non-transit forward chain missing XFRM-to-XFRM drop")
	}
}

func TestBuildDesiredState_TransitEnabled(t *testing.T) {
	spec := FirewallInstanceSpec{
		ID:                "higgstesth2",
		NetNS:             "higgstesth2",
		Enabled:           true,
		Mode:              ModeManaged,
		DefaultPolicy:     DefaultPolicyDrop,
		XFRMTunnelPattern: "hgs*",
	}
	input := FirewallPolicyInput{
		MeshAuthorized: []netip.Prefix{mustPrefix(t, "10.42.0.0/24")},
		Forwarding: ForwardingPolicy{
			Transit:       true,
			AllowPrefixes: []netip.Prefix{mustPrefix(t, "10.42.0.0/24")},
		},
	}
	desired, err := BuildDesiredState(spec, input)
	if err != nil {
		t.Fatalf("BuildDesiredState: %v", err)
	}
	foundTransitAccept := false
	for _, r := range desired.ForwardRules {
		if r.Action == ActionAccept && r.Comment == "xfrm transit (transit enabled)" {
			foundTransitAccept = true
		}
	}
	if !foundTransitAccept {
		t.Error("transit enabled but no XFRM transit accept rule")
	}
}

func TestBuildDesiredState_TransitAllowFilters(t *testing.T) {
	spec := FirewallInstanceSpec{
		ID: "higgstesth2", NetNS: "higgstesth2", Enabled: true, Mode: ModeManaged,
		DefaultPolicy: DefaultPolicyDrop, XFRMTunnelPattern: "hgs*",
	}
	// Allow only 10.42.0.0/24, mesh has 10.42 and 10.43.
	input := FirewallPolicyInput{
		MeshAuthorized: []netip.Prefix{mustPrefix(t, "10.42.0.0/24"), mustPrefix(t, "10.43.0.0/24")},
		Forwarding: ForwardingPolicy{
			Transit:       true,
			AllowPrefixes: []netip.Prefix{mustPrefix(t, "10.42.0.0/24")},
		},
	}
	desired, err := BuildDesiredState(spec, input)
	if err != nil {
		t.Fatalf("BuildDesiredState: %v", err)
	}
	for _, r := range desired.ForwardRules {
		if r.Comment != "xfrm transit (transit enabled)" {
			continue
		}
		// Should only contain 10.42.0.0/24
		for _, p := range r.Src {
			if p.String() == "10.43.0.0/24" {
				t.Error("transit allow filter did not exclude 10.43.0.0/24")
			}
		}
	}
}

func TestBuildDesiredState_TransitAllowParentPrefix(t *testing.T) {
	desired, err := BuildDesiredState(FirewallInstanceSpec{
		ID: "mesh", Enabled: true, Mode: ModeManaged, DefaultPolicy: DefaultPolicyDrop,
	}, FirewallPolicyInput{
		MeshAuthorized: []netip.Prefix{mustPrefix(t, "10.42.1.0/24"), mustPrefix(t, "10.43.0.0/24")},
		Forwarding: ForwardingPolicy{
			Transit:       true,
			AllowPrefixes: []netip.Prefix{mustPrefix(t, "10.42.0.0/16")},
		},
	})
	if err != nil {
		t.Fatalf("BuildDesiredState: %v", err)
	}
	for _, rule := range desired.ForwardRules {
		if rule.Comment != "xfrm transit (transit enabled)" {
			continue
		}
		if len(rule.Src) != 1 || rule.Src[0].String() != "10.42.1.0/24" {
			t.Fatalf("transit prefixes = %v, want child prefix covered by allow /16", rule.Src)
		}
		return
	}
	t.Fatal("transit accept rule not found")
}

func TestBuildDesiredState_HostInstance(t *testing.T) {
	spec := FirewallInstanceSpec{
		ID:            "host-ipsec",
		NetNS:         "host",
		IsHost:        true,
		Enabled:       true,
		Mode:          ModeManaged,
		HostPorts:     HostPortConfig{IKE: true, NATT: true},
		RedirectGrace: RedirectGrace{Enabled: true},
	}
	input := FirewallPolicyInput{
		AdvertisedPreviousNATTPorts: []uint16{4500},
	}
	desired, err := BuildDesiredState(spec, input)
	if err != nil {
		t.Fatalf("BuildDesiredState: %v", err)
	}
	if len(desired.HostIngress) < 2 {
		t.Errorf("expected at least 2 host ingress rules (ike+natt), got %d", len(desired.HostIngress))
	}
	foundIKE := false
	foundNATT := false
	for _, hi := range desired.HostIngress {
		if hi.Port == 500 {
			foundIKE = true
		}
		if hi.Port == 4500 {
			foundNATT = true
		}
	}
	if !foundIKE {
		t.Error("missing IKE ingress rule")
	}
	if !foundNATT {
		t.Error("missing NAT-T ingress rule")
	}
}

func TestBuildDesiredState_HostIngressListenAddrsBinding(t *testing.T) {
	addrA := netip.MustParseAddr("192.0.2.10")
	addrB := netip.MustParseAddr("2001:db8::10")

	t.Run("empty binds no destination", func(t *testing.T) {
		spec := FirewallInstanceSpec{
			ID:            "host-ipsec",
			NetNS:         "host",
			IsHost:        true,
			Enabled:       true,
			Mode:          ModeManaged,
			HostPorts:     HostPortConfig{IKE: true, NATT: true},
			RedirectGrace: RedirectGrace{Enabled: true},
		}
		desired, err := BuildDesiredState(spec, FirewallPolicyInput{})
		if err != nil {
			t.Fatalf("BuildDesiredState: %v", err)
		}
		if len(desired.HostIngress) == 0 {
			t.Fatal("expected host ingress rules")
		}
		for _, hi := range desired.HostIngress {
			if hi.DstAddr.IsValid() {
				t.Errorf("port %d: expected no daddr binding, got %s", hi.Port, hi.DstAddr)
			}
		}
	})

	t.Run("multiple addrs bind one rule per address", func(t *testing.T) {
		spec := FirewallInstanceSpec{
			ID:            "host-ipsec",
			NetNS:         "host",
			IsHost:        true,
			Enabled:       true,
			Mode:          ModeManaged,
			HostPorts:     HostPortConfig{IKE: true},
			ListenAddrs:   []netip.Addr{addrA, addrB},
			RedirectGrace: RedirectGrace{Enabled: true},
		}
		desired, err := BuildDesiredState(spec, FirewallPolicyInput{})
		if err != nil {
			t.Fatalf("BuildDesiredState: %v", err)
		}
		// IKE only -> exactly one ingress rule per listen addr, in order.
		var got []netip.Addr
		for _, hi := range desired.HostIngress {
			if hi.Port != defaultIKEPort {
				t.Errorf("unexpected ingress port %d", hi.Port)
				continue
			}
			if !hi.DstAddr.IsValid() {
				t.Errorf("port %d: expected daddr binding, got none", hi.Port)
				continue
			}
			got = append(got, hi.DstAddr)
		}
		if len(got) != 2 {
			t.Fatalf("expected 2 ingress rules (one per addr), got %d: %+v", len(got), got)
		}
		if !(got[0] == addrA && got[1] == addrB) {
			t.Errorf("ingress addrs = %+v, want [%s %s]", got, addrA, addrB)
		}
	})
}

func TestBuildDesiredState_Disabled(t *testing.T) {
	spec := FirewallInstanceSpec{
		ID:   "higgstesth2",
		Mode: ModeDisabled,
	}
	desired, err := BuildDesiredState(spec, FirewallPolicyInput{})
	if err != nil {
		t.Fatalf("BuildDesiredState: %v", err)
	}
	if len(desired.InputRules) != 0 || len(desired.ForwardRules) != 0 {
		t.Error("disabled mode should produce no rules")
	}
}

func TestBuildDesiredState_MissingID(t *testing.T) {
	spec := FirewallInstanceSpec{}
	_, err := BuildDesiredState(spec, FirewallPolicyInput{})
	if err == nil {
		t.Error("expected error for missing ID")
	}
}

func TestBuildDesiredState_LocalServices(t *testing.T) {
	spec := FirewallInstanceSpec{
		ID: "higgstesth2", NetNS: "higgstesth2", Enabled: true, Mode: ModeManaged,
		DefaultPolicy: DefaultPolicyDrop, XFRMTunnelPattern: "hgs*",
		LocalServices: []LocalService{
			{Proto: "tcp", Port: 8080},
		},
	}
	input := FirewallPolicyInput{
		MeshAuthorized: []netip.Prefix{mustPrefix(t, "10.42.0.0/24")},
	}
	desired, err := BuildDesiredState(spec, input)
	if err != nil {
		t.Fatalf("BuildDesiredState: %v", err)
	}
	found := false
	for _, r := range desired.InputRules {
		if r.Proto == "tcp" && r.Port == 8080 {
			found = true
		}
	}
	if !found {
		t.Error("local service rule not found")
	}
}

func TestDesiredStateHash_Stable(t *testing.T) {
	spec := FirewallInstanceSpec{
		ID: "higgstesth2", NetNS: "higgstesth2", Enabled: true, Mode: ModeManaged,
		DefaultPolicy: DefaultPolicyDrop, XFRMTunnelPattern: "hgs*",
	}
	input := FirewallPolicyInput{
		LocalAssigned: []netip.Prefix{mustPrefix(t, "10.42.0.0/24")},
	}
	d1, _ := BuildDesiredState(spec, input)
	d2, _ := BuildDesiredState(spec, input)
	h1 := DesiredStateHash(d1)
	hash2 := DesiredStateHash(d2)
	if h1 != hash2 {
		t.Errorf("hash not stable: %s vs %s", h1, hash2)
	}
	if h1 == "" {
		t.Error("hash is empty")
	}
}

func TestDesiredStateHash_ChangesOnPrefixChange(t *testing.T) {
	spec := FirewallInstanceSpec{
		ID: "higgstesth2", NetNS: "higgstesth2", Enabled: true, Mode: ModeManaged,
		DefaultPolicy: DefaultPolicyDrop, XFRMTunnelPattern: "hgs*",
	}
	d1, _ := BuildDesiredState(spec, FirewallPolicyInput{
		LocalAssigned: []netip.Prefix{mustPrefix(t, "10.42.0.0/24")},
	})
	d2, _ := BuildDesiredState(spec, FirewallPolicyInput{
		LocalAssigned: []netip.Prefix{mustPrefix(t, "10.99.0.0/24")},
	})
	if DesiredStateHash(d1) == DesiredStateHash(d2) {
		t.Error("hash should change when prefixes change")
	}
}

func TestOwnerToken_Stable(t *testing.T) {
	spec := FirewallInstanceSpec{ID: "higgstesth2", NetNS: "higgstesth2", OwnerPrefix: "higgs"}
	t1 := OwnerToken(spec)
	t2 := OwnerToken(spec)
	if t1 != t2 {
		t.Error("owner token not stable")
	}
	if t1 == "" {
		t.Error("owner token empty")
	}
}

func TestOwnerToken_DifferentInstances(t *testing.T) {
	a := OwnerToken(FirewallInstanceSpec{ID: "higgstesth2", NetNS: "higgstesth2"})
	b := OwnerToken(FirewallInstanceSpec{ID: "host", NetNS: "host", IsHost: true})
	if a == b {
		t.Error("different instances should have different owner tokens")
	}
}

func TestDesiredObjects_Overlay(t *testing.T) {
	spec := FirewallInstanceSpec{
		ID: "higgstesth2", NetNS: "higgstesth2", Enabled: true, Mode: ModeManaged,
	}
	input := FirewallPolicyInput{
		MeshAuthorized: []netip.Prefix{mustPrefix(t, "10.42.0.0/24")},
	}
	desired, _ := BuildDesiredState(spec, input)
	objs := DesiredObjects(desired)
	if len(objs) == 0 {
		t.Fatal("expected owned objects")
	}
	foundTable := false
	foundSet := false
	for _, o := range objs {
		if o.Kind == "table" {
			foundTable = true
		}
		if o.Kind == "set" {
			foundSet = true
		}
	}
	if !foundTable {
		t.Error("missing table object")
	}
	if !foundSet {
		t.Error("missing set object")
	}
}

func TestPlanDiff_CreateAdoptDelete(t *testing.T) {
	spec := FirewallInstanceSpec{
		ID: "higgstesth2", NetNS: "higgstesth2", Enabled: true, Mode: ModeManaged,
	}
	input := FirewallPolicyInput{
		MeshAuthorized: []netip.Prefix{mustPrefix(t, "10.42.0.0/24")},
	}
	desired, _ := BuildDesiredState(spec, input)

	// Observed has a matching table (adopt) and a stale extra chain (delete).
	observed := FirewallObservedState{
		Objects: []FirewallObjectRef{
			{Kind: "table", Family: "inet", Name: "higgs_higgstesth2"},
			{Kind: "chain", Family: "inet", Name: "higgs_higgstesth2_stale_extra"},
		},
	}
	plan := PlanDiff("higgstesth2", desired, observed)

	createCount := 0
	adoptCount := 0
	deleteCount := 0
	for _, a := range plan.Actions {
		switch a.Action {
		case "create":
			createCount++
		case "adopt":
			adoptCount++
		case "delete":
			deleteCount++
		}
	}
	if createCount == 0 {
		t.Error("expected at least one create action for missing desired objects")
	}
	if adoptCount == 0 {
		t.Error("expected at least one adopt action for existing matching object")
	}
	if deleteCount == 0 {
		t.Error("expected at least one delete action for stale observed object")
	}
}

func TestDryRunDriver_PlanApply(t *testing.T) {
	driver := NewDryRunDriver()
	spec := FirewallInstanceSpec{
		ID: "higgstesth2", NetNS: "higgstesth2", Enabled: true, Mode: ModeManaged,
	}
	input := FirewallPolicyInput{
		MeshAuthorized: []netip.Prefix{mustPrefix(t, "10.42.0.0/24")},
	}
	desired, _ := BuildDesiredState(spec, input)

	observed, err := driver.ListOwned(context.Background(), Owner{})
	if err != nil {
		t.Fatalf("ListOwned: %v", err)
	}
	plan, err := driver.Plan(context.Background(), desired, observed)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	result, err := driver.Apply(context.Background(), plan, desired)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if result.Generation == 0 {
		t.Error("generation should be non-zero")
	}
	if len(driver.RecordedPlans()) == 0 {
		t.Error("no recorded plans")
	}
}

func TestPreflightProbe_BackendSelection(t *testing.T) {
	pf := PreflightProbe(context.Background())
	if pf.Backend == "" {
		t.Error("backend should be set")
	}
	// On a non-root dev machine without nft/iptables, it may be "none".
	// Just verify the field is populated.
}

func TestResolveBackend(t *testing.T) {
	pf := FirewallPreflight{NFTNetlink: "ok", Iptables: "available", Backend: BackendNFT}
	if got := ResolveBackend(BackendNFT, pf); got != BackendNFT {
		t.Errorf("ResolveBackend(nft) = %s, want nft", got)
	}
	pf2 := FirewallPreflight{NFTNetlink: "unavailable", Iptables: "available", Backend: BackendIptables}
	if got := ResolveBackend(BackendNFT, pf2); got != BackendNone {
		t.Errorf("ResolveBackend(nft, unavailable) = %s, want none", got)
	}
	if got := ResolveBackend(BackendIptables, pf2); got != BackendIptables {
		t.Errorf("ResolveBackend(iptables) = %s, want iptables", got)
	}
	if got := ResolveBackend("", pf); got != BackendNFT {
		t.Errorf("ResolveBackend(auto) = %s, want nft", got)
	}
	if got := ResolveBackend(BackendNone, pf); got != BackendNone {
		t.Errorf("ResolveBackend(none) = %s, want none", got)
	}
}

func TestBuildDesiredState_InvalidDropFirst(t *testing.T) {
	spec := FirewallInstanceSpec{
		ID: "higgstesth2", NetNS: "higgstesth2", Enabled: true, Mode: ModeManaged,
		DefaultPolicy: DefaultPolicyDrop, XFRMTunnelPattern: "hgs*",
	}
	desired, err := BuildDesiredState(spec, FirewallPolicyInput{})
	if err != nil {
		t.Fatalf("BuildDesiredState: %v", err)
	}
	if len(desired.InputRules) < 2 {
		t.Fatalf("input rules = %+v, want at least invalid drop and loopback", desired.InputRules)
	}
	first := desired.InputRules[0]
	if first.Action != ActionDrop {
		t.Fatalf("first input rule action = %q, want drop", first.Action)
	}
	if len(first.CtStates) != 1 || first.CtStates[0] != CtStateInvalid {
		t.Fatalf("first input rule ct states = %v, want [invalid]", first.CtStates)
	}
	if desired.InputRules[1].Comment != "loopback" {
		t.Fatalf("second input rule = %+v, want loopback accept", desired.InputRules[1])
	}
	if len(desired.ForwardRules) == 0 {
		t.Fatal("forward rules are empty")
	}
	forwardFirst := desired.ForwardRules[0]
	if forwardFirst.Action != ActionDrop || len(forwardFirst.CtStates) != 1 || forwardFirst.CtStates[0] != CtStateInvalid {
		t.Fatalf("first forward rule = %+v, want ct state invalid drop", forwardFirst)
	}
}

func TestBuildDesiredState_EstablishedRelatedCtState(t *testing.T) {
	spec := FirewallInstanceSpec{
		ID: "higgstesth2", NetNS: "higgstesth2", Enabled: true, Mode: ModeManaged,
		DefaultPolicy: DefaultPolicyDrop, XFRMTunnelPattern: "hgs*",
	}
	desired, err := BuildDesiredState(spec, FirewallPolicyInput{})
	if err != nil {
		t.Fatalf("BuildDesiredState: %v", err)
	}
	assertEstRelated := func(chain string, rules []Rule) {
		t.Helper()
		for _, r := range rules {
			if r.Comment != "established related" {
				continue
			}
			if r.Action != ActionAccept {
				t.Fatalf("%s established/related action = %q, want accept", chain, r.Action)
			}
			if len(r.CtStates) != 2 || r.CtStates[0] != CtStateEstablished || r.CtStates[1] != CtStateRelated {
				t.Fatalf("%s established/related ct states = %v, want [established related]", chain, r.CtStates)
			}
			return
		}
		t.Fatalf("%s established/related rule not found", chain)
	}
	assertEstRelated("input", desired.InputRules)
	assertEstRelated("forward", desired.ForwardRules)
}

func TestBuildDesiredState_RevokedPrefixesExcluded(t *testing.T) {
	spec := FirewallInstanceSpec{
		ID: "higgstesth2", NetNS: "higgstesth2", Enabled: true, Mode: ModeManaged,
		DefaultPolicy: DefaultPolicyDrop, XFRMTunnelPattern: "hgs*",
	}
	input := FirewallPolicyInput{
		LocalAssigned:  []netip.Prefix{mustPrefix(t, "10.42.0.0/24"), mustPrefix(t, "10.99.0.0/24")},
		MeshAuthorized: []netip.Prefix{mustPrefix(t, "10.42.0.0/24"), mustPrefix(t, "10.99.0.0/24")},
		Revoked:        []netip.Prefix{mustPrefix(t, "10.99.0.0/24")},
		Forwarding:     ForwardingPolicy{Transit: true},
	}
	desired, err := BuildDesiredState(spec, input)
	if err != nil {
		t.Fatalf("BuildDesiredState: %v", err)
	}
	// Revoked prefix should not appear in allow sets
	for _, p := range desired.Prefixes.LocalAssignedV4 {
		if p.String() == "10.99.0.0/24" {
			t.Error("revoked prefix 10.99.0.0/24 appeared in LocalAssignedV4")
		}
	}
	for _, p := range desired.Prefixes.MeshAuthorizedV4 {
		if p.String() == "10.99.0.0/24" {
			t.Error("revoked prefix 10.99.0.0/24 appeared in MeshAuthorizedV4")
		}
	}
	// Revoked prefix should appear in audit set
	foundRevoked := false
	for _, p := range desired.Prefixes.RevokedV4 {
		if p.String() == "10.99.0.0/24" {
			foundRevoked = true
		}
	}
	if !foundRevoked {
		t.Error("revoked prefix 10.99.0.0/24 missing from RevokedV4 audit set")
	}
}

func TestBuildDesiredState_RevokedHashChanges(t *testing.T) {
	spec := FirewallInstanceSpec{
		ID: "higgstesth2", NetNS: "higgstesth2", Enabled: true, Mode: ModeManaged,
		DefaultPolicy: DefaultPolicyDrop, XFRMTunnelPattern: "hgs*",
	}
	base := FirewallPolicyInput{
		LocalAssigned: []netip.Prefix{mustPrefix(t, "10.42.0.0/24")},
	}
	withRevoked := FirewallPolicyInput{
		LocalAssigned: []netip.Prefix{mustPrefix(t, "10.42.0.0/24")},
		Revoked:       []netip.Prefix{mustPrefix(t, "10.99.0.0/24")},
	}
	d1, _ := BuildDesiredState(spec, base)
	d2, _ := BuildDesiredState(spec, withRevoked)
	if DesiredStateHash(d1) == DesiredStateHash(d2) {
		t.Error("hash should change when revoked prefix is added")
	}
}

func TestBuildDesiredState_TransitDenyPrefixes(t *testing.T) {
	spec := FirewallInstanceSpec{
		ID: "higgstesth2", NetNS: "higgstesth2", Enabled: true, Mode: ModeManaged,
		DefaultPolicy: DefaultPolicyDrop, XFRMTunnelPattern: "hgs*",
	}
	input := FirewallPolicyInput{
		MeshAuthorized: []netip.Prefix{mustPrefix(t, "10.42.0.0/24"), mustPrefix(t, "10.99.0.0/24")},
		Forwarding: ForwardingPolicy{
			Transit:      true,
			DenyPrefixes: []netip.Prefix{mustPrefix(t, "10.99.0.0/24")},
		},
	}
	desired, err := BuildDesiredState(spec, input)
	if err != nil {
		t.Fatalf("BuildDesiredState: %v", err)
	}
	// Transit rule should not include denied prefix
	for _, r := range desired.ForwardRules {
		if r.Comment != "xfrm transit (transit enabled)" {
			continue
		}
		for _, p := range r.Src {
			if p.String() == "10.99.0.0/24" {
				t.Error("denied prefix 10.99.0.0/24 appeared in transit accept rule")
			}
		}
	}
}

func TestBuildDesiredState_DefaultPolicyAccept(t *testing.T) {
	spec := FirewallInstanceSpec{
		ID: "higgstesth2", NetNS: "higgstesth2", Enabled: true, Mode: ModeManaged,
		DefaultPolicy: DefaultPolicyAccept, XFRMTunnelPattern: "hgs*",
	}
	desired, err := BuildDesiredState(spec, FirewallPolicyInput{})
	if err != nil {
		t.Fatalf("BuildDesiredState: %v", err)
	}
	// Input default should be accept
	foundAcceptDefault := false
	for _, r := range desired.InputRules {
		if r.Comment == "default policy" && r.Action == ActionAccept {
			foundAcceptDefault = true
		}
	}
	if !foundAcceptDefault {
		t.Error("default policy accept not found in input chain")
	}
}
