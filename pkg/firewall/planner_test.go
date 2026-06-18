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

func TestBuildDesiredState_OverlayInput(t *testing.T) {
	spec := FirewallInstanceSpec{
		ID:                "h2",
		NetNS:             "h2",
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
		ID:                "h2",
		NetNS:             "h2",
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
		ID: "h2", NetNS: "h2", Enabled: true, Mode: ModeManaged,
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
		AdvertisedPreviousPorts: []uint16{4500},
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

func TestBuildDesiredState_Disabled(t *testing.T) {
	spec := FirewallInstanceSpec{
		ID:   "h2",
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
		ID: "h2", NetNS: "h2", Enabled: true, Mode: ModeManaged,
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
		ID: "h2", NetNS: "h2", Enabled: true, Mode: ModeManaged,
		DefaultPolicy: DefaultPolicyDrop, XFRMTunnelPattern: "hgs*",
	}
	input := FirewallPolicyInput{
		LocalAssigned: []netip.Prefix{mustPrefix(t, "10.42.0.0/24")},
	}
	d1, _ := BuildDesiredState(spec, input)
	d2, _ := BuildDesiredState(spec, input)
	h1 := DesiredStateHash(d1)
	h2 := DesiredStateHash(d2)
	if h1 != h2 {
		t.Errorf("hash not stable: %s vs %s", h1, h2)
	}
	if h1 == "" {
		t.Error("hash is empty")
	}
}

func TestDesiredStateHash_ChangesOnPrefixChange(t *testing.T) {
	spec := FirewallInstanceSpec{
		ID: "h2", NetNS: "h2", Enabled: true, Mode: ModeManaged,
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
	spec := FirewallInstanceSpec{ID: "h2", NetNS: "h2", OwnerPrefix: "higgs"}
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
	a := OwnerToken(FirewallInstanceSpec{ID: "h2", NetNS: "h2"})
	b := OwnerToken(FirewallInstanceSpec{ID: "host", NetNS: "host", IsHost: true})
	if a == b {
		t.Error("different instances should have different owner tokens")
	}
}

func TestDesiredObjects_Overlay(t *testing.T) {
	spec := FirewallInstanceSpec{
		ID: "h2", NetNS: "h2", Enabled: true, Mode: ModeManaged,
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
		ID: "h2", NetNS: "h2", Enabled: true, Mode: ModeManaged,
	}
	input := FirewallPolicyInput{
		MeshAuthorized: []netip.Prefix{mustPrefix(t, "10.42.0.0/24")},
	}
	desired, _ := BuildDesiredState(spec, input)

	// Observed has a matching table (adopt) and a stale extra chain (delete).
	observed := FirewallObservedState{
		Objects: []FirewallObjectRef{
			{Kind: "table", Family: "inet", Name: "higgs_h2"},
			{Kind: "chain", Family: "inet", Name: "higgs_h2_stale_extra"},
		},
	}
	plan := PlanDiff("h2", desired, observed)

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
		ID: "h2", NetNS: "h2", Enabled: true, Mode: ModeManaged,
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

func TestBuildForwardingPolicy(t *testing.T) {
	p := BuildForwardingPolicy(true,
		[]netip.Prefix{mustPrefix(t, "10.0.0.0/8")},
		[]netip.Prefix{mustPrefix(t, "10.99.0.0/24")},
		[]string{"*.catofes."},
		[]string{},
		200,
	)
	if !p.Transit {
		t.Error("transit should be true")
	}
	if !IsTransitPrefixAllowed(p, mustPrefix(t, "10.42.0.0/24")) {
		t.Error("10.42/16 should be allowed under 10/8 allow")
	}
	if IsTransitPrefixAllowed(p, mustPrefix(t, "10.99.0.0/24")) {
		t.Error("10.99/24 should be denied")
	}
}

func TestBuildDesiredState_Hooks(t *testing.T) {
	spec := FirewallInstanceSpec{
		ID: "h2", NetNS: "h2", Enabled: true, Mode: ModeManaged,
		DefaultPolicy: DefaultPolicyDrop, XFRMTunnelPattern: "hgs*",
		Hooks: Hooks{PreInput: "my_pre_input", PostForward: "my_post_forward"},
	}
	desired, err := BuildDesiredState(spec, FirewallPolicyInput{})
	if err != nil {
		t.Fatalf("BuildDesiredState: %v", err)
	}
	foundPreInput := false
	foundPostForward := false
	for _, r := range desired.InputRules {
		if r.Comment == "pre_input hook" {
			foundPreInput = true
		}
	}
	for _, r := range desired.ForwardRules {
		if r.Comment == "post_forward hook" {
			foundPostForward = true
		}
	}
	if !foundPreInput {
		t.Error("pre_input hook not found")
	}
	if !foundPostForward {
		t.Error("post_forward hook not found")
	}
}

func TestBuildDesiredState_DefaultPolicyAccept(t *testing.T) {
	spec := FirewallInstanceSpec{
		ID: "h2", NetNS: "h2", Enabled: true, Mode: ModeManaged,
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
