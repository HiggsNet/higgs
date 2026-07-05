package ipsec

import (
	"context"
	"github.com/Catofes/higgs/pkg/core/zone"
	"net/netip"
	"testing"
	"time"
)

func TestReconcileMatchesSameRuntimeSAByPathFamily(t *testing.T) {
	now := time.Unix(1717171717, 0)
	spec := TransportLinkSpec{
		LocalZone:       "node-a.catofes.",
		PeerZone:        "node-b.catofes.",
		OverlayID:       "ipsec-main",
		Provider:        ProviderStrongSwan,
		LinkID:          StableLinkID("node-a.catofes.", "node-b.catofes.", "ipsec-main", "family:ipv4"),
		PathKey:         "family:ipv4",
		TransportID:     "ipsec-same-runtime",
		InterfaceName:   "hgs1",
		XFRMIfID:        77,
		Generation:      3,
		LocalTunnelAddr: netip.MustParseAddr("fe80::1"),
		PeerTunnelAddr:  netip.MustParseAddr("fe80::2"),
		ContactPoints: []ContactPoint{{
			Address:    "198.51.100.20",
			Family:     FamilyIPv4,
			Generation: 3,
			IKEPort:    DefaultIKEPort,
			NATTPort:   4501,
		}},
	}
	existing := NewLinkInstance(spec, LinkStateUp, now)
	existing.PathKey = "family:ipv4"
	existing.RemoteGeneration = 3
	existing.Endpoint = "[2001:db8::20]:4501"

	result := ReconcileLinkInstances(ReconcileInputs{
		Desired:   []TransportLinkSpec{spec},
		Instances: map[string]LinkInstance{existing.ID: existing},
		SAs: []SAState{
			{
				Name:           spec.TransportID,
				ChildSA:        ChildSAName(spec),
				XFRMIfID:       spec.XFRMIfID,
				RemoteEndpoint: "[2001:db8::20]:4501",
				Endpoint:       "[2001:db8::20]:4501",
				Established:    true,
			},
			{
				Name:           spec.TransportID,
				ChildSA:        ChildSAName(spec),
				XFRMIfID:       spec.XFRMIfID,
				RemoteEndpoint: "198.51.100.20:4501",
				Endpoint:       "198.51.100.20:4501",
				Established:    true,
			},
		},
		Now: now,
	})

	action := firstAction(result, ReconcileActionAdopt)
	if action == nil {
		t.Fatalf("expected adopt from matching IPv4 SA, got %+v", result.Actions)
	}
	inst := result.Instances[existing.ID]
	if inst.Endpoint != "198.51.100.20:4501" {
		t.Fatalf("endpoint = %q, want IPv4 SA endpoint", inst.Endpoint)
	}
}

func TestReconcileSecondaryStandbyInitialNoop(t *testing.T) {
	now := time.Unix(1717171717, 0)
	ns := zone.NewNetworkState()
	addIPsecNode(t, ns, "node-a.catofes.", RoleBoth, []AddressAdvertisement{{
		ID: "a-public", Source: SourceManualAddress, Address: "198.51.100.10", Priority: 100, TTLSeconds: 300,
	}}, now)
	addIPsecNode(t, ns, "node-b.catofes.", RoleBoth, []AddressAdvertisement{{
		ID: "b-public", Source: SourceManualAddress, Address: "198.51.100.20", Priority: 100, TTLSeconds: 300,
	}}, now)
	group := LinkGroupSpec{ID: "ipsec-main"}
	plan, err := PlanTransportLinks(context.TODO(), ns, "node-b.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks: %v", err)
	}
	if len(plan.Desired) != 1 || plan.Roles[plan.Desired[0].TransportID] != InitiatorRoleSecondaryStandby {
		t.Fatalf("expected one secondary-standby desired spec: %+v", plan)
	}
	spec := plan.Desired[0]
	result := ReconcileLinkInstances(ReconcileInputs{
		Desired:      []TransportLinkSpec{spec},
		Instances:    map[string]LinkInstance{},
		SAs:          nil,
		Now:          now,
		Roles:        plan.Roles,
		GroupBackoff: map[string]BackoffPolicy{group.ID: group.Reconcile.Backoff},
	})
	if len(result.Actions) != 1 || result.Actions[0].Action != ReconcileActionNoop || result.Actions[0].Reason != "bidirectional_standby" {
		t.Fatalf("expected standby noop, got %+v", result.Actions)
	}
	inst := result.Instances[LinkInstanceID(spec)]
	if inst.ActualState != LinkStateDown || inst.InitiatorRole != InitiatorRoleSecondaryStandby {
		t.Fatalf("instance = %+v", inst)
	}
}

func TestReconcileSecondaryStandbyRepairsMissingDriverStateWithoutTakeover(t *testing.T) {
	now := time.Unix(1717171717, 0)
	ns := zone.NewNetworkState()
	addIPsecNode(t, ns, "node-a.catofes.", RoleBoth, []AddressAdvertisement{{
		ID: "a-public", Source: SourceManualAddress, Address: "198.51.100.10", Priority: 100, TTLSeconds: 300,
	}}, now)
	addIPsecNode(t, ns, "node-b.catofes.", RoleBoth, []AddressAdvertisement{{
		ID: "b-public", Source: SourceManualAddress, Address: "198.51.100.20", Priority: 100, TTLSeconds: 300,
	}}, now)
	group := LinkGroupSpec{ID: "ipsec-main"}
	plan, err := PlanTransportLinks(context.TODO(), ns, "node-b.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks: %v", err)
	}
	spec := plan.Desired[0]
	inst := NewLinkInstance(spec, LinkStateDown, now.Add(-time.Minute))
	inst.InitiatorRole = InitiatorRoleSecondaryStandby
	inst.ActualState = LinkStateDegraded
	inst.LastError = "xfrm namespace or interface missing"

	result := ReconcileLinkInstances(ReconcileInputs{
		Desired:      []TransportLinkSpec{spec},
		Instances:    map[string]LinkInstance{inst.ID: inst},
		SAs:          nil,
		Now:          now,
		Roles:        plan.Roles,
		GroupBackoff: map[string]BackoffPolicy{group.ID: group.Reconcile.Backoff},
	})
	if len(result.Actions) != 1 || result.Actions[0].Action != ReconcileActionUpdate || result.Actions[0].Reason != "standby driver state missing" {
		t.Fatalf("expected standby update, got %+v", result.Actions)
	}
	got := result.Instances[inst.ID]
	if got.InitiatorRole != InitiatorRoleSecondaryStandby || got.TakeoverPhase != TakeoverPhaseIdle {
		t.Fatalf("instance = %+v, want standby without takeover", got)
	}
}

func TestReconcileSecondaryTakeoverAfterDelay(t *testing.T) {
	base := time.Unix(1717171717, 0)
	ns := zone.NewNetworkState()
	addIPsecNode(t, ns, "node-a.catofes.", RoleBoth, []AddressAdvertisement{{
		ID: "a-public", Source: SourceManualAddress, Address: "198.51.100.10", Priority: 100, TTLSeconds: 300,
	}}, base)
	addIPsecNode(t, ns, "node-b.catofes.", RoleBoth, []AddressAdvertisement{{
		ID: "b-public", Source: SourceManualAddress, Address: "198.51.100.20", Priority: 100, TTLSeconds: 300,
	}}, base)
	group := LinkGroupSpec{ID: "ipsec-main"}
	plan, err := PlanTransportLinks(context.TODO(), ns, "node-b.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{Now: base})
	if err != nil {
		t.Fatalf("PlanTransportLinks: %v", err)
	}
	spec := plan.Desired[0]
	// First reconcile creates the standby instance.
	result := ReconcileLinkInstances(ReconcileInputs{
		Desired:      []TransportLinkSpec{spec},
		Instances:    map[string]LinkInstance{},
		SAs:          nil,
		Now:          base,
		Roles:        plan.Roles,
		GroupBackoff: map[string]BackoffPolicy{group.ID: group.Reconcile.Backoff},
	})
	inst := result.Instances[LinkInstanceID(spec)]
	// Before delay has passed, takeover is suppressed.
	result = ReconcileLinkInstances(ReconcileInputs{
		Desired:      []TransportLinkSpec{spec},
		Instances:    map[string]LinkInstance{inst.ID: inst},
		SAs:          nil,
		Now:          base.Add(30 * time.Second),
		Roles:        plan.Roles,
		GroupBackoff: map[string]BackoffPolicy{group.ID: group.Reconcile.Backoff},
	})
	if len(result.Actions) != 1 || result.Actions[0].Reason != "takeover_delay_active" {
		t.Fatalf("expected takeover_delay_active, got %+v", result.Actions)
	}
	// After the conservative delay, secondary takes over.
	result = ReconcileLinkInstances(ReconcileInputs{
		Desired:      []TransportLinkSpec{spec},
		Instances:    map[string]LinkInstance{inst.ID: inst},
		SAs:          nil,
		Now:          base.Add(2 * time.Minute),
		Roles:        plan.Roles,
		GroupBackoff: map[string]BackoffPolicy{group.ID: group.Reconcile.Backoff},
	})
	if len(result.Actions) != 1 || result.Actions[0].Action != ReconcileActionCreate || result.Actions[0].Reason != "secondary_takeover" {
		t.Fatalf("expected secondary_takeover create, got %+v", result.Actions)
	}
	if result.Actions[0].Spec == nil || result.Actions[0].Spec.InitiatorRole != InitiatorRoleSecondaryTakeover {
		t.Fatalf("takeover action spec = %+v, want secondary takeover role", result.Actions[0].Spec)
	}
	inst = result.Instances[LinkInstanceID(spec)]
	if inst.InitiatorRole != InitiatorRoleSecondaryTakeover || inst.ActualState != LinkStateConfiguring || inst.TakeoverPhase != TakeoverPhaseActive {
		t.Fatalf("instance = %+v", inst)
	}
}

func TestReconcileSecondaryTakeoverCooldownPreventsRetry(t *testing.T) {
	base := time.Unix(1717171717, 0)
	ns := zone.NewNetworkState()
	addIPsecNode(t, ns, "node-a.catofes.", RoleBoth, []AddressAdvertisement{{
		ID: "a-public", Source: SourceManualAddress, Address: "198.51.100.10", Priority: 100, TTLSeconds: 300,
	}}, base)
	addIPsecNode(t, ns, "node-b.catofes.", RoleBoth, []AddressAdvertisement{{
		ID: "b-public", Source: SourceManualAddress, Address: "198.51.100.20", Priority: 100, TTLSeconds: 300,
	}}, base)
	group := LinkGroupSpec{ID: "ipsec-main"}
	plan, err := PlanTransportLinks(context.TODO(), ns, "node-b.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{Now: base})
	if err != nil {
		t.Fatalf("PlanTransportLinks: %v", err)
	}
	spec := plan.Desired[0]
	inst := NewLinkInstance(spec, LinkStateDown, base)
	inst.InitiatorRole = InitiatorRoleSecondaryStandby
	inst.LastTransition = base.Unix()

	// Trigger takeover.
	result := ReconcileLinkInstances(ReconcileInputs{
		Desired:      []TransportLinkSpec{spec},
		Instances:    map[string]LinkInstance{inst.ID: inst},
		SAs:          nil,
		Now:          base.Add(2 * time.Minute),
		Roles:        plan.Roles,
		GroupBackoff: map[string]BackoffPolicy{group.ID: group.Reconcile.Backoff},
	})
	inst = result.Instances[LinkInstanceID(spec)]
	if inst.InitiatorRole != InitiatorRoleSecondaryTakeover {
		t.Fatalf("expected takeover, got %+v", inst)
	}
	// Simulate apply failure: cooldown is set by the daemon, but we can set it directly.
	inst.ActualState = LinkStateError
	inst.FailureCount = 1
	inst.LastError = "ike timeout"
	inst.TakeoverPhase = TakeoverPhaseCooldown
	inst.TakeoverUntil = base.Add(3 * time.Minute).Unix()

	result = ReconcileLinkInstances(ReconcileInputs{
		Desired:      []TransportLinkSpec{spec},
		Instances:    map[string]LinkInstance{inst.ID: inst},
		SAs:          nil,
		Now:          base.Add(2*time.Minute + 30*time.Second),
		Roles:        plan.Roles,
		GroupBackoff: map[string]BackoffPolicy{group.ID: group.Reconcile.Backoff},
	})
	if len(result.Actions) != 1 || result.Actions[0].Reason != "takeover_cooldown_active" {
		t.Fatalf("expected cooldown noop, got %+v", result.Actions)
	}
}

func TestReconcileTakeoverAdoptsExistingSA(t *testing.T) {
	now := time.Unix(1717171717, 0)
	ns := zone.NewNetworkState()
	addIPsecNode(t, ns, "node-a.catofes.", RoleBoth, []AddressAdvertisement{{
		ID: "a-public", Source: SourceManualAddress, Address: "198.51.100.10", Priority: 100, TTLSeconds: 300,
	}}, now)
	addIPsecNode(t, ns, "node-b.catofes.", RoleBoth, []AddressAdvertisement{{
		ID: "b-public", Source: SourceManualAddress, Address: "198.51.100.20", Priority: 100, TTLSeconds: 300,
	}}, now)
	group := LinkGroupSpec{ID: "ipsec-main"}
	plan, err := PlanTransportLinks(context.TODO(), ns, "node-b.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks: %v", err)
	}
	spec := plan.Desired[0]
	inst := NewLinkInstance(spec, LinkStateDown, now)
	inst.InitiatorRole = InitiatorRoleSecondaryStandby

	result := ReconcileLinkInstances(ReconcileInputs{
		Desired:      []TransportLinkSpec{spec},
		Instances:    map[string]LinkInstance{inst.ID: inst},
		SAs:          []SAState{{Name: spec.TransportID, Established: true, Endpoint: "198.51.100.10:500"}},
		Now:          now,
		Roles:        plan.Roles,
		GroupBackoff: map[string]BackoffPolicy{group.ID: group.Reconcile.Backoff},
	})
	if len(result.Actions) != 1 || result.Actions[0].Action != ReconcileActionAdopt {
		t.Fatalf("expected adopt, got %+v", result.Actions)
	}
	inst = result.Instances[LinkInstanceID(spec)]
	if inst.ActualState != LinkStateUp || inst.InitiatorRole != InitiatorRoleConverged || inst.Endpoint != "198.51.100.10:500" {
		t.Fatalf("instance = %+v", inst)
	}
}

func TestReconcileTakeoverForbiddenByRevocation(t *testing.T) {
	now := time.Unix(1717171717, 0)
	ns := zone.NewNetworkState()
	addIPsecNode(t, ns, "node-a.catofes.", RoleBoth, []AddressAdvertisement{{
		ID: "a-public", Source: SourceManualAddress, Address: "198.51.100.10", Priority: 100, TTLSeconds: 300,
	}}, now)
	addIPsecNode(t, ns, "node-b.catofes.", RoleBoth, []AddressAdvertisement{{
		ID: "b-public", Source: SourceManualAddress, Address: "198.51.100.20", Priority: 100, TTLSeconds: 300,
	}}, now)
	ns.Zones["catofes."] = zone.NewZoneState("catofes.", nil)
	ns.Zones["catofes."].Revocations["node-a.catofes."] = &zone.DelegationRevocation{
		ChildZone:  "node-a.catofes.",
		ParentZone: "catofes.",
		RevokedAt:  now.Add(-time.Minute).Unix(),
	}
	group := LinkGroupSpec{ID: "ipsec-main"}
	plan, err := PlanTransportLinks(context.TODO(), ns, "node-b.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks: %v", err)
	}
	if len(plan.Desired) != 0 {
		t.Fatalf("planner should skip revoked peer")
	}
}
