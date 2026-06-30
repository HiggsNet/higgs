package ipsec

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/Catofes/higgs/pkg/core/zone"
)

func TestRotateConnectionNameStable(t *testing.T) {
	base := "ipsec-deadbeef"
	if got := RotateConnectionName(base, 3); got != "ipsec-deadbeef-r3" {
		t.Fatalf("RotateConnectionName = %q", got)
	}
	if got := RotateChildSAName(base, 3); got != "ipsec-deadbeef-r3-child" {
		t.Fatalf("RotateChildSAName = %q", got)
	}
}

func stagedRuntimeID(inst LinkInstance, generation uint64) string {
	return RuntimeConnectionID(firstNonEmptyString(inst.LinkID, inst.ID), generation, inst.TransportKind)
}

func runtimeSpecForPortGeneration(spec TransportLinkSpec, generation uint64) TransportLinkSpec {
	spec.Generation = generation
	runtimeGeneration := runtimeGenerationForPortGeneration(generation)
	spec.AddressEpoch = runtimeGeneration
	if spec.LinkID != "" {
		spec.TransportID = RuntimeConnectionID(spec.LinkID, runtimeGeneration, spec.Provider)
		spec.XFRMIfID = RuntimeXFRMIfID(spec.LinkID, runtimeGeneration, spec.Provider)
	} else {
		spec.XFRMIfID = StableXFRMIfID(spec.LocalZone, spec.PeerZone, spec.TransportID)
	}
	spec.InterfaceName = StableInterfaceName(spec.XFRMIfID)
	return spec
}

func TestRotateSpecUsesIndependentXFRMInterface(t *testing.T) {
	spec := TransportLinkSpec{
		LocalZone:     "node-a.catofes.",
		PeerZone:      "node-b.catofes.",
		TransportID:   "ipsec-main-ab",
		InterfaceName: "hgs1",
		XFRMIfID:      77,
		ContactPoints: []ContactPoint{{
			Address:    "198.51.100.20",
			Family:     FamilyIPv4,
			Generation: 2,
			IKEPort:    DefaultIKEPort,
			NATTPort:   DefaultNATTPort,
		}},
	}
	staged := rotateSpec(spec, 2)
	if staged.TransportID != RotateConnectionName(spec.TransportID, 2) {
		t.Fatalf("staged transport id = %q", staged.TransportID)
	}
	if staged.XFRMIfID == 0 || staged.XFRMIfID == spec.XFRMIfID {
		t.Fatalf("staged if_id = %d, want independent from %d", staged.XFRMIfID, spec.XFRMIfID)
	}
	if staged.InterfaceName == "" || staged.InterfaceName == spec.InterfaceName {
		t.Fatalf("staged interface = %q, want independent from %q", staged.InterfaceName, spec.InterfaceName)
	}
}

func TestTransportLinkSpecHashIgnoresRuntimeQuality(t *testing.T) {
	now := time.Unix(1717171717, 0)
	spec := TransportLinkSpec{
		LocalZone:     "node-a.catofes.",
		PeerZone:      "node-b.catofes.",
		TransportID:   "ipsec-main-ab",
		InterfaceName: "hgs1",
		XFRMIfID:      77,
		ContactPoints: []ContactPoint{{
			Address:      "198.51.100.20",
			Family:       FamilyIPv4,
			Generation:   2,
			IKEPort:      DefaultIKEPort,
			NATTPort:     DefaultNATTPort,
			Successes:    5,
			Failures:     2,
			BackoffUntil: now.Add(time.Minute),
			LastError:    "timeout",
			RankReason:   "recent success",
		}},
	}
	base := TransportLinkSpecHash(spec)

	spec.ContactPoints[0].Successes = 10
	spec.ContactPoints[0].Failures = 0
	spec.ContactPoints[0].BackoffUntil = now.Add(2 * time.Minute)
	spec.ContactPoints[0].LastError = ""
	spec.ContactPoints[0].RankReason = "best"
	if got := TransportLinkSpecHash(spec); got != base {
		t.Fatalf("hash changed after quality updates: %q != %q", got, base)
	}

	spec.ContactPoints[0].Address = "198.51.100.21"
	if got := TransportLinkSpecHash(spec); got == base {
		t.Fatalf("hash unchanged after address change")
	}
}

func TestRotateSpecForSecondaryStandbyUsesInboundTrap(t *testing.T) {
	spec := TransportLinkSpec{
		LocalZone:     "node-b.catofes.",
		PeerZone:      "node-a.catofes.",
		InitiatorRole: InitiatorRolePrimary,
		TransportID:   "ipsec-main-ba",
		InterfaceName: "hgs1",
		XFRMIfID:      77,
		ContactPoints: []ContactPoint{{
			Address:    "198.51.100.10",
			Family:     FamilyIPv4,
			Generation: 2,
			IKEPort:    DefaultIKEPort,
			NATTPort:   DefaultNATTPort,
		}},
	}

	staged := rotateSpecForRole(spec, 2, InitiatorRoleSecondaryStandby)
	if len(staged.ContactPoints) != 0 {
		t.Fatalf("standby staged contacts = %+v, want responder-only config", staged.ContactPoints)
	}

	active := rotateSpecForRole(spec, 2, InitiatorRolePrimary)
	if len(active.ContactPoints) != 1 {
		t.Fatalf("active staged contacts = %+v, want preserved contact point", active.ContactPoints)
	}
}

func TestReconcilePrepareRotateOnGenerationChange(t *testing.T) {
	now := time.Unix(1717171717, 0)
	ns := zone.NewNetworkState()
	addIPsecNode(t, ns, "node-b.catofes.", AcceptInbound, []AddressAdvertisement{{
		ID: "b-public", Source: SourceManualAddress, Address: "198.51.100.20", Priority: 100, TTLSeconds: 300,
	}}, now)
	addIPsecNode(t, ns, "node-a.catofes.", AcceptNone, []AddressAdvertisement{{
		ID: "a-public", Source: SourceManualAddress, Address: "198.51.100.10", Priority: 100, TTLSeconds: 300,
	}}, now)
	group := LinkGroupSpec{ID: "ipsec-main"}
	plan, err := PlanTransportLinks(context.TODO(), ns, "node-a.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks: %v", err)
	}
	if len(plan.Desired) != 1 {
		t.Fatalf("desired len = %d", len(plan.Desired))
	}
	spec := plan.Desired[0]

	// Existing instance is on generation 1.
	existing := NewLinkInstance(spec, LinkStateUp, now)
	if existing.RemoteGeneration != 1 {
		t.Fatalf("existing.RemoteGeneration = %d, want 1", existing.RemoteGeneration)
	}

	// Planner now sees generation 2 (peer published a rotated port record).
	addIPsecNode(t, ns, "node-b.catofes.", AcceptInbound, []AddressAdvertisement{{
		ID: "b-public", Source: SourceManualAddress, Address: "198.51.100.20", Priority: 100, TTLSeconds: 300,
	}}, now)
	ns.Zones["node-b.catofes."].Records[RecordKeyPorts] = record(t, "node-b.catofes.", RecordKeyPorts, RecordTypePorts, PortRecord{
		Version: 1,
		Mode:    PortModeFixed,
		Current: &PortSelection{
			Generation: 2,
			IKE:        PortBinding{Advertised: DefaultIKEPort},
			NATT:       PortBinding{Advertised: 4501},
		},
		UpdatedAt: now.Unix(),
	})
	plan2, err := PlanTransportLinks(context.TODO(), ns, "node-a.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks: %v", err)
	}
	if len(plan2.Desired) != 1 {
		t.Fatalf("desired len = %d", len(plan2.Desired))
	}
	newSpec := plan2.Desired[0]
	if contactGeneration(newSpec) != 2 {
		t.Fatalf("new spec generation = %d, want 2", contactGeneration(newSpec))
	}

	result := ReconcileLinkInstances(ReconcileInputs{
		Desired:   []TransportLinkSpec{newSpec},
		Instances: map[string]LinkInstance{existing.ID: existing},
		SAs:       []SAState{{Name: existing.IKEName, Established: true}},
		Now:       now,
	})

	action := firstAction(result, ReconcileActionPrepareRotate)
	if action == nil {
		t.Fatalf("expected prepare_rotate action, got %+v", result.Actions)
	}
	if action.Spec == nil {
		t.Fatalf("prepare_rotate action missing spec")
	}
	if action.Spec.TransportID != RuntimeConnectionID(existing.LinkID, 2, existing.TransportKind) {
		t.Fatalf("staged transport id = %q, want %q", action.Spec.TransportID, RuntimeConnectionID(existing.LinkID, 2, existing.TransportKind))
	}
	inst := result.Instances[existing.ID]
	if inst.RotatePhase != RotatePhasePreparing {
		t.Fatalf("rotate phase = %q, want preparing", inst.RotatePhase)
	}
	if inst.StagedGeneration != 2 {
		t.Fatalf("staged generation = %d, want 2", inst.StagedGeneration)
	}
	if inst.StagedIKEName != RuntimeConnectionID(existing.LinkID, 2, existing.TransportKind) {
		t.Fatalf("staged ike name = %q", inst.StagedIKEName)
	}
	if inst.StagedInterfaceName == "" || inst.StagedInterfaceName == existing.InterfaceName {
		t.Fatalf("staged interface = %q, want independent from %q", inst.StagedInterfaceName, existing.InterfaceName)
	}
	if inst.StagedXFRMIfID == 0 || inst.StagedXFRMIfID == existing.XFRMIfID {
		t.Fatalf("staged if_id = %d, want independent from %d", inst.StagedXFRMIfID, existing.XFRMIfID)
	}
	if inst.RemoteGeneration != 1 {
		t.Fatalf("remote generation changed before commit = %d", inst.RemoteGeneration)
	}
}

func TestReconcileSecondaryStandbyPreparesResponderRotate(t *testing.T) {
	now := time.Unix(1717171717, 0)
	ns := zone.NewNetworkState()
	addIPsecNode(t, ns, "node-a.catofes.", AcceptBidirectional, []AddressAdvertisement{{
		ID: "a-public", Source: SourceManualAddress, Address: "198.51.100.10", Priority: 100, TTLSeconds: 300,
	}}, now)
	addIPsecNode(t, ns, "node-b.catofes.", AcceptBidirectional, []AddressAdvertisement{{
		ID: "b-public", Source: SourceManualAddress, Address: "198.51.100.20", Priority: 100, TTLSeconds: 300,
	}}, now)
	ns.Zones["node-b.catofes."].Records[RecordKeyPorts] = record(t, "node-b.catofes.", RecordKeyPorts, RecordTypePorts, PortRecord{
		Version: 1,
		Mode:    PortModeFixed,
		Current: &PortSelection{
			Generation: 2,
			IKE:        PortBinding{Advertised: DefaultIKEPort},
			NATT:       PortBinding{Advertised: 4501},
		},
		UpdatedAt: now.Unix(),
	})
	group := LinkGroupSpec{ID: "ipsec-main"}
	plan, err := PlanTransportLinks(context.TODO(), ns, "node-b.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks: %v", err)
	}
	if len(plan.Desired) != 1 || plan.Roles[plan.Desired[0].TransportID] != InitiatorRoleSecondaryStandby {
		t.Fatalf("expected secondary standby plan: %+v", plan)
	}
	spec := plan.Desired[0]
	existing := NewLinkInstance(spec, LinkStateUp, now)
	existing.RemoteGeneration = 1
	existing.InitiatorRole = InitiatorRoleConverged

	result := ReconcileLinkInstances(ReconcileInputs{
		Desired:   []TransportLinkSpec{spec},
		Instances: map[string]LinkInstance{existing.ID: existing},
		SAs:       []SAState{{Name: existing.IKEName, Established: true}},
		Now:       now,
		Roles:     plan.Roles,
	})

	action := firstAction(result, ReconcileActionPrepareRotate)
	if action == nil || action.Spec == nil {
		t.Fatalf("expected prepare_rotate, got %+v", result.Actions)
	}
	if action.Spec.InitiatorRole != InitiatorRoleSecondaryStandby {
		t.Fatalf("staged role = %q, want secondary-standby", action.Spec.InitiatorRole)
	}
	if len(action.Spec.ContactPoints) != 0 {
		t.Fatalf("staged contacts = %+v, want responder-only config", action.Spec.ContactPoints)
	}
	inst := result.Instances[existing.ID]
	if inst.RotatePhase != RotatePhasePreparing || inst.StagedGeneration != 2 {
		t.Fatalf("instance = %+v", inst)
	}
}

func TestReconcileRetainsOldGenerationAfterStagedSAObserved(t *testing.T) {
	now := time.Unix(1717171717, 0)
	ns := zone.NewNetworkState()
	addIPsecNode(t, ns, "node-b.catofes.", AcceptInbound, []AddressAdvertisement{{
		ID: "b-public", Source: SourceManualAddress, Address: "198.51.100.20", Priority: 100, TTLSeconds: 300,
	}}, now)
	ns.Zones["node-b.catofes."].Records[RecordKeyPorts] = record(t, "node-b.catofes.", RecordKeyPorts, RecordTypePorts, PortRecord{
		Version: 1,
		Mode:    PortModeFixed,
		Current: &PortSelection{
			Generation: 2,
			IKE:        PortBinding{Advertised: DefaultIKEPort},
			NATT:       PortBinding{Advertised: 4501},
		},
		UpdatedAt: now.Unix(),
	})
	addIPsecNode(t, ns, "node-a.catofes.", AcceptNone, []AddressAdvertisement{{
		ID: "a-public", Source: SourceManualAddress, Address: "198.51.100.10", Priority: 100, TTLSeconds: 300,
	}}, now)
	group := LinkGroupSpec{ID: "ipsec-main"}
	plan, err := PlanTransportLinks(context.TODO(), ns, "node-a.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks: %v", err)
	}
	newSpec := plan.Desired[0]

	existing := NewLinkInstance(runtimeSpecForPortGeneration(newSpec, 1), LinkStateUp, now)
	existing.RemoteGeneration = 1
	existing.StagedGeneration = 2
	existing.StagedIKEName = stagedRuntimeID(existing, 2)
	existing.StagedChildSAName = existing.StagedIKEName + "-child"
	existing.RotatePhase = RotatePhaseTestingNew
	existing.RotateDeadline = now.Add(time.Minute).Unix()

	result := ReconcileLinkInstances(ReconcileInputs{
		Desired:   []TransportLinkSpec{newSpec},
		Instances: map[string]LinkInstance{existing.ID: existing},
		SAs: []SAState{
			{Name: existing.IKEName, Established: true},
			{Name: existing.StagedIKEName, Established: true},
		},
		Now: now,
	})

	action := firstAction(result, ReconcileActionNoop)
	if action == nil {
		t.Fatalf("expected noop while rotate retention is active, got %+v", result.Actions)
	}
	inst := result.Instances[existing.ID]
	if inst.RemoteGeneration != 1 {
		t.Fatalf("remote generation changed during retention = %d", inst.RemoteGeneration)
	}
	if inst.StagedGeneration != 2 {
		t.Fatalf("staged generation = %d, want retained staged generation", inst.StagedGeneration)
	}
	if inst.IKEName != existing.IKEName {
		t.Fatalf("ike name = %q, want old generation %q", inst.IKEName, existing.IKEName)
	}
	if inst.InterfaceName != existing.InterfaceName {
		t.Fatalf("interface = %q, want old interface %q", inst.InterfaceName, existing.InterfaceName)
	}
	if inst.RotatePhase != RotatePhaseDualRunning {
		t.Fatalf("rotate phase = %q, want dual_running", inst.RotatePhase)
	}
	if inst.RotateDeadline != now.Add(time.Hour).Unix() {
		t.Fatalf("rotate deadline = %d, want default 1h retention", inst.RotateDeadline)
	}
}

func TestReconcileSecondaryStandbyDoesNotTakeoverDuringRotateRetention(t *testing.T) {
	now := time.Unix(1717171717, 0)
	ns := zone.NewNetworkState()
	addIPsecNode(t, ns, "node-a.catofes.", AcceptBidirectional, []AddressAdvertisement{{
		ID: "a-public", Source: SourceManualAddress, Address: "198.51.100.10", Priority: 100, TTLSeconds: 300,
	}}, now)
	addIPsecNode(t, ns, "node-b.catofes.", AcceptBidirectional, []AddressAdvertisement{{
		ID: "b-public", Source: SourceManualAddress, Address: "198.51.100.20", Priority: 100, TTLSeconds: 300,
	}}, now)
	group := LinkGroupSpec{ID: "ipsec-main"}
	plan, err := PlanTransportLinks(context.TODO(), ns, "node-b.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks: %v", err)
	}
	if len(plan.Desired) != 1 || plan.Roles[plan.Desired[0].TransportID] != InitiatorRoleSecondaryStandby {
		t.Fatalf("expected secondary standby plan: %+v", plan)
	}
	spec := plan.Desired[0]
	inst := NewLinkInstance(spec, LinkStateDown, now)
	inst.InitiatorRole = InitiatorRoleSecondaryStandby
	inst.LastTransition = now.Add(-10 * time.Minute).Unix()
	inst.StagedGeneration = 2
	inst.StagedIKEName = RotateConnectionName(inst.TransportID, 2)
	inst.StagedChildSAName = RotateChildSAName(inst.TransportID, 2)
	inst.RotatePhase = RotatePhaseDualRunning
	inst.RotateDeadline = now.Add(time.Hour).Unix()

	result := ReconcileLinkInstances(ReconcileInputs{
		Desired:      []TransportLinkSpec{spec},
		Instances:    map[string]LinkInstance{inst.ID: inst},
		SAs:          nil,
		Now:          now,
		Roles:        plan.Roles,
		GroupBackoff: map[string]BackoffPolicy{group.ID: group.Reconcile.Backoff},
	})
	if len(result.Actions) != 1 || result.Actions[0].Action != ReconcileActionNoop || result.Actions[0].Reason != "rotate_retention_active" {
		t.Fatalf("expected rotate retention noop, got %+v", result.Actions)
	}
	got := result.Instances[inst.ID]
	if got.InitiatorRole != InitiatorRoleSecondaryStandby || got.TakeoverPhase != TakeoverPhaseIdle {
		t.Fatalf("takeover state changed during rotate retention: %+v", got)
	}
}

func TestReconcileCommitsRotateAfterRetentionExpires(t *testing.T) {
	now := time.Unix(1717171717, 0)
	ns := zone.NewNetworkState()
	addIPsecNode(t, ns, "node-b.catofes.", AcceptInbound, []AddressAdvertisement{{
		ID: "b-public", Source: SourceManualAddress, Address: "198.51.100.20", Priority: 100, TTLSeconds: 300,
	}}, now)
	ns.Zones["node-b.catofes."].Records[RecordKeyPorts] = record(t, "node-b.catofes.", RecordKeyPorts, RecordTypePorts, PortRecord{
		Version: 1,
		Mode:    PortModeFixed,
		Current: &PortSelection{
			Generation: 2,
			IKE:        PortBinding{Advertised: DefaultIKEPort},
			NATT:       PortBinding{Advertised: 4501},
		},
		UpdatedAt: now.Unix(),
	})
	addIPsecNode(t, ns, "node-a.catofes.", AcceptNone, []AddressAdvertisement{{
		ID: "a-public", Source: SourceManualAddress, Address: "198.51.100.10", Priority: 100, TTLSeconds: 300,
	}}, now)
	group := LinkGroupSpec{ID: "ipsec-main"}
	plan, err := PlanTransportLinks(context.TODO(), ns, "node-a.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks: %v", err)
	}
	newSpec := plan.Desired[0]

	existing := NewLinkInstance(runtimeSpecForPortGeneration(newSpec, 1), LinkStateUp, now)
	existing.RemoteGeneration = 1
	existing.StagedGeneration = 2
	existing.StagedIKEName = stagedRuntimeID(existing, 2)
	existing.StagedChildSAName = existing.StagedIKEName + "-child"
	stagedSpec := rotateSpec(newSpec, 2)
	existing.StagedInterfaceName = stagedSpec.InterfaceName
	existing.StagedXFRMIfID = stagedSpec.XFRMIfID
	existing.RotatePhase = RotatePhaseDualRunning
	existing.RotateDeadline = now.Add(-time.Second).Unix()

	result := ReconcileLinkInstances(ReconcileInputs{
		Desired:   []TransportLinkSpec{newSpec},
		Instances: map[string]LinkInstance{existing.ID: existing},
		SAs: []SAState{
			{Name: existing.IKEName, Established: true},
			{Name: existing.StagedIKEName, Established: true},
		},
		Now: now,
	})

	action := firstAction(result, ReconcileActionCommitRotate)
	if action == nil {
		t.Fatalf("expected commit_rotate after retention expiry, got %+v", result.Actions)
	}
	inst := result.Instances[existing.ID]
	if inst.RemoteGeneration != 2 {
		t.Fatalf("remote generation = %d, want 2", inst.RemoteGeneration)
	}
	if inst.StagedGeneration != 0 {
		t.Fatalf("staged generation not cleared = %d", inst.StagedGeneration)
	}
	if inst.IKEName != stagedRuntimeID(existing, 2) {
		t.Fatalf("ike name = %q, want rotated", inst.IKEName)
	}
	if inst.InterfaceName != stagedSpec.InterfaceName {
		t.Fatalf("interface = %q, want promoted staged interface %q", inst.InterfaceName, stagedSpec.InterfaceName)
	}
	if inst.XFRMIfID != stagedSpec.XFRMIfID {
		t.Fatalf("if_id = %d, want promoted staged if_id %d", inst.XFRMIfID, stagedSpec.XFRMIfID)
	}
}

func TestReconcileHoldsRotateWhenRouteCutoverPending(t *testing.T) {
	now := time.Unix(1717171717, 0)
	ns := zone.NewNetworkState()
	addIPsecNode(t, ns, "node-b.catofes.", AcceptInbound, []AddressAdvertisement{{
		ID: "b-public", Source: SourceManualAddress, Address: "198.51.100.20", Priority: 100, TTLSeconds: 300,
	}}, now)
	ns.Zones["node-b.catofes."].Records[RecordKeyPorts] = record(t, "node-b.catofes.", RecordKeyPorts, RecordTypePorts, PortRecord{
		Version: 1,
		Mode:    PortModeFixed,
		Current: &PortSelection{
			Generation: 2,
			IKE:        PortBinding{Advertised: DefaultIKEPort},
			NATT:       PortBinding{Advertised: 4501},
		},
		UpdatedAt: now.Unix(),
	})
	addIPsecNode(t, ns, "node-a.catofes.", AcceptNone, []AddressAdvertisement{{
		ID: "a-public", Source: SourceManualAddress, Address: "198.51.100.10", Priority: 100, TTLSeconds: 300,
	}}, now)
	group := LinkGroupSpec{ID: "ipsec-main"}
	plan, err := PlanTransportLinks(context.TODO(), ns, "node-a.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks: %v", err)
	}
	newSpec := plan.Desired[0]
	stagedSpec := rotateSpec(newSpec, 2)

	existing := NewLinkInstance(runtimeSpecForPortGeneration(newSpec, 1), LinkStateUp, now)
	existing.RemoteGeneration = 1
	existing.StagedGeneration = 2
	existing.StagedIKEName = stagedSpec.TransportID
	existing.StagedChildSAName = ChildSAName(stagedSpec)
	existing.StagedInterfaceName = stagedSpec.InterfaceName
	existing.StagedXFRMIfID = stagedSpec.XFRMIfID
	existing.RotatePhase = RotatePhaseDualRunning
	existing.RotateDeadline = now.Add(-time.Second).Unix()

	result := ReconcileLinkInstances(ReconcileInputs{
		Desired:   []TransportLinkSpec{newSpec},
		Instances: map[string]LinkInstance{existing.ID: existing},
		SAs: []SAState{
			{Name: existing.IKEName, Established: true},
			{Name: existing.StagedIKEName, Established: true},
		},
		Now:                now,
		RotateCutoverReady: map[string]bool{existing.ID: false},
	})

	if len(result.Actions) != 1 || result.Actions[0].Action != ReconcileActionNoop || result.Actions[0].Reason != "route_cutover_pending" {
		t.Fatalf("expected route cutover pending noop, got %+v", result.Actions)
	}
	inst := result.Instances[existing.ID]
	if inst.RemoteGeneration != 1 || inst.StagedGeneration != 2 {
		t.Fatalf("rotate generation changed before route cutover: %+v", inst)
	}
	if inst.IKEName != existing.IKEName || inst.InterfaceName != existing.InterfaceName {
		t.Fatalf("old generation was promoted before route cutover: %+v", inst)
	}
	if inst.RotatePhase != RotatePhaseDualRunning {
		t.Fatalf("rotate phase = %q, want dual_running", inst.RotatePhase)
	}
}

func TestReconcileCommitsRotateWhenOldSADisappearsDuringRetention(t *testing.T) {
	now := time.Unix(1717171717, 0)
	ns := zone.NewNetworkState()
	addIPsecNode(t, ns, "node-b.catofes.", AcceptInbound, []AddressAdvertisement{{
		ID: "b-public", Source: SourceManualAddress, Address: "198.51.100.20", Priority: 100, TTLSeconds: 300,
	}}, now)
	ns.Zones["node-b.catofes."].Records[RecordKeyPorts] = record(t, "node-b.catofes.", RecordKeyPorts, RecordTypePorts, PortRecord{
		Version: 1,
		Mode:    PortModeFixed,
		Current: &PortSelection{
			Generation: 2,
			IKE:        PortBinding{Advertised: DefaultIKEPort},
			NATT:       PortBinding{Advertised: 4501},
		},
		UpdatedAt: now.Unix(),
	})
	addIPsecNode(t, ns, "node-a.catofes.", AcceptNone, []AddressAdvertisement{{
		ID: "a-public", Source: SourceManualAddress, Address: "198.51.100.10", Priority: 100, TTLSeconds: 300,
	}}, now)
	group := LinkGroupSpec{ID: "ipsec-main"}
	plan, err := PlanTransportLinks(context.TODO(), ns, "node-a.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks: %v", err)
	}
	newSpec := plan.Desired[0]
	stagedSpec := rotateSpec(newSpec, 2)

	existing := NewLinkInstance(runtimeSpecForPortGeneration(newSpec, 1), LinkStateUp, now)
	existing.RemoteGeneration = 1
	existing.StagedGeneration = 2
	existing.StagedIKEName = stagedSpec.TransportID
	existing.StagedChildSAName = ChildSAName(stagedSpec)
	existing.StagedInterfaceName = stagedSpec.InterfaceName
	existing.StagedXFRMIfID = stagedSpec.XFRMIfID
	existing.RotatePhase = RotatePhaseDualRunning
	existing.RotateDeadline = now.Add(time.Hour).Unix()

	result := ReconcileLinkInstances(ReconcileInputs{
		Desired:   []TransportLinkSpec{newSpec},
		Instances: map[string]LinkInstance{existing.ID: existing},
		SAs: []SAState{
			{Name: existing.StagedIKEName, Established: true},
		},
		Now: now,
	})

	action := firstAction(result, ReconcileActionCommitRotate)
	if action == nil {
		t.Fatalf("expected commit_rotate when old SA disappeared, got %+v", result.Actions)
	}
	inst := result.Instances[existing.ID]
	if inst.RemoteGeneration != 2 || inst.IKEName != stagedSpec.TransportID || inst.InterfaceName != stagedSpec.InterfaceName {
		t.Fatalf("instance not promoted to staged generation: %+v", inst)
	}
}

func TestReconcileSecondaryConvergedCommitsRotateWhenOldSADisappears(t *testing.T) {
	now := time.Unix(1717171717, 0)
	ns := zone.NewNetworkState()
	addIPsecNode(t, ns, "node-a.catofes.", AcceptBidirectional, []AddressAdvertisement{{
		ID: "a-public", Source: SourceManualAddress, Address: "198.51.100.10", Priority: 100, TTLSeconds: 300,
	}}, now)
	addIPsecNode(t, ns, "node-b.catofes.", AcceptBidirectional, []AddressAdvertisement{{
		ID: "b-public", Source: SourceManualAddress, Address: "198.51.100.20", Priority: 100, TTLSeconds: 300,
	}}, now)
	ns.Zones["node-a.catofes."].Records[RecordKeyPorts] = record(t, "node-a.catofes.", RecordKeyPorts, RecordTypePorts, PortRecord{
		Version: 1,
		Mode:    PortModeFixed,
		Current: &PortSelection{
			Generation: 2,
			IKE:        PortBinding{Advertised: DefaultIKEPort},
			NATT:       PortBinding{Advertised: 4501},
		},
		UpdatedAt: now.Unix(),
	})
	group := LinkGroupSpec{ID: "ipsec-main"}
	plan, err := PlanTransportLinks(context.TODO(), ns, "node-b.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks: %v", err)
	}
	if len(plan.Desired) != 1 || plan.Roles[plan.Desired[0].TransportID] != InitiatorRoleSecondaryStandby {
		t.Fatalf("expected one secondary-standby desired spec: %+v", plan)
	}
	newSpec := plan.Desired[0]
	newSpec.Generation = 2
	stagedSpec := rotateSpecForRole(newSpec, 2, InitiatorRoleSecondaryStandby)

	existing := NewLinkInstance(runtimeSpecForPortGeneration(newSpec, 1), LinkStateUp, now)
	existing.RemoteGeneration = 1
	existing.InitiatorRole = InitiatorRoleConverged
	existing.StagedGeneration = 2
	existing.StagedIKEName = stagedSpec.TransportID
	existing.StagedChildSAName = ChildSAName(stagedSpec)
	existing.StagedInterfaceName = stagedSpec.InterfaceName
	existing.StagedXFRMIfID = stagedSpec.XFRMIfID
	existing.RotatePhase = RotatePhaseTestingNew
	existing.RotateDeadline = now.Add(-time.Minute).Unix()

	result := ReconcileLinkInstances(ReconcileInputs{
		Desired:      []TransportLinkSpec{newSpec},
		Instances:    map[string]LinkInstance{existing.ID: existing},
		SAs:          []SAState{{Name: existing.StagedIKEName, Established: true, Endpoint: "198.51.100.20:4501"}},
		Now:          now,
		Roles:        plan.Roles,
		GroupBackoff: map[string]BackoffPolicy{group.ID: group.Reconcile.Backoff},
	})

	action := firstAction(result, ReconcileActionCommitRotate)
	if action == nil {
		t.Fatalf("expected commit_rotate when secondary old SA disappeared, got %+v", result.Actions)
	}
	inst := result.Instances[existing.ID]
	if inst.RemoteGeneration != 2 || inst.StagedGeneration != 0 || inst.IKEName != stagedSpec.TransportID {
		t.Fatalf("instance not promoted to staged generation: %+v", inst)
	}
	if inst.InterfaceName != stagedSpec.InterfaceName || inst.XFRMIfID != stagedSpec.XFRMIfID {
		t.Fatalf("staged xfrm not promoted: %+v", inst)
	}
}

func TestReconcileRecoversRotatedRuntimeMetadataFromSA(t *testing.T) {
	now := time.Unix(1717171717, 0)
	spec := TransportLinkSpec{
		LocalZone:     "node-a.catofes.",
		PeerZone:      "node-b.catofes.",
		OverlayID:     "ipsec-main",
		Provider:      ProviderStrongSwan,
		LinkID:        "link-stable",
		TransportID:   RuntimeConnectionID("link-stable", 0, ProviderStrongSwan),
		InterfaceName: "hgs-old",
		XFRMIfID:      1001,
		Generation:    2,
		ContactPoints: []ContactPoint{{
			Address:    "198.51.100.20",
			Family:     FamilyIPv4,
			Generation: 2,
			IKEPort:    DefaultIKEPort,
			NATTPort:   DefaultNATTPort,
		}},
	}
	stagedSpec := rotateSpec(spec, 2)
	existing := NewLinkInstance(spec, LinkStateUp, now)
	existing.RemoteGeneration = 2
	existing.IKEName = stagedSpec.TransportID
	existing.ChildSAName = ChildSAName(stagedSpec)
	existing.InterfaceName = spec.InterfaceName
	existing.XFRMIfID = spec.XFRMIfID
	existing.DesiredSpecHash = TransportLinkSpecHash(spec)

	result := ReconcileLinkInstances(ReconcileInputs{
		Desired:   []TransportLinkSpec{spec},
		Instances: map[string]LinkInstance{existing.ID: existing},
		SAs: []SAState{{
			Name:        stagedSpec.TransportID,
			ChildSA:     ChildSAName(stagedSpec),
			XFRMIfID:    stagedSpec.XFRMIfID,
			Endpoint:    "198.51.100.20:4500",
			Established: true,
		}},
		Now: now,
	})

	if len(result.Actions) != 1 || result.Actions[0].Action != ReconcileActionAdopt || result.Actions[0].Reason != "driver runtime metadata recovered" {
		t.Fatalf("expected runtime metadata recovery adopt, got %+v", result.Actions)
	}
	inst := result.Instances[existing.ID]
	if inst.InterfaceName != stagedSpec.InterfaceName || inst.XFRMIfID != stagedSpec.XFRMIfID {
		t.Fatalf("runtime metadata not recovered: %+v, want interface %s if_id %d", inst, stagedSpec.InterfaceName, stagedSpec.XFRMIfID)
	}
}

func TestReconcileRollbackRotateOnTimeout(t *testing.T) {
	now := time.Unix(1717171717, 0)
	ns := zone.NewNetworkState()
	addIPsecNode(t, ns, "node-b.catofes.", AcceptInbound, []AddressAdvertisement{{
		ID: "b-public", Source: SourceManualAddress, Address: "198.51.100.20", Priority: 100, TTLSeconds: 300,
	}}, now)
	ns.Zones["node-b.catofes."].Records[RecordKeyPorts] = record(t, "node-b.catofes.", RecordKeyPorts, RecordTypePorts, PortRecord{
		Version: 1,
		Mode:    PortModeFixed,
		Current: &PortSelection{
			Generation: 2,
			IKE:        PortBinding{Advertised: DefaultIKEPort},
			NATT:       PortBinding{Advertised: 4501},
		},
		UpdatedAt: now.Unix(),
	})
	addIPsecNode(t, ns, "node-a.catofes.", AcceptNone, []AddressAdvertisement{{
		ID: "a-public", Source: SourceManualAddress, Address: "198.51.100.10", Priority: 100, TTLSeconds: 300,
	}}, now)
	group := LinkGroupSpec{ID: "ipsec-main"}
	plan, err := PlanTransportLinks(context.TODO(), ns, "node-a.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks: %v", err)
	}
	newSpec := plan.Desired[0]

	existing := NewLinkInstance(runtimeSpecForPortGeneration(newSpec, 1), LinkStateUp, now)
	existing.RemoteGeneration = 1
	existing.StagedGeneration = 2
	existing.StagedIKEName = stagedRuntimeID(existing, 2)
	existing.StagedChildSAName = existing.StagedIKEName + "-child"
	existing.RotatePhase = RotatePhaseTestingNew
	existing.RotateDeadline = now.Add(-time.Second).Unix()

	result := ReconcileLinkInstances(ReconcileInputs{
		Desired:   []TransportLinkSpec{newSpec},
		Instances: map[string]LinkInstance{existing.ID: existing},
		SAs:       []SAState{{Name: existing.IKEName, Established: true}},
		Now:       now,
	})

	action := firstAction(result, ReconcileActionRollbackRotate)
	if action == nil {
		t.Fatalf("expected rollback_rotate action, got %+v", result.Actions)
	}
	inst := result.Instances[existing.ID]
	if inst.RemoteGeneration != 1 {
		t.Fatalf("remote generation changed on rollback = %d", inst.RemoteGeneration)
	}
	if inst.StagedGeneration != 0 {
		t.Fatalf("staged generation not cleared = %d", inst.StagedGeneration)
	}
	if inst.RotatePhase != RotatePhaseRollback {
		t.Fatalf("rotate phase = %q, want rollback", inst.RotatePhase)
	}
}

func TestReconcileCleanupStaleStagedGeneration(t *testing.T) {
	now := time.Unix(1717171717, 0)
	ns := zone.NewNetworkState()
	addIPsecNode(t, ns, "node-b.catofes.", AcceptInbound, []AddressAdvertisement{{
		ID: "b-public", Source: SourceManualAddress, Address: "198.51.100.20", Priority: 100, TTLSeconds: 300,
	}}, now)
	ns.Zones["node-b.catofes."].Records[RecordKeyPorts] = record(t, "node-b.catofes.", RecordKeyPorts, RecordTypePorts, PortRecord{
		Version: 1,
		Mode:    PortModeFixed,
		Current: &PortSelection{
			Generation: 5,
			IKE:        PortBinding{Advertised: DefaultIKEPort},
			NATT:       PortBinding{Advertised: 4504},
		},
		UpdatedAt: now.Unix(),
	})
	addIPsecNode(t, ns, "node-a.catofes.", AcceptNone, []AddressAdvertisement{{
		ID: "a-public", Source: SourceManualAddress, Address: "198.51.100.10", Priority: 100, TTLSeconds: 300,
	}}, now)
	group := LinkGroupSpec{ID: "ipsec-main"}
	plan, err := PlanTransportLinks(context.TODO(), ns, "node-a.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks: %v", err)
	}
	newSpec := plan.Desired[0]

	existing := NewLinkInstance(newSpec, LinkStateUp, now)
	existing.RemoteGeneration = 2
	existing.StagedGeneration = 3 // stale; desired is 5
	existing.StagedIKEName = stagedRuntimeID(existing, 3)
	existing.StagedChildSAName = existing.StagedIKEName + "-child"
	existing.RotatePhase = RotatePhaseTestingNew

	result := ReconcileLinkInstances(ReconcileInputs{
		Desired:   []TransportLinkSpec{newSpec},
		Instances: map[string]LinkInstance{existing.ID: existing},
		SAs:       []SAState{{Name: existing.IKEName, Established: true}},
		Now:       now,
	})

	action := firstAction(result, ReconcileActionCleanupRotate)
	if action == nil {
		t.Fatalf("expected cleanup_rotate action, got %+v", result.Actions)
	}
	if action.Spec == nil || action.Spec.TransportID != stagedRuntimeID(existing, 3) {
		t.Fatalf("cleanup spec = %+v", action.Spec)
	}
	inst := result.Instances[existing.ID]
	if inst.RotatePhase != RotatePhaseCleanup {
		t.Fatalf("rotate phase = %q, want cleanup", inst.RotatePhase)
	}
}

func TestApplyReconcileActionPrepareRotateSkipsPrivateKeyLoad(t *testing.T) {
	spec := TransportLinkSpec{
		LocalZone:                "node-a.catofes.",
		PeerZone:                 "node-b.catofes.",
		OverlayID:                "ipsec-main",
		Provider:                 ProviderStrongSwan,
		TransportID:              "ipsec-main-ab",
		InterfaceName:            "hgs1",
		XFRMIfID:                 77,
		LocalPrivateKey:          []byte("private-key-material"),
		LocalPrivateKeyAlgorithm: AlgorithmEd25519,
		ContactPoints: []ContactPoint{{
			Address:    "198.51.100.20",
			Family:     FamilyIPv4,
			Generation: 2,
			IKEPort:    DefaultIKEPort,
			NATTPort:   4501,
		}},
	}
	stagedSpec := rotateSpec(spec, 2)
	ipsecDrv := &DryRunDriver{}
	xfrmDrv := &DryRunDriver{}
	_, err := ApplyReconcileAction(context.TODO(), ipsecDrv, xfrmDrv, ReconcileAction{
		Action: ReconcileActionPrepareRotate,
		Spec:   &stagedSpec,
	}, NetNSSpec{Kind: NetNSName, Name: "h2", Create: true})
	if err != nil {
		t.Fatalf("ApplyReconcileAction: %v", err)
	}
	if len(ipsecDrv.PrivateKeys) != 0 {
		t.Fatalf("prepare_rotate loaded private keys: %+v", ipsecDrv.PrivateKeys)
	}
	if len(ipsecDrv.Connections) != 1 || ipsecDrv.Connections[0].TransportID != stagedSpec.TransportID {
		t.Fatalf("connections = %+v", ipsecDrv.Connections)
	}
	if len(xfrmDrv.Interfaces) != 1 {
		t.Fatalf("interfaces = %+v", xfrmDrv.Interfaces)
	}
}

func TestApplyReconcileActionPrepareRotateKeepsOldSA(t *testing.T) {
	spec := TransportLinkSpec{
		LocalZone:     "node-a.catofes.",
		PeerZone:      "node-b.catofes.",
		OverlayID:     "ipsec-main",
		Provider:      ProviderStrongSwan,
		TransportID:   "ipsec-main-ab",
		InterfaceName: "hgs1",
		XFRMIfID:      77,
		InitiatorRole: InitiatorRolePrimary,
		ContactPoints: []ContactPoint{{
			Address:    "198.51.100.20",
			Family:     FamilyIPv4,
			Generation: 2,
			IKEPort:    DefaultIKEPort,
			NATTPort:   DefaultNATTPort,
		}},
	}
	stagedSpec := rotateSpec(spec, 2)
	inst := NewLinkInstance(spec, LinkStateUp, time.Unix(4100, 0))
	inst.IKEName = spec.TransportID
	inst.StagedIKEName = stagedSpec.TransportID
	inst.StagedGeneration = 2

	ipsecDrv := &DryRunDriver{}
	xfrmDrv := &DryRunDriver{}
	plan, err := ApplyReconcileAction(context.Background(), ipsecDrv, xfrmDrv, ReconcileAction{
		Action:   ReconcileActionPrepareRotate,
		Spec:     &stagedSpec,
		Instance: &inst,
	}, NetNSSpec{Kind: NetNSName, Name: "h2", Create: true})
	if err != nil {
		t.Fatalf("ApplyReconcileAction: %v", err)
	}
	if len(ipsecDrv.Terminated) != 0 {
		t.Fatalf("prepare_rotate terminated old SA: %+v", ipsecDrv.Terminated)
	}
	if len(ipsecDrv.Connections) != 1 || ipsecDrv.Connections[0].TransportID != stagedSpec.TransportID {
		t.Fatalf("connections = %+v", ipsecDrv.Connections)
	}
	if len(xfrmDrv.Interfaces) != 1 || xfrmDrv.Interfaces[0].InterfaceName != stagedSpec.InterfaceName {
		t.Fatalf("interfaces = %+v, want staged interface %s", xfrmDrv.Interfaces, stagedSpec.InterfaceName)
	}
	if len(plan.Operations) == 0 || plan.Operations[0].Action == "terminate_sa" {
		t.Fatalf("plan operations = %+v, want no old SA termination", plan.Operations)
	}
}

func TestApplyReconcileActionPrepareResponderRotateKeepsOldSA(t *testing.T) {
	spec := TransportLinkSpec{
		LocalZone:     "node-b.catofes.",
		PeerZone:      "node-a.catofes.",
		OverlayID:     "ipsec-main",
		Provider:      ProviderStrongSwan,
		TransportID:   "ipsec-main-ba",
		InterfaceName: "hgs-old",
		XFRMIfID:      77,
	}
	stagedSpec := rotateSpecForRole(spec, 2, InitiatorRoleSecondaryStandby)
	inst := NewLinkInstance(spec, LinkStateUp, time.Unix(4100, 0))
	inst.IKEName = spec.TransportID
	inst.StagedIKEName = stagedSpec.TransportID
	inst.StagedGeneration = 2

	ipsecDrv := &DryRunDriver{}
	xfrmDrv := &DryRunDriver{}
	_, err := ApplyReconcileAction(context.Background(), ipsecDrv, xfrmDrv, ReconcileAction{
		Action:   ReconcileActionPrepareRotate,
		Spec:     &stagedSpec,
		Instance: &inst,
	}, NetNSSpec{Kind: NetNSName, Name: "h2", Create: true})
	if err != nil {
		t.Fatalf("ApplyReconcileAction: %v", err)
	}
	if len(ipsecDrv.Terminated) != 0 {
		t.Fatalf("prepare_rotate terminated old SA: %+v", ipsecDrv.Terminated)
	}
	if len(ipsecDrv.Unloaded) == 0 || ipsecDrv.Unloaded[0] != spec.TransportID {
		t.Fatalf("unloaded = %+v, want old %s", ipsecDrv.Unloaded, spec.TransportID)
	}
	if len(ipsecDrv.Connections) != 1 || ipsecDrv.Connections[0].TransportID != stagedSpec.TransportID {
		t.Fatalf("connections = %+v, want staged %s", ipsecDrv.Connections, stagedSpec.TransportID)
	}
}

func TestApplyReconcileActionRepairInitiatesChild(t *testing.T) {
	spec := TransportLinkSpec{
		LocalZone:       "node-a.catofes.",
		PeerZone:        "node-b.catofes.",
		OverlayID:       "ipsec-main",
		Provider:        ProviderStrongSwan,
		TransportID:     "ipsec-main-ab",
		InterfaceName:   "hgs1",
		XFRMIfID:        77,
		InitiatorRole:   InitiatorRolePrimary,
		LocalTunnelAddr: netip.MustParseAddr("fd00:1234::1"),
		ContactPoints: []ContactPoint{{
			Address:  "198.51.100.20",
			Family:   FamilyIPv4,
			IKEPort:  DefaultIKEPort,
			NATTPort: DefaultNATTPort,
		}},
	}
	ipsecDrv := &DryRunDriver{}
	xfrmDrv := &DryRunDriver{}
	plan, err := ApplyReconcileAction(context.Background(), ipsecDrv, xfrmDrv, ReconcileAction{
		Action: ReconcileActionRepair,
		Spec:   &spec,
	}, NetNSSpec{Kind: NetNSName, Name: "h2", Create: true})
	if err != nil {
		t.Fatalf("ApplyReconcileAction: %v", err)
	}
	if len(ipsecDrv.Initiated) != 1 || ipsecDrv.Initiated[0] != ChildSAName(spec) {
		t.Fatalf("initiated = %+v", ipsecDrv.Initiated)
	}
	last := plan.Operations[len(plan.Operations)-1]
	if last.Action != "initiate_child" || last.Target != ChildSAName(spec) {
		t.Fatalf("plan = %+v", plan)
	}
}

func TestApplyReconcileActionCreateInitiatesActiveChild(t *testing.T) {
	spec := TransportLinkSpec{
		LocalZone:       "node-a.catofes.",
		PeerZone:        "node-b.catofes.",
		OverlayID:       "ipsec-main",
		Provider:        ProviderStrongSwan,
		TransportID:     "ipsec-main-ab",
		InterfaceName:   "hgs1",
		XFRMIfID:        77,
		InitiatorRole:   InitiatorRoleSecondaryTakeover,
		LocalTunnelAddr: netip.MustParseAddr("fd00:1234::1"),
		ContactPoints: []ContactPoint{{
			Address:  "198.51.100.20",
			Family:   FamilyIPv4,
			IKEPort:  DefaultIKEPort,
			NATTPort: DefaultNATTPort,
		}},
	}
	ipsecDrv := &DryRunDriver{}
	xfrmDrv := &DryRunDriver{}
	plan, err := ApplyReconcileAction(context.Background(), ipsecDrv, xfrmDrv, ReconcileAction{
		Action: ReconcileActionCreate,
		Spec:   &spec,
	}, NetNSSpec{Kind: NetNSName, Name: "h2", Create: true})
	if err != nil {
		t.Fatalf("ApplyReconcileAction: %v", err)
	}
	if len(ipsecDrv.Initiated) != 1 || ipsecDrv.Initiated[0] != ChildSAName(spec) {
		t.Fatalf("initiated = %+v", ipsecDrv.Initiated)
	}
	last := plan.Operations[len(plan.Operations)-1]
	if last.Action != "initiate_child" || last.Target != ChildSAName(spec) {
		t.Fatalf("plan = %+v", plan)
	}
}

func TestApplyReconcileActionUpdateReplacesOldConnectionBeforeLoad(t *testing.T) {
	oldSpec := TransportLinkSpec{
		LocalZone:     "node-a.catofes.",
		PeerZone:      "node-b.catofes.",
		OverlayID:     "ipsec-main",
		Provider:      ProviderStrongSwan,
		TransportID:   "ipsec-main-ab",
		InterfaceName: "hgs1",
		XFRMIfID:      77,
		ContactPoints: []ContactPoint{{
			Address:    "198.51.100.20",
			Family:     FamilyIPv4,
			Generation: 1,
			IKEPort:    DefaultIKEPort,
			NATTPort:   DefaultNATTPort,
		}},
	}
	newSpec := oldSpec
	newSpec.ContactPoints = []ContactPoint{{
		Address:    "198.51.100.20",
		Family:     FamilyIPv4,
		Generation: 2,
		IKEPort:    30001,
		NATTPort:   30002,
	}}
	inst := NewLinkInstance(oldSpec, LinkStateUp, time.Unix(4100, 0))

	ipsecDrv := &DryRunDriver{}
	xfrmDrv := &DryRunDriver{}
	_, err := ApplyReconcileAction(context.Background(), ipsecDrv, xfrmDrv, ReconcileAction{
		Action:   ReconcileActionUpdate,
		Spec:     &newSpec,
		Instance: &inst,
	}, NetNSSpec{Kind: NetNSName, Name: "h2", Create: true})
	if err != nil {
		t.Fatalf("ApplyReconcileAction: %v", err)
	}
	if len(ipsecDrv.Terminated) != 1 || ipsecDrv.Terminated[0] != oldSpec.TransportID {
		t.Fatalf("terminated = %+v, want old %s", ipsecDrv.Terminated, oldSpec.TransportID)
	}
	if len(ipsecDrv.Unloaded) != 1 || ipsecDrv.Unloaded[0] != oldSpec.TransportID {
		t.Fatalf("unloaded = %+v, want old %s", ipsecDrv.Unloaded, oldSpec.TransportID)
	}
	if len(ipsecDrv.Connections) != 1 || ipsecDrv.Connections[0].ContactPoints[0].IKEPort != 30001 {
		t.Fatalf("connections = %+v, want new port spec", ipsecDrv.Connections)
	}
}

func TestApplyReconcileActionPrepareRotateUnloadsBaseConfig(t *testing.T) {
	spec := TransportLinkSpec{
		LocalZone:       "node-a.catofes.",
		PeerZone:        "node-b.catofes.",
		OverlayID:       "ipsec-main",
		Provider:        ProviderStrongSwan,
		LinkID:          "link-stable",
		TransportID:     RuntimeConnectionID("link-stable", 2, ProviderStrongSwan),
		InterfaceName:   "hgs2",
		XFRMIfID:        78,
		InitiatorRole:   InitiatorRolePrimary,
		LocalTunnelAddr: netip.MustParseAddr("fd00:1234::2"),
		ContactPoints: []ContactPoint{{
			Address:    "198.51.100.20",
			Family:     FamilyIPv4,
			Generation: 2,
			IKEPort:    DefaultIKEPort,
			NATTPort:   DefaultNATTPort,
		}},
	}
	inst := LinkInstance{IKEName: RuntimeConnectionID("link-stable", 0, ProviderStrongSwan)}
	ipsecDrv := &DryRunDriver{}
	xfrmDrv := &DryRunDriver{}
	if _, err := ApplyReconcileAction(context.Background(), ipsecDrv, xfrmDrv, ReconcileAction{
		Action:   ReconcileActionPrepareRotate,
		Spec:     &spec,
		Instance: &inst,
	}, NetNSSpec{Kind: NetNSName, Name: "h2", Create: true}); err != nil {
		t.Fatalf("ApplyReconcileAction: %v", err)
	}
	if !stringSliceContains(ipsecDrv.Unloaded, inst.IKEName) {
		t.Fatalf("unloaded = %+v, want base config %s", ipsecDrv.Unloaded, inst.IKEName)
	}
	if len(ipsecDrv.Terminated) != 0 {
		t.Fatalf("prepare_rotate terminated old SA: %+v", ipsecDrv.Terminated)
	}
}

func TestApplyReconcileActionCommitRotateTeardownsOldGeneration(t *testing.T) {
	oldSpec := TransportLinkSpec{
		LocalZone:     "node-a.catofes.",
		PeerZone:      "node-b.catofes.",
		OverlayID:     "ipsec-main",
		Provider:      ProviderStrongSwan,
		TransportID:   "ipsec-main-ab",
		InterfaceName: "hgs1",
		XFRMIfID:      77,
	}
	ipsecDrv := &DryRunDriver{}
	xfrmDrv := &DryRunDriver{}
	_, err := ApplyReconcileAction(context.TODO(), ipsecDrv, xfrmDrv, ReconcileAction{
		Action: ReconcileActionCommitRotate,
		Spec:   &oldSpec,
	}, NetNSSpec{})
	if err != nil {
		t.Fatalf("ApplyReconcileAction: %v", err)
	}
	if len(ipsecDrv.Terminated) != 1 || ipsecDrv.Terminated[0] != oldSpec.TransportID {
		t.Fatalf("terminated = %+v", ipsecDrv.Terminated)
	}
	if len(ipsecDrv.Unloaded) != 1 || ipsecDrv.Unloaded[0] != oldSpec.TransportID {
		t.Fatalf("unloaded = %+v", ipsecDrv.Unloaded)
	}
	if len(xfrmDrv.DeletedIFs) != 1 || xfrmDrv.DeletedIFs[0] != oldSpec.InterfaceName {
		t.Fatalf("deleted interfaces = %+v", xfrmDrv.DeletedIFs)
	}
}

func TestReconcileRestartRecoversRotationPhase(t *testing.T) {
	now := time.Unix(1717171717, 0)
	ns := zone.NewNetworkState()
	addIPsecNode(t, ns, "node-b.catofes.", AcceptInbound, []AddressAdvertisement{{
		ID: "b-public", Source: SourceManualAddress, Address: "198.51.100.20", Priority: 100, TTLSeconds: 300,
	}}, now)
	ns.Zones["node-b.catofes."].Records[RecordKeyPorts] = record(t, "node-b.catofes.", RecordKeyPorts, RecordTypePorts, PortRecord{
		Version: 1,
		Mode:    PortModeFixed,
		Current: &PortSelection{
			Generation: 2,
			IKE:        PortBinding{Advertised: DefaultIKEPort},
			NATT:       PortBinding{Advertised: 4501},
		},
		UpdatedAt: now.Unix(),
	})
	addIPsecNode(t, ns, "node-a.catofes.", AcceptNone, []AddressAdvertisement{{
		ID: "a-public", Source: SourceManualAddress, Address: "198.51.100.10", Priority: 100, TTLSeconds: 300,
	}}, now)
	group := LinkGroupSpec{ID: "ipsec-main"}
	plan, err := PlanTransportLinks(context.TODO(), ns, "node-a.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks: %v", err)
	}
	newSpec := plan.Desired[0]

	// Simulate a persisted instance in the testing_new phase after daemon restart.
	existing := NewLinkInstance(runtimeSpecForPortGeneration(newSpec, 1), LinkStateUp, now)
	existing.RemoteGeneration = 1
	existing.IKEName = existing.TransportID
	existing.ChildSAName = ChildSAName(newSpec)
	existing.StagedGeneration = 2
	existing.StagedIKEName = stagedRuntimeID(existing, 2)
	existing.StagedChildSAName = existing.StagedIKEName + "-child"
	existing.RotatePhase = RotatePhaseTestingNew
	existing.RotateDeadline = now.Add(time.Minute).Unix()

	// On restart, the staged SA is already observed.
	result := ReconcileLinkInstances(ReconcileInputs{
		Desired:   []TransportLinkSpec{newSpec},
		Instances: map[string]LinkInstance{existing.ID: existing},
		SAs: []SAState{
			{Name: existing.StagedIKEName, Established: true},
		},
		Now: now,
	})

	action := firstAction(result, ReconcileActionCommitRotate)
	if action == nil {
		t.Fatalf("expected commit_rotate after restart when old SA is missing, got %+v", result.Actions)
	}
	inst := result.Instances[existing.ID]
	if inst.RemoteGeneration != 2 || inst.StagedGeneration != 0 {
		t.Fatalf("instance not recovered: %+v", inst)
	}
	if inst.IKEName != existing.StagedIKEName {
		t.Fatalf("ike name = %q, want %q", inst.IKEName, existing.StagedIKEName)
	}
}

func TestReconcileNormalUpdateWhenNoGenerationChange(t *testing.T) {
	now := time.Unix(1717171717, 0)
	ns := zone.NewNetworkState()
	addIPsecNode(t, ns, "node-b.catofes.", AcceptInbound, []AddressAdvertisement{{
		ID: "b-public", Source: SourceManualAddress, Address: "198.51.100.20", Priority: 100, TTLSeconds: 300,
	}}, now)
	addIPsecNode(t, ns, "node-a.catofes.", AcceptNone, []AddressAdvertisement{{
		ID: "a-public", Source: SourceManualAddress, Address: "198.51.100.10", Priority: 100, TTLSeconds: 300,
	}}, now)
	group := LinkGroupSpec{ID: "ipsec-main"}
	plan, err := PlanTransportLinks(context.TODO(), ns, "node-a.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks: %v", err)
	}
	spec := plan.Desired[0]
	existing := NewLinkInstance(spec, LinkStateUp, now)

	// Spec hash differs because tunnel address changed by adding a new address.
	ns.Zones["node-b.catofes."].Records[RecordKeyAddresses] = record(t, "node-b.catofes.", RecordKeyAddresses, RecordTypeAddresses, AddressRecord{
		Version: 1,
		Addresses: []AddressAdvertisement{{
			ID: "b-public2", Source: SourceManualAddress, Address: "198.51.100.21", Priority: 200, TTLSeconds: 300,
		}},
		UpdatedAt: now.Unix(),
	})
	plan2, err := PlanTransportLinks(context.TODO(), ns, "node-a.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks: %v", err)
	}
	newSpec := plan2.Desired[0]
	if contactGeneration(newSpec) != existing.RemoteGeneration {
		t.Fatalf("generation mismatch before normal update test")
	}

	result := ReconcileLinkInstances(ReconcileInputs{
		Desired:   []TransportLinkSpec{newSpec},
		Instances: map[string]LinkInstance{existing.ID: existing},
		SAs:       []SAState{{Name: existing.IKEName, Established: true}},
		Now:       now,
	})

	if firstAction(result, ReconcileActionPrepareRotate) != nil {
		t.Fatalf("unexpected prepare_rotate action")
	}
	if firstAction(result, ReconcileActionUpdate) == nil {
		t.Fatalf("expected update action, got %+v", result.Actions)
	}
}

func TestReconcileRotateUsesUpdatedEndpointWhenGenerationChanges(t *testing.T) {
	now := time.Unix(1717171717, 0)
	ns := zone.NewNetworkState()
	addIPsecNode(t, ns, "node-b.catofes.", AcceptInbound, []AddressAdvertisement{{
		ID: "b-public", Source: SourceManualAddress, Address: "198.51.100.20", Priority: 100, TTLSeconds: 300,
	}}, now)
	addIPsecNode(t, ns, "node-a.catofes.", AcceptNone, []AddressAdvertisement{{
		ID: "a-public", Source: SourceManualAddress, Address: "198.51.100.10", Priority: 100, TTLSeconds: 300,
	}}, now)
	group := LinkGroupSpec{ID: "ipsec-main"}
	plan, err := PlanTransportLinks(context.TODO(), ns, "node-a.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks: %v", err)
	}
	spec := plan.Desired[0]
	existing := NewLinkInstance(spec, LinkStateUp, now)
	if existing.RemoteGeneration != 1 {
		t.Fatalf("existing.RemoteGeneration = %d, want 1", existing.RemoteGeneration)
	}

	ns.Zones["node-b.catofes."].Records[RecordKeyAddresses] = record(t, "node-b.catofes.", RecordKeyAddresses, RecordTypeAddresses, AddressRecord{
		Version: 1,
		Addresses: []AddressAdvertisement{{
			ID: "b-public2", Source: SourceManualAddress, Address: "198.51.100.21", Priority: 200, TTLSeconds: 300,
		}},
		UpdatedAt: now.Unix(),
	})
	ns.Zones["node-b.catofes."].Records[RecordKeyPorts] = record(t, "node-b.catofes.", RecordKeyPorts, RecordTypePorts, PortRecord{
		Version: 1,
		Mode:    PortModeFixed,
		Current: &PortSelection{
			Generation: 2,
			IKE:        PortBinding{Advertised: DefaultIKEPort},
			NATT:       PortBinding{Advertised: 4501},
		},
		UpdatedAt: now.Unix(),
	})
	plan2, err := PlanTransportLinks(context.TODO(), ns, "node-a.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks: %v", err)
	}
	newSpec := plan2.Desired[0]
	if contactGeneration(newSpec) != 2 {
		t.Fatalf("new spec generation = %d, want 2", contactGeneration(newSpec))
	}

	result := ReconcileLinkInstances(ReconcileInputs{
		Desired:   []TransportLinkSpec{newSpec},
		Instances: map[string]LinkInstance{existing.ID: existing},
		SAs:       []SAState{{Name: existing.IKEName, Established: true}},
		Now:       now,
	})

	action := firstAction(result, ReconcileActionPrepareRotate)
	if action == nil || action.Spec == nil {
		t.Fatalf("expected prepare_rotate action, got %+v", result.Actions)
	}
	if len(action.Spec.ContactPoints) != 1 {
		t.Fatalf("staged contact points = %+v", action.Spec.ContactPoints)
	}
	point := action.Spec.ContactPoints[0]
	if point.Address != "198.51.100.21" || point.Generation != 2 || point.NATTPort != 4501 {
		t.Fatalf("staged contact point = %+v, want new endpoint generation", point)
	}
	inst := result.Instances[existing.ID]
	if inst.RemoteGeneration != 1 || inst.StagedGeneration != 2 || inst.RotatePhase != RotatePhasePreparing {
		t.Fatalf("instance = %+v", inst)
	}
}

func TestReconcileSecondaryStandbyInitialNoop(t *testing.T) {
	now := time.Unix(1717171717, 0)
	ns := zone.NewNetworkState()
	addIPsecNode(t, ns, "node-a.catofes.", AcceptBidirectional, []AddressAdvertisement{{
		ID: "a-public", Source: SourceManualAddress, Address: "198.51.100.10", Priority: 100, TTLSeconds: 300,
	}}, now)
	addIPsecNode(t, ns, "node-b.catofes.", AcceptBidirectional, []AddressAdvertisement{{
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
	addIPsecNode(t, ns, "node-a.catofes.", AcceptBidirectional, []AddressAdvertisement{{
		ID: "a-public", Source: SourceManualAddress, Address: "198.51.100.10", Priority: 100, TTLSeconds: 300,
	}}, now)
	addIPsecNode(t, ns, "node-b.catofes.", AcceptBidirectional, []AddressAdvertisement{{
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
	addIPsecNode(t, ns, "node-a.catofes.", AcceptBidirectional, []AddressAdvertisement{{
		ID: "a-public", Source: SourceManualAddress, Address: "198.51.100.10", Priority: 100, TTLSeconds: 300,
	}}, base)
	addIPsecNode(t, ns, "node-b.catofes.", AcceptBidirectional, []AddressAdvertisement{{
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
	addIPsecNode(t, ns, "node-a.catofes.", AcceptBidirectional, []AddressAdvertisement{{
		ID: "a-public", Source: SourceManualAddress, Address: "198.51.100.10", Priority: 100, TTLSeconds: 300,
	}}, base)
	addIPsecNode(t, ns, "node-b.catofes.", AcceptBidirectional, []AddressAdvertisement{{
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
	addIPsecNode(t, ns, "node-a.catofes.", AcceptBidirectional, []AddressAdvertisement{{
		ID: "a-public", Source: SourceManualAddress, Address: "198.51.100.10", Priority: 100, TTLSeconds: 300,
	}}, now)
	addIPsecNode(t, ns, "node-b.catofes.", AcceptBidirectional, []AddressAdvertisement{{
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
	addIPsecNode(t, ns, "node-a.catofes.", AcceptBidirectional, []AddressAdvertisement{{
		ID: "a-public", Source: SourceManualAddress, Address: "198.51.100.10", Priority: 100, TTLSeconds: 300,
	}}, now)
	addIPsecNode(t, ns, "node-b.catofes.", AcceptBidirectional, []AddressAdvertisement{{
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

func stringSliceContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
