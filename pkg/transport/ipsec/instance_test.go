package ipsec

import (
	"net/netip"
	"testing"
	"time"

	"github.com/Catofes/higgs/pkg/core/zone"
)

func TestRotateConnectionNameStable(t *testing.T) {
	base := "ipsec-deadbeef"
	if got := RotateConnectionName(base, 3); got != "ipsec-deadbeef-rot-3" {
		t.Fatalf("RotateConnectionName = %q", got)
	}
	if got := RotateChildSAName(base, 3); got != "ipsec-deadbeef-rot-3-child" {
		t.Fatalf("RotateChildSAName = %q", got)
	}
}

func TestReconcilePrepareRotateOnGenerationChange(t *testing.T) {
	now := time.Unix(1717171717, 0)
	ns := zone.NewNetworkState()
	addIPsecNode(t, ns, "node-b.catofes.", AcceptInbound, []AddressAdvertisement{{
		ID: "b-public", Source: SourceManualAddress, Address: "198.51.100.20", Priority: 100, TTLSeconds: 300,
	}}, now)
	group := LinkGroupSpec{
		ID:                "ipsec-main",
		Direction:         DirectionOutbound,
		TunnelAddressPool: netip.MustParsePrefix("10.44.0.0/29"),
	}
	plan, err := PlanTransportLinks(nil, ns, "node-a.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{Now: now})
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
	plan2, err := PlanTransportLinks(nil, ns, "node-a.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{Now: now})
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
	if action.Spec.TransportID != RotateConnectionName(existing.TransportID, 2) {
		t.Fatalf("staged transport id = %q, want %q", action.Spec.TransportID, RotateConnectionName(existing.TransportID, 2))
	}
	inst := result.Instances[existing.ID]
	if inst.RotatePhase != RotatePhasePreparing {
		t.Fatalf("rotate phase = %q, want preparing", inst.RotatePhase)
	}
	if inst.StagedGeneration != 2 {
		t.Fatalf("staged generation = %d, want 2", inst.StagedGeneration)
	}
	if inst.StagedIKEName != RotateConnectionName(existing.TransportID, 2) {
		t.Fatalf("staged ike name = %q", inst.StagedIKEName)
	}
	if inst.RemoteGeneration != 1 {
		t.Fatalf("remote generation changed before commit = %d", inst.RemoteGeneration)
	}
}

func TestReconcileCommitRotateAfterStagedSAObserved(t *testing.T) {
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
	group := LinkGroupSpec{
		ID:                "ipsec-main",
		Direction:         DirectionOutbound,
		TunnelAddressPool: netip.MustParsePrefix("10.44.0.0/29"),
	}
	plan, err := PlanTransportLinks(nil, ns, "node-a.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks: %v", err)
	}
	newSpec := plan.Desired[0]

	existing := NewLinkInstance(newSpec, LinkStateUp, now)
	existing.RemoteGeneration = 1
	existing.StagedGeneration = 2
	existing.StagedIKEName = RotateConnectionName(existing.TransportID, 2)
	existing.StagedChildSAName = RotateChildSAName(existing.TransportID, 2)
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

	action := firstAction(result, ReconcileActionCommitRotate)
	if action == nil {
		t.Fatalf("expected commit_rotate action, got %+v", result.Actions)
	}
	inst := result.Instances[existing.ID]
	if inst.RemoteGeneration != 2 {
		t.Fatalf("remote generation = %d, want 2", inst.RemoteGeneration)
	}
	if inst.StagedGeneration != 0 {
		t.Fatalf("staged generation not cleared = %d", inst.StagedGeneration)
	}
	if inst.IKEName != RotateConnectionName(existing.TransportID, 2) {
		t.Fatalf("ike name = %q, want rotated", inst.IKEName)
	}
	if inst.RotatePhase != RotatePhaseCutover {
		t.Fatalf("rotate phase = %q, want cutover", inst.RotatePhase)
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
	group := LinkGroupSpec{
		ID:                "ipsec-main",
		Direction:         DirectionOutbound,
		TunnelAddressPool: netip.MustParsePrefix("10.44.0.0/29"),
	}
	plan, err := PlanTransportLinks(nil, ns, "node-a.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks: %v", err)
	}
	newSpec := plan.Desired[0]

	existing := NewLinkInstance(newSpec, LinkStateUp, now)
	existing.RemoteGeneration = 1
	existing.StagedGeneration = 2
	existing.StagedIKEName = RotateConnectionName(existing.TransportID, 2)
	existing.StagedChildSAName = RotateChildSAName(existing.TransportID, 2)
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
	group := LinkGroupSpec{
		ID:                "ipsec-main",
		Direction:         DirectionOutbound,
		TunnelAddressPool: netip.MustParsePrefix("10.44.0.0/29"),
	}
	plan, err := PlanTransportLinks(nil, ns, "node-a.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks: %v", err)
	}
	newSpec := plan.Desired[0]

	existing := NewLinkInstance(newSpec, LinkStateUp, now)
	existing.RemoteGeneration = 2
	existing.StagedGeneration = 3 // stale; desired is 5
	existing.StagedIKEName = RotateConnectionName(existing.TransportID, 3)
	existing.StagedChildSAName = RotateChildSAName(existing.TransportID, 3)
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
	if action.Spec == nil || action.Spec.TransportID != RotateConnectionName(existing.TransportID, 3) {
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
	_, err := ApplyReconcileAction(nil, ipsecDrv, xfrmDrv, ReconcileAction{
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

func TestApplyReconcileActionCommitRotateOnlyUnloadsConnection(t *testing.T) {
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
	_, err := ApplyReconcileAction(nil, ipsecDrv, xfrmDrv, ReconcileAction{
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
	if len(xfrmDrv.DeletedIFs) != 0 {
		t.Fatalf("commit rotate should not delete interface: %+v", xfrmDrv.DeletedIFs)
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
	group := LinkGroupSpec{
		ID:                "ipsec-main",
		Direction:         DirectionOutbound,
		TunnelAddressPool: netip.MustParsePrefix("10.44.0.0/29"),
	}
	plan, err := PlanTransportLinks(nil, ns, "node-a.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks: %v", err)
	}
	newSpec := plan.Desired[0]

	// Simulate a persisted instance in the testing_new phase after daemon restart.
	existing := NewLinkInstance(newSpec, LinkStateUp, now)
	existing.RemoteGeneration = 1
	existing.IKEName = existing.TransportID
	existing.ChildSAName = ChildSAName(newSpec)
	existing.StagedGeneration = 2
	existing.StagedIKEName = RotateConnectionName(existing.TransportID, 2)
	existing.StagedChildSAName = RotateChildSAName(existing.TransportID, 2)
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
		t.Fatalf("expected commit_rotate after restart, got %+v", result.Actions)
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
	group := LinkGroupSpec{
		ID:                "ipsec-main",
		Direction:         DirectionOutbound,
		TunnelAddressPool: netip.MustParsePrefix("10.44.0.0/29"),
	}
	plan, err := PlanTransportLinks(nil, ns, "node-a.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{Now: now})
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
	plan2, err := PlanTransportLinks(nil, ns, "node-a.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{Now: now})
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
