package ipsec

import (
	"context"
	"testing"
	"time"
)

func TestPlanDuplicateSAGCSecondaryRemovesNonCanonicalSAAfterGrace(t *testing.T) {
	spec := duplicateGCTestSpec()
	inst := NewLinkInstance(spec, LinkStateUp, time.Unix(1000, 0))
	inst.InitiatorRole = InitiatorRoleConverged
	sas := []SAState{
		duplicateGCTestSA(spec, 12, false, 240),
		duplicateGCTestSA(spec, 18, true, 180),
	}

	actions := PlanDuplicateSAGC(
		[]TransportLinkSpec{spec},
		map[string]LinkInstance{inst.ID: inst},
		sas,
		map[string]string{inst.ID: InitiatorRoleSecondaryStandby},
	)
	if len(actions) != 1 || actions[0].Action != ReconcileActionCleanupDuplicateSA || actions[0].SAUniqueID != 18 {
		t.Fatalf("actions = %+v, want cleanup of locally initiated SA #18", actions)
	}

	driver := &DryRunDriver{}
	if _, err := ApplyReconcileAction(context.Background(), driver, driver, actions[0], NetNSSpec{}); err != nil {
		t.Fatalf("ApplyReconcileAction: %v", err)
	}
	if len(driver.Terminated) != 1 || driver.Terminated[0] != "#18" {
		t.Fatalf("terminated = %+v, want [#18]", driver.Terminated)
	}
}

func TestPlanDuplicateSAGCWaitsForEverySAAndRunsOnlyOnSecondary(t *testing.T) {
	spec := duplicateGCTestSpec()
	inst := NewLinkInstance(spec, LinkStateUp, time.Unix(1000, 0))
	sas := []SAState{
		duplicateGCTestSA(spec, 12, false, 240),
		duplicateGCTestSA(spec, 18, true, 119),
	}
	if actions := PlanDuplicateSAGC(
		[]TransportLinkSpec{spec},
		map[string]LinkInstance{inst.ID: inst},
		sas,
		map[string]string{inst.ID: InitiatorRoleSecondaryStandby},
	); len(actions) != 0 {
		t.Fatalf("premature actions = %+v", actions)
	}

	sas[1] = duplicateGCTestSA(spec, 18, true, 180)
	if actions := PlanDuplicateSAGC(
		[]TransportLinkSpec{spec},
		map[string]LinkInstance{inst.ID: inst},
		sas,
		map[string]string{inst.ID: InitiatorRolePrimary},
	); len(actions) != 0 {
		t.Fatalf("primary emitted GC actions = %+v", actions)
	}
}

func TestPlanDuplicateSAGCKeepsTakeoverWhenPrimarySAIsAbsent(t *testing.T) {
	spec := duplicateGCTestSpec()
	inst := NewLinkInstance(spec, LinkStateUp, time.Unix(1000, 0))
	sas := []SAState{
		duplicateGCTestSA(spec, 18, true, 240),
		duplicateGCTestSA(spec, 19, true, 180),
	}
	if actions := PlanDuplicateSAGC(
		[]TransportLinkSpec{spec},
		map[string]LinkInstance{inst.ID: inst},
		sas,
		map[string]string{inst.ID: InitiatorRoleSecondaryStandby},
	); len(actions) != 0 {
		t.Fatalf("actions without canonical primary SA = %+v", actions)
	}
}

func duplicateGCTestSpec() TransportLinkSpec {
	return TransportLinkSpec{
		LocalZone:     "node-b.catofes.",
		PeerZone:      "node-a.catofes.",
		OverlayID:     "main",
		Provider:      ProviderStrongSwan,
		PathKey:       "family:ipv4",
		TransportID:   "ipsec-duplicate",
		InterfaceName: "hgs1234",
		XFRMIfID:      0x1234,
	}
}

func duplicateGCTestSA(spec TransportLinkSpec, id uint64, initiator bool, age uint64) SAState {
	return SAState{
		Name:            spec.TransportID,
		UniqueID:        id,
		Initiator:       initiator,
		InitiatorKnown:  true,
		IKEAgeSeconds:   age,
		ChildAgeSeconds: age,
		ChildSA:         ChildSAName(spec),
		IKEState:        "ESTABLISHED",
		ChildState:      "INSTALLED",
		XFRMIfID:        spec.XFRMIfID,
		LocalIdentity:   string(spec.LocalZone),
		RemoteIdentity:  string(spec.PeerZone),
		RemoteEndpoint:  "198.51.100.10:4500",
		Endpoint:        "198.51.100.10:4500",
		Established:     true,
	}
}
