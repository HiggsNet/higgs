package ipsec

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/Catofes/higgs/pkg/core/zone"
)

func TestPlanTransportLinksBuildsDesiredSpecsFromActiveState(t *testing.T) {
	now := time.Unix(1717171717, 0)
	ns := zone.NewNetworkState()
	addIPsecNode(t, ns, "node-a.catofes.", AcceptInbound, []AddressAdvertisement{{
		ID: "a-public", Source: SourceManualAddress, Address: "198.51.100.10", Priority: 100, TTLSeconds: 300,
	}}, now)
	addIPsecNode(t, ns, "node-b.catofes.", AcceptInbound, []AddressAdvertisement{{
		ID: "b-public", Source: SourceManualAddress, Address: "198.51.100.20", Priority: 100, TTLSeconds: 300,
	}}, now)
	group := LinkGroupSpec{
		ID:                "ipsec-main",
		Direction:         DirectionOutbound,
		TunnelAddressPool: netip.MustParsePrefix("10.44.0.0/29"),
	}
	plan, err := PlanTransportLinks(context.Background(), ns, "node-a.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks: %v", err)
	}
	if len(plan.Desired) != 1 {
		t.Fatalf("desired len = %d, skips = %+v", len(plan.Desired), plan.Skipped)
	}
	spec := plan.Desired[0]
	if spec.PeerZone != "node-b.catofes." || spec.Direction != DirectionOutbound {
		t.Fatalf("spec = %+v", spec)
	}
	if spec.LocalTunnelAddr.String() != "10.44.0.1" || spec.PeerTunnelAddr.String() != "10.44.0.2" {
		t.Fatalf("tunnel addresses = %s, %s", spec.LocalTunnelAddr, spec.PeerTunnelAddr)
	}
	if len(spec.ContactPoints) != 1 || spec.ContactPoints[0].Address != "198.51.100.20" {
		t.Fatalf("contact points = %+v", spec.ContactPoints)
	}
}

func TestPlanTransportLinksHonorsBidirectionalTieBreakAndInboundAccept(t *testing.T) {
	now := time.Unix(1717171717, 0)
	ns := zone.NewNetworkState()
	addIPsecNode(t, ns, "node-a.catofes.", AcceptBidirectional, []AddressAdvertisement{{
		ID: "a-public", Source: SourceManualAddress, Address: "198.51.100.10", Priority: 100, TTLSeconds: 300,
	}}, now)
	addIPsecNode(t, ns, "node-b.catofes.", AcceptBidirectional, []AddressAdvertisement{{
		ID: "b-public", Source: SourceManualAddress, Address: "198.51.100.20", Priority: 100, TTLSeconds: 300,
	}}, now)
	group := LinkGroupSpec{ID: "ipsec-main", Direction: DirectionBidirectional}
	plan, err := PlanTransportLinks(context.Background(), ns, "node-a.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks(a): %v", err)
	}
	if len(plan.Desired) != 1 || plan.Desired[0].PeerZone != "node-b.catofes." {
		t.Fatalf("node-a plan = %+v skips=%+v", plan.Desired, plan.Skipped)
	}
	plan, err = PlanTransportLinks(context.Background(), ns, "node-b.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks(b): %v", err)
	}
	if len(plan.Desired) != 0 {
		t.Fatalf("node-b should not initiate duplicate link: %+v", plan.Desired)
	}
	if !hasSkip(plan.Skipped, "node-a.catofes.", SkipAcceptIntentMismatch) {
		t.Fatalf("skips = %+v", plan.Skipped)
	}
}

func TestPlanTransportLinksSkipsRevokedPeerAndMissingContactPoint(t *testing.T) {
	now := time.Unix(1717171717, 0)
	ns := zone.NewNetworkState()
	addIPsecNode(t, ns, "node-a.catofes.", AcceptInbound, []AddressAdvertisement{{
		ID: "a-public", Source: SourceManualAddress, Address: "198.51.100.10", Priority: 100, TTLSeconds: 300,
	}}, now)
	addIPsecNode(t, ns, "node-b.catofes.", AcceptInbound, []AddressAdvertisement{{
		ID: "b-local", Source: SourceLocal, Address: "192.168.8.20", Priority: 100, TTLSeconds: 300,
	}}, now)
	addIPsecNode(t, ns, "node-c.catofes.", AcceptInbound, []AddressAdvertisement{{
		ID: "c-public", Source: SourceManualAddress, Address: "198.51.100.30", Priority: 100, TTLSeconds: 300,
	}}, now)
	ns.Zones["catofes."] = zone.NewZoneState("catofes.", nil)
	ns.Zones["catofes."].Revocations["node-c.catofes."] = &zone.DelegationRevocation{
		ChildZone:  "node-c.catofes.",
		ParentZone: "catofes.",
		RevokedAt:  now.Add(-time.Minute).Unix(),
	}
	group := LinkGroupSpec{ID: "ipsec-main", Direction: DirectionOutbound}
	plan, err := PlanTransportLinks(context.Background(), ns, "node-a.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks: %v", err)
	}
	if len(plan.Desired) != 0 {
		t.Fatalf("desired = %+v", plan.Desired)
	}
	if !hasSkip(plan.Skipped, "node-b.catofes.", SkipNoContactPoints) {
		t.Fatalf("missing no-contact skip: %+v", plan.Skipped)
	}
	if !hasSkip(plan.Skipped, "node-c.catofes.", SkipRevokedZone) {
		t.Fatalf("missing revoked skip: %+v", plan.Skipped)
	}
}

func TestPlanTransportLinksUsesContactPointQualityForPortFallback(t *testing.T) {
	now := time.Unix(1717171717, 0)
	ns := zone.NewNetworkState()
	addIPsecNode(t, ns, "node-a.catofes.", AcceptInbound, []AddressAdvertisement{{
		ID: "a-public", Source: SourceManualAddress, Address: "198.51.100.10", Priority: 100, Reachability: ReachabilityPublic, TTLSeconds: 300,
	}}, now)
	addIPsecNode(t, ns, "node-b.catofes.", AcceptInbound, []AddressAdvertisement{{
		ID: "b-public", Source: SourceManualAddress, Address: "198.51.100.20", Priority: 100, Reachability: ReachabilityPublic, TTLSeconds: 300,
	}}, now)
	ns.Zones["node-b.catofes."].Records[RecordKeyPorts] = record(t, "node-b.catofes.", RecordKeyPorts, RecordTypePorts, PortRecord{
		Version: 1,
		Mode:    PortModeFixed,
		Current: &PortSelection{
			Generation: 2,
			IKE:        PortBinding{Advertised: 500},
			NATT:       PortBinding{Advertised: 4500},
			ValidUntil: now.Add(time.Hour).Unix(),
		},
		Previous: []PortSelection{{
			Generation: 1,
			IKE:        PortBinding{Advertised: 1500},
			NATT:       PortBinding{Advertised: 14500},
			ValidUntil: now.Add(10 * time.Minute).Unix(),
		}},
		UpdatedAt: now.Unix(),
	})
	currentKey := ContactPoint{
		AddressID:  "b-public",
		Address:    "198.51.100.20",
		Generation: 2,
		IKEPort:    500,
		NATTPort:   4500,
	}.Key()
	group := LinkGroupSpec{ID: "ipsec-main", Direction: DirectionOutbound, DefaultPathMode: PathModeExhaustive}
	plan, err := PlanTransportLinks(context.Background(), ns, "node-a.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{
		Now: now,
		ContactPointQuality: map[zone.ZonePath]map[string]ContactPointQuality{
			"node-b.catofes.": {
				currentKey: {
					Failures:     2,
					BackoffUntil: now.Add(time.Minute),
					LastError:    "ike_timeout",
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("PlanTransportLinks: %v", err)
	}
	if len(plan.Desired) != 1 {
		t.Fatalf("desired len = %d skips=%+v", len(plan.Desired), plan.Skipped)
	}
	point := plan.Desired[0].ContactPoints[0]
	if point.Current || point.IKEPort != 1500 {
		t.Fatalf("first contact point = %+v, want previous grace port", point)
	}
	if plan.Desired[0].ContactPoints[1].LastError != "ike_timeout" {
		t.Fatalf("current point quality missing: %+v", plan.Desired[0].ContactPoints)
	}
}

func TestReconcileLinkInstancesCreatesAdoptsRepairsAndTeardowns(t *testing.T) {
	now := time.Unix(1717171717, 0)
	spec := TransportLinkSpec{
		LocalZone:     "node-a.catofes.",
		PeerZone:      "node-b.catofes.",
		OverlayID:     "ipsec-main",
		Provider:      ProviderStrongSwan,
		TransportID:   "ipsec-main-ab",
		InterfaceName: "hgs1",
		XFRMIfID:      77,
	}
	result := ReconcileLinkInstances(ReconcileInputs{Desired: []TransportLinkSpec{spec}, Now: now})
	if action := firstAction(result, ReconcileActionCreate); action == nil {
		t.Fatalf("create action missing: %+v", result.Actions)
	}
	instance := result.Instances[LinkInstanceID(spec)]
	if instance.Owner.Manager != "higgs" || instance.DesiredSpecHash == "" {
		t.Fatalf("instance = %+v", instance)
	}

	adopted := ReconcileLinkInstances(ReconcileInputs{
		Desired: []TransportLinkSpec{spec},
		SAs:     []SAState{{Name: spec.TransportID, ChildSA: ChildSAName(spec), XFRMIfID: spec.XFRMIfID, Endpoint: "198.51.100.20", Established: true}},
		Now:     now,
	})
	if action := firstAction(adopted, ReconcileActionAdopt); action == nil {
		t.Fatalf("adopt action missing: %+v", adopted.Actions)
	}
	if adopted.Instances[LinkInstanceID(spec)].ActualState != LinkStateUp {
		t.Fatalf("adopted instance = %+v", adopted.Instances[LinkInstanceID(spec)])
	}

	up := NewLinkInstance(spec, LinkStateUp, now)
	repaired := ReconcileLinkInstances(ReconcileInputs{
		Desired:   []TransportLinkSpec{spec},
		Instances: map[string]LinkInstance{up.ID: up},
		Now:       now.Add(time.Minute),
	})
	if action := firstAction(repaired, ReconcileActionRepair); action == nil {
		t.Fatalf("repair action missing: %+v", repaired.Actions)
	}
	if repaired.Instances[up.ID].ActualState != LinkStateDegraded {
		t.Fatalf("repaired instance = %+v", repaired.Instances[up.ID])
	}

	teardown := ReconcileLinkInstances(ReconcileInputs{
		Instances: map[string]LinkInstance{up.ID: up},
		Now:       now.Add(time.Minute),
	})
	if action := firstAction(teardown, ReconcileActionTeardown); action == nil || action.Reason != "no longer desired" {
		t.Fatalf("teardown action = %+v", teardown.Actions)
	}
}

func TestReconcileLinkInstancesRevocationWinsOverDesiredState(t *testing.T) {
	now := time.Unix(1717171717, 0)
	spec := TransportLinkSpec{
		LocalZone:     "node-a.catofes.",
		PeerZone:      "node-b.catofes.",
		OverlayID:     "ipsec-main",
		Provider:      ProviderStrongSwan,
		TransportID:   "ipsec-main-ab",
		InterfaceName: "hgs1",
		XFRMIfID:      77,
	}
	result := ReconcileLinkInstances(ReconcileInputs{
		Desired: []TransportLinkSpec{spec},
		Revoked: map[zone.ZonePath]bool{
			"node-b.catofes.": true,
		},
		Now: now,
	})
	action := firstAction(result, ReconcileActionTeardown)
	if action == nil || action.Reason != "peer revoked" {
		t.Fatalf("actions = %+v", result.Actions)
	}
	if result.Instances[LinkInstanceID(spec)].ActualState != LinkStateRemoving {
		t.Fatalf("instance = %+v", result.Instances[LinkInstanceID(spec)])
	}
}

func addIPsecNode(t *testing.T, ns *zone.NetworkState, peer zone.ZonePath, accept string, addresses []AddressAdvertisement, now time.Time) {
	t.Helper()
	zs := zone.NewZoneState(peer, nil)
	fingerprint := "fp-" + string(peer)
	zs.Records[RecordKeyProfile] = record(t, peer, RecordKeyProfile, RecordTypeProfile, ProfileRecord{
		Version:                 1,
		Enabled:                 true,
		Provider:                ProviderStrongSwan,
		IKEIdentity:             string(peer),
		TransportKeyFingerprint: fingerprint,
		Accept:                  accept,
		AddressFamilies:         []string{FamilyIPv4, FamilyIPv6},
		PathModes:               []string{PathModeFamilyRedundant, PathModeExhaustive},
		UpdatedAt:               now.Unix(),
	})
	zs.Records[RecordKeyAddresses] = record(t, peer, RecordKeyAddresses, RecordTypeAddresses, AddressRecord{
		Version:   1,
		Addresses: addresses,
		UpdatedAt: now.Unix(),
	})
	zs.Records[RecordKeyPorts] = record(t, peer, RecordKeyPorts, RecordTypePorts, PortRecord{
		Version: 1,
		Mode:    PortModeFixed,
		Current: &PortSelection{
			Generation: 1,
			IKE:        PortBinding{Advertised: DefaultIKEPort},
			NATT:       PortBinding{Advertised: DefaultNATTPort},
			ValidUntil: now.Add(time.Hour).Unix(),
		},
		UpdatedAt: now.Unix(),
	})
	zs.Records[RecordKeyTransportKey] = record(t, peer, RecordKeyTransportKey, RecordTypeTransportKey, TransportKeyRecord{
		Version:     1,
		Kind:        TransportKeyRawPublicKey,
		Algorithm:   AlgorithmEd25519,
		PublicKey:   "base64",
		Fingerprint: fingerprint,
		UpdatedAt:   now.Unix(),
	})
	ns.Zones[peer] = zs
}

func hasSkip(skips []PlanSkip, peer zone.ZonePath, reason string) bool {
	for _, skip := range skips {
		if skip.Peer == peer && skip.Reason == reason {
			return true
		}
	}
	return false
}

func firstAction(result ReconcileResult, action string) *ReconcileAction {
	for i := range result.Actions {
		if result.Actions[i].Action == action {
			return &result.Actions[i]
		}
	}
	return nil
}
