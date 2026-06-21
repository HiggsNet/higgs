package ipsec

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
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
	if spec.IKEIdentity != "node-a.catofes." {
		t.Fatalf("IKEIdentity = %q, want local zone", spec.IKEIdentity)
	}
	if spec.LocalTunnelAddr.String() != "10.44.0.1" || spec.PeerTunnelAddr.String() != "10.44.0.2" {
		t.Fatalf("tunnel addresses = %s, %s", spec.LocalTunnelAddr, spec.PeerTunnelAddr)
	}
	if len(spec.ContactPoints) != 1 || spec.ContactPoints[0].Address != "198.51.100.20" {
		t.Fatalf("contact points = %+v", spec.ContactPoints)
	}
}

func TestPlanTransportLinksMirrorsTunnelAddressesForPeerPair(t *testing.T) {
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
	planA, err := PlanTransportLinks(context.Background(), ns, "node-a.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks(a): %v", err)
	}
	planB, err := PlanTransportLinks(context.Background(), ns, "node-b.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks(b): %v", err)
	}
	if len(planA.Desired) != 1 || len(planB.Desired) != 1 {
		t.Fatalf("desired A/B = %+v / %+v", planA.Desired, planB.Desired)
	}
	a := planA.Desired[0]
	b := planB.Desired[0]
	if a.LocalTunnelAddr != b.PeerTunnelAddr || a.PeerTunnelAddr != b.LocalTunnelAddr {
		t.Fatalf("tunnel addresses are not mirrored: A local=%s peer=%s, B local=%s peer=%s", a.LocalTunnelAddr, a.PeerTunnelAddr, b.LocalTunnelAddr, b.PeerTunnelAddr)
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
	if plan.Roles[plan.Desired[0].TransportID] != InitiatorRolePrimary {
		t.Fatalf("node-a role = %q, want primary", plan.Roles[plan.Desired[0].TransportID])
	}
	plan, err = PlanTransportLinks(context.Background(), ns, "node-b.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks(b): %v", err)
	}
	if len(plan.Desired) != 1 || plan.Desired[0].PeerZone != "node-a.catofes." {
		t.Fatalf("node-b should keep a standby desired spec: desired=%+v skips=%+v", plan.Desired, plan.Skipped)
	}
	if plan.Roles[plan.Desired[0].TransportID] != InitiatorRoleSecondaryStandby {
		t.Fatalf("node-b role = %q, want secondary-standby", plan.Roles[plan.Desired[0].TransportID])
	}
}

func TestPlanTransportLinksKeepsInboundResponderDesired(t *testing.T) {
	now := time.Unix(1717171717, 0)
	ns := zone.NewNetworkState()
	addIPsecNode(t, ns, "node-a.catofes.", AcceptInbound, []AddressAdvertisement{{
		ID: "a-public", Source: SourceManualAddress, Address: "198.51.100.10", Priority: 100, TTLSeconds: 300,
	}}, now)
	addIPsecNode(t, ns, "node-b.catofes.", AcceptInbound, []AddressAdvertisement{{
		ID: "b-local", Source: SourceLocal, Address: "192.168.8.20", Priority: 100, TTLSeconds: 300,
	}}, now)

	group := LinkGroupSpec{ID: "ipsec-main", Direction: DirectionInbound}
	plan, err := PlanTransportLinks(context.Background(), ns, "node-a.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks: %v", err)
	}
	if len(plan.Desired) != 1 || plan.Desired[0].PeerZone != "node-b.catofes." {
		t.Fatalf("inbound responder desired = %+v skips=%+v, want one", plan.Desired, plan.Skipped)
	}
	spec := plan.Desired[0]
	if spec.Direction != DirectionInbound || len(spec.ContactPoints) != 0 {
		t.Fatalf("inbound responder spec = %+v, want trap-style spec without contact points", spec)
	}
	if plan.Roles[spec.TransportID] != InitiatorRolePrimary {
		t.Fatalf("inbound responder role = %q, want apply-capable role", plan.Roles[spec.TransportID])
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

func TestPlanTransportLinksDoesNotUseAdvertisedLocalPortAsStrongSwanLocalPort(t *testing.T) {
	now := time.Unix(1717171717, 0)
	ns := zone.NewNetworkState()
	addIPsecNode(t, ns, "node-a.catofes.", AcceptBidirectional, []AddressAdvertisement{{
		ID: "a-public", Source: SourceManualAddress, Address: "198.51.100.10", Priority: 100, Reachability: ReachabilityPublic, TTLSeconds: 300,
	}}, now)
	addIPsecNode(t, ns, "node-b.catofes.", AcceptBidirectional, []AddressAdvertisement{{
		ID: "b-public", Source: SourceManualAddress, Address: "198.51.100.20", Priority: 100, Reachability: ReachabilityPublic, TTLSeconds: 300,
	}}, now)
	ns.Zones["node-a.catofes."].Records[RecordKeyPorts] = record(t, "node-a.catofes.", RecordKeyPorts, RecordTypePorts, PortRecord{
		Version: 1,
		Mode:    PortModeRange,
		Range:   &PortRange{From: 33400, To: 33499},
		Current: &PortSelection{
			Generation: 2,
			IKE:        PortBinding{Local: DefaultIKEPort, Advertised: 33402},
			NATT:       PortBinding{Local: DefaultNATTPort, Advertised: 33403},
		},
		UpdatedAt: now.Unix(),
	})
	ns.Zones["node-b.catofes."].Records[RecordKeyPorts] = record(t, "node-b.catofes.", RecordKeyPorts, RecordTypePorts, PortRecord{
		Version: 1,
		Mode:    PortModeRange,
		Range:   &PortRange{From: 30000, To: 30099},
		Current: &PortSelection{
			Generation: 7,
			IKE:        PortBinding{Local: DefaultIKEPort, Advertised: 30001},
			NATT:       PortBinding{Local: DefaultNATTPort, Advertised: 30002},
		},
		UpdatedAt: now.Unix(),
	})

	group := LinkGroupSpec{ID: "ipsec-main", Direction: DirectionBidirectional, DefaultPathMode: PathModeFamilyRedundant}
	plan, err := PlanTransportLinks(context.Background(), ns, "node-a.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks: %v", err)
	}
	if len(plan.Desired) != 1 {
		t.Fatalf("desired len = %d, want 1; skips=%+v", len(plan.Desired), plan.Skipped)
	}
	spec := plan.Desired[0]
	if spec.LocalIKEPort != 0 {
		t.Fatalf("LocalIKEPort = %d, want zero so charon uses its actual listener", spec.LocalIKEPort)
	}
	if len(spec.ContactPoints) != 1 || spec.ContactPoints[0].IKEPort != 30001 {
		t.Fatalf("remote contact points = %+v, want peer advertised port", spec.ContactPoints)
	}
	conn, err := BuildStrongSwanConnection(spec)
	if err != nil {
		t.Fatalf("BuildStrongSwanConnection: %v", err)
	}
	if got := conn["remote_port"]; got != "30001" {
		t.Fatalf("remote_port = %v, want peer advertised port 30001", got)
	}
	if _, ok := conn["local_port"]; ok {
		t.Fatalf("local_port should be omitted for advertised entry ports: %+v", conn)
	}
}

func TestPlanTransportLinksSkipsBehindNATWithoutInboundEvidence(t *testing.T) {
	now := time.Unix(1717171717, 0)
	ns := zone.NewNetworkState()
	addIPsecNode(t, ns, "node-a.catofes.", AcceptInbound, []AddressAdvertisement{{
		ID: "a-public", Source: SourceManualAddress, Address: "198.51.100.10", Priority: 100, Reachability: ReachabilityPublic, TTLSeconds: 300,
	}}, now)
	addIPsecNode(t, ns, "node-b.catofes.", AcceptInbound, []AddressAdvertisement{{
		ID: "b-lan", Source: SourceLocal, Address: "192.168.8.20", Priority: 100, Reachability: ReachabilityPrivate, TTLSeconds: 300,
	}}, now)
	setIPsecNATProfile(t, ns, "node-b.catofes.", NATProfile{Hint: NATHintBehindNAT, InboundReachable: NATReachableFalse}, now)

	group := LinkGroupSpec{ID: "ipsec-main", Direction: DirectionOutbound}
	plan, err := PlanTransportLinks(context.Background(), ns, "node-a.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{
		Now:               now,
		AllowPrivateLocal: true,
	})
	if err != nil {
		t.Fatalf("PlanTransportLinks: %v", err)
	}
	if len(plan.Desired) != 0 {
		t.Fatalf("desired = %+v, want no fake reachable NAT link", plan.Desired)
	}
	if !hasSkip(plan.Skipped, "node-b.catofes.", SkipNoInboundNATEvidence) {
		t.Fatalf("skips = %+v, want %s", plan.Skipped, SkipNoInboundNATEvidence)
	}
}

func TestPlanTransportLinksAllowsNATOutboundToPublicPeer(t *testing.T) {
	now := time.Unix(1717171717, 0)
	ns := zone.NewNetworkState()
	addIPsecNode(t, ns, "node-a.catofes.", AcceptInbound, []AddressAdvertisement{{
		ID: "a-lan", Source: SourceLocal, Address: "192.168.8.10", Priority: 100, Reachability: ReachabilityPrivate, TTLSeconds: 300,
	}}, now)
	setIPsecNATProfile(t, ns, "node-a.catofes.", NATProfile{Hint: NATHintBehindNAT, InboundReachable: NATReachableFalse}, now)
	addIPsecNode(t, ns, "node-b.catofes.", AcceptInbound, []AddressAdvertisement{{
		ID: "b-public", Source: SourceManualAddress, Address: "198.51.100.20", Priority: 100, Reachability: ReachabilityPublic, TTLSeconds: 300,
	}}, now)

	group := LinkGroupSpec{ID: "ipsec-main", Direction: DirectionOutbound}
	plan, err := PlanTransportLinks(context.Background(), ns, "node-a.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks: %v", err)
	}
	if len(plan.Desired) != 1 {
		t.Fatalf("desired len = %d skips=%+v", len(plan.Desired), plan.Skipped)
	}
	if plan.Desired[0].PeerZone != "node-b.catofes." || plan.Desired[0].ContactPoints[0].Address != "198.51.100.20" {
		t.Fatalf("desired = %+v", plan.Desired)
	}
}

func TestPlanTransportLinksAllowsNATObservedExternalPort(t *testing.T) {
	now := time.Unix(1717171717, 0)
	ns := zone.NewNetworkState()
	addIPsecNode(t, ns, "node-a.catofes.", AcceptInbound, []AddressAdvertisement{{
		ID: "a-public", Source: SourceManualAddress, Address: "198.51.100.10", Priority: 100, Reachability: ReachabilityPublic, TTLSeconds: 300,
	}}, now)
	addIPsecNode(t, ns, "node-b.catofes.", AcceptInbound, []AddressAdvertisement{{
		ID: "b-observed", Source: SourceReflector, Address: "203.0.113.20", Priority: 100, Reachability: ReachabilityNATObserved, TTLSeconds: 300,
	}}, now)
	setIPsecNATProfile(t, ns, "node-b.catofes.", NATProfile{Hint: NATHintBehindNAT, InboundReachable: NATReachableUnknown}, now)
	ns.Zones["node-b.catofes."].Records[RecordKeyPorts] = record(t, "node-b.catofes.", RecordKeyPorts, RecordTypePorts, PortRecord{
		Version: 1,
		Mode:    PortModeFixed,
		Current: &PortSelection{
			Generation: 1,
			IKE:        PortBinding{Advertised: 500, Observed: 35000},
			NATT:       PortBinding{Advertised: 4500, Observed: 35001},
			ValidUntil: now.Add(time.Hour).Unix(),
		},
		UpdatedAt: now.Unix(),
	})

	group := LinkGroupSpec{ID: "ipsec-main", Direction: DirectionOutbound}
	plan, err := PlanTransportLinks(context.Background(), ns, "node-a.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks: %v", err)
	}
	if len(plan.Desired) != 1 {
		t.Fatalf("desired len = %d skips=%+v", len(plan.Desired), plan.Skipped)
	}
	point := plan.Desired[0].ContactPoints[0]
	if !point.ObservedPort || point.IKEPort != 35000 || point.NATTPort != 35001 {
		t.Fatalf("contact point = %+v, want observed external ports", point)
	}
}

func TestPlanTransportLinksAppliesMeshPolicyRules(t *testing.T) {
	now := time.Unix(1717171717, 0)
	ns := zone.NewNetworkState()
	addIPsecNode(t, ns, "node-a.catofes.", AcceptInbound, []AddressAdvertisement{{
		ID: "a-public", Source: SourceManualAddress, Address: "198.51.100.10", Priority: 100, Reachability: ReachabilityPublic, TTLSeconds: 300,
	}}, now)
	addIPsecNode(t, ns, "node-b.catofes.", AcceptInbound, []AddressAdvertisement{
		{ID: "b-manual", Source: SourceManualAddress, Address: "198.51.100.20", Priority: 100, Reachability: ReachabilityPublic, TTLSeconds: 300},
		{ID: "b-discovery", Source: SourceDiscovery, Address: "198.51.100.21", Priority: 1, Reachability: ReachabilityPublic, TTLSeconds: 300},
	}, now)
	addIPsecNode(t, ns, "node-c.catofes.", AcceptNone, []AddressAdvertisement{{
		ID: "c-public", Source: SourceManualAddress, Address: "198.51.100.30", Priority: 100, Reachability: ReachabilityPublic, TTLSeconds: 300,
	}}, now)
	addIPsecNode(t, ns, "node-d.catofes.", AcceptInbound, []AddressAdvertisement{{
		ID: "d-public", Source: SourceManualAddress, Address: "198.51.100.40", Priority: 100, Reachability: ReachabilityPublic, TTLSeconds: 300,
	}}, now)
	addIPsecNode(t, ns, "node-e.catofes.", AcceptInbound, []AddressAdvertisement{{
		ID: "e-discovery", Source: SourceDiscovery, Address: "198.51.100.50", Priority: 100, Reachability: ReachabilityPublic, TTLSeconds: 300,
	}}, now)

	group := LinkGroupSpec{
		ID:           "ipsec-main",
		ConnectRules: []string{"strongswan://*.catofes.?accept=inbound&source=discovery&mode=exhaustive&direction=outbound&max_peers=1"},
		DenyRules:    []string{"strongswan://node-d.catofes."},
	}
	plan, err := PlanTransportLinks(context.Background(), ns, "node-a.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks: %v", err)
	}
	if len(plan.Desired) != 1 {
		t.Fatalf("desired len = %d skips=%+v", len(plan.Desired), plan.Skipped)
	}
	spec := plan.Desired[0]
	if spec.PeerZone != "node-b.catofes." || spec.PathMode != PathModeExhaustive {
		t.Fatalf("spec = %+v", spec)
	}
	if len(spec.ContactPoints) != 1 || spec.ContactPoints[0].Source != SourceDiscovery || spec.ContactPoints[0].Address != "198.51.100.21" {
		t.Fatalf("contact points = %+v, want discovery-only address from policy source filter", spec.ContactPoints)
	}
	if !hasSkip(plan.Skipped, "node-c.catofes.", SkipPolicyNoMatch) {
		t.Fatalf("missing policy no-match skip: %+v", plan.Skipped)
	}
	if !hasSkip(plan.Skipped, "node-d.catofes.", SkipPolicyDenied) {
		t.Fatalf("missing policy denied skip: %+v", plan.Skipped)
	}
	if !hasSkip(plan.Skipped, "node-e.catofes.", SkipMaxPeers) {
		t.Fatalf("missing policy max-peers skip: %+v", plan.Skipped)
	}
}

func TestPlanTransportLinksDryRunDualStackModes(t *testing.T) {
	now := time.Unix(1717171717, 0)
	ns := zone.NewNetworkState()
	addIPsecNode(t, ns, "node-a.catofes.", AcceptInbound, []AddressAdvertisement{{
		ID: "a-public", Source: SourceManualAddress, Address: "198.51.100.10", Priority: 100, Reachability: ReachabilityPublic, TTLSeconds: 300,
	}}, now)
	addIPsecNode(t, ns, "node-b.catofes.", AcceptInbound, []AddressAdvertisement{
		{ID: "b-v4-primary", Source: SourceManualAddress, Address: "198.51.100.20", Priority: 100, Reachability: ReachabilityPublic, TTLSeconds: 300},
		{ID: "b-v4-backup", Source: SourceManualAddress, Address: "198.51.100.21", Priority: 10, Reachability: ReachabilityPublic, TTLSeconds: 300},
		{ID: "b-v6-primary", Source: SourceManualAddress, Address: "2001:db8::20", Priority: 100, Reachability: ReachabilityPublic, TTLSeconds: 300},
		{ID: "b-v6-backup", Source: SourceManualAddress, Address: "2001:db8::21", Priority: 10, Reachability: ReachabilityPublic, TTLSeconds: 300},
	}, now)

	group := LinkGroupSpec{ID: "ipsec-main", Direction: DirectionOutbound, DefaultPathMode: PathModeFamilyRedundant}
	plan, err := PlanTransportLinks(context.Background(), ns, "node-a.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks(family): %v", err)
	}
	if len(plan.Desired) != 1 {
		t.Fatalf("desired len = %d skips=%+v", len(plan.Desired), plan.Skipped)
	}
	points := plan.Desired[0].ContactPoints
	if len(points) != 2 || !familiesInOrder(points, FamilyIPv4, FamilyIPv6) {
		t.Fatalf("family-redundant contacts = %+v, want one IPv4 and one IPv6", points)
	}
	for _, point := range points {
		if point.RankReason == "" {
			t.Fatalf("contact missing rank reason: %+v", point)
		}
	}

	group.DefaultPathMode = PathModeExhaustive
	plan, err = PlanTransportLinks(context.Background(), ns, "node-a.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks(exhaustive): %v", err)
	}
	if len(plan.Desired) != 1 || len(plan.Desired[0].ContactPoints) != 4 {
		t.Fatalf("exhaustive desired = %+v skips=%+v", plan.Desired, plan.Skipped)
	}
}

func TestPlanTransportLinksDryRunDNSRefreshUpdatesContactPoint(t *testing.T) {
	now := time.Unix(1717171717, 0)
	ns := zone.NewNetworkState()
	addIPsecNode(t, ns, "node-a.catofes.", AcceptInbound, []AddressAdvertisement{{
		ID: "a-public", Source: SourceManualAddress, Address: "198.51.100.10", Priority: 100, Reachability: ReachabilityPublic, TTLSeconds: 300,
	}}, now)
	addIPsecNode(t, ns, "node-b.catofes.", AcceptInbound, []AddressAdvertisement{{
		ID: "b-dns", Source: SourceManualDNS, Host: "node-b.example.com", Families: []string{FamilyIPv4}, RefreshSeconds: 30, Priority: 100, Reachability: ReachabilityPublic, TTLSeconds: 300,
	}}, now)

	group := LinkGroupSpec{
		ID:                 "ipsec-main",
		Direction:          DirectionOutbound,
		AddressSourceOrder: []string{SourceManualDNS},
	}
	first, err := PlanTransportLinks(context.Background(), ns, "node-a.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{
		Now: now,
		DNSResolver: staticDNSResolver{
			"node-b.example.com": {{IP: net.ParseIP("198.51.100.20")}},
		},
	})
	if err != nil {
		t.Fatalf("PlanTransportLinks(first): %v", err)
	}
	second, err := PlanTransportLinks(context.Background(), ns, "node-a.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{
		Now: now.Add(31 * time.Second),
		DNSResolver: staticDNSResolver{
			"node-b.example.com": {{IP: net.ParseIP("198.51.100.21")}},
		},
	})
	if err != nil {
		t.Fatalf("PlanTransportLinks(second): %v", err)
	}
	if len(first.Desired) != 1 || len(second.Desired) != 1 {
		t.Fatalf("plans = %+v / %+v", first, second)
	}
	firstPoint := first.Desired[0].ContactPoints[0]
	secondPoint := second.Desired[0].ContactPoints[0]
	if firstPoint.Host != "node-b.example.com" || firstPoint.Address != "198.51.100.20" {
		t.Fatalf("first contact = %+v", firstPoint)
	}
	if secondPoint.Host != "node-b.example.com" || secondPoint.Address != "198.51.100.21" {
		t.Fatalf("second contact = %+v", secondPoint)
	}
	if first.Desired[0].TransportID != second.Desired[0].TransportID || first.Desired[0].XFRMIfID != second.Desired[0].XFRMIfID {
		t.Fatalf("DNS refresh changed stable link identity: %+v vs %+v", first.Desired[0], second.Desired[0])
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
	if instance.Owner.Manager != "higgs" || instance.Owner.Token == "" || instance.DesiredSpecHash == "" {
		t.Fatalf("instance = %+v", instance)
	}
	if err := instance.Owner.Validate(instance); err != nil {
		t.Fatalf("owner should validate: %v", err)
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

func TestReconcileLinkInstancesRetainsUnmanagedInstances(t *testing.T) {
	now := time.Unix(1717171717, 0)
	inst := LinkInstance{
		ID:            "manual-conn",
		GroupID:       "main",
		PeerZone:      "node-b.catofes.",
		TransportKind: ProviderStrongSwan,
		TransportID:   "manual-conn",
		ActualState:   LinkStateUp,
		InterfaceName: "admin0",
		XFRMIfID:      77,
		Owner: ResourceOwner{
			Manager:     "admin",
			GroupID:     "main",
			InstanceID:  "manual-conn",
			TransportID: "manual-conn",
		},
	}
	result := ReconcileLinkInstances(ReconcileInputs{
		Instances: map[string]LinkInstance{inst.ID: inst},
		Now:       now,
	})
	action := firstAction(result, ReconcileActionNoop)
	if action == nil || !strings.Contains(action.Reason, "unmanaged resource retained") {
		t.Fatalf("actions = %+v, want retained unmanaged noop", result.Actions)
	}
	if result.Instances[inst.ID].ActualState != LinkStateUp {
		t.Fatalf("instance state changed: %+v", result.Instances[inst.ID])
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

func TestReconcileLinkInstancesHonorsApplyBackoff(t *testing.T) {
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
	inst := NewLinkInstance(spec, LinkStateUp, now)
	inst = MarkLinkApplyFailure(inst, BackoffPolicy{InitialSeconds: 2, MaxSeconds: 8}, now, errors.New("load connection: vici unavailable"))
	if inst.FailureCount != 1 || inst.BackoffUntil != now.Add(2*time.Second).Unix() || inst.LastError == "" {
		t.Fatalf("failed instance = %+v", inst)
	}
	inst = MarkLinkApplyFailure(inst, BackoffPolicy{InitialSeconds: 2, MaxSeconds: 8}, now.Add(time.Second), errors.New("load connection: vici unavailable"))
	if inst.FailureCount != 2 || inst.BackoffUntil != now.Add(5*time.Second).Unix() {
		t.Fatalf("second failed instance = %+v", inst)
	}

	duringBackoff := ReconcileLinkInstances(ReconcileInputs{
		Desired:   []TransportLinkSpec{spec},
		Instances: map[string]LinkInstance{inst.ID: inst},
		Now:       now.Add(3 * time.Second),
	})
	if action := firstAction(duringBackoff, ReconcileActionNoop); action == nil || action.Reason != "apply backoff active" {
		t.Fatalf("during backoff actions = %+v", duringBackoff.Actions)
	}

	afterBackoff := ReconcileLinkInstances(ReconcileInputs{
		Desired:   []TransportLinkSpec{spec},
		Instances: map[string]LinkInstance{inst.ID: inst},
		Now:       now.Add(6 * time.Second),
	})
	if action := firstAction(afterBackoff, ReconcileActionRepair); action == nil {
		t.Fatalf("after backoff actions = %+v", afterBackoff.Actions)
	}
	cleared := MarkLinkApplySuccess(inst, now.Add(6*time.Second))
	if cleared.FailureCount != 0 || cleared.BackoffUntil != 0 || cleared.LastError != "" {
		t.Fatalf("cleared instance = %+v", cleared)
	}
}

func TestReconcileLinkInstancesRetriesConnectingWithoutSAAfterBackoff(t *testing.T) {
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
	inst := NewLinkInstance(spec, LinkStateConnecting, now)

	waiting := ReconcileLinkInstances(ReconcileInputs{
		Desired:   []TransportLinkSpec{spec},
		Instances: map[string]LinkInstance{inst.ID: inst},
		Now:       now.Add(time.Second),
		GroupBackoff: map[string]BackoffPolicy{
			spec.OverlayID: {InitialSeconds: 2, MaxSeconds: 8},
		},
	})
	if action := firstAction(waiting, ReconcileActionNoop); action == nil || action.Reason != "awaiting established sa" {
		t.Fatalf("waiting actions = %+v", waiting.Actions)
	}
	waitingInst := waiting.Instances[inst.ID]
	if waitingInst.ActualState != LinkStateError || waitingInst.FailureCount != 1 || waitingInst.BackoffUntil != now.Add(3*time.Second).Unix() {
		t.Fatalf("waiting instance = %+v, want error with backoff", waitingInst)
	}

	duringBackoff := ReconcileLinkInstances(ReconcileInputs{
		Desired:   []TransportLinkSpec{spec},
		Instances: map[string]LinkInstance{inst.ID: waitingInst},
		Now:       now.Add(2 * time.Second),
	})
	if action := firstAction(duringBackoff, ReconcileActionNoop); action == nil || action.Reason != "apply backoff active" {
		t.Fatalf("during backoff actions = %+v", duringBackoff.Actions)
	}

	afterBackoff := ReconcileLinkInstances(ReconcileInputs{
		Desired:   []TransportLinkSpec{spec},
		Instances: map[string]LinkInstance{inst.ID: waitingInst},
		Now:       now.Add(4 * time.Second),
	})
	if action := firstAction(afterBackoff, ReconcileActionRepair); action == nil || action.Reason != "previous apply failed" {
		t.Fatalf("after backoff actions = %+v", afterBackoff.Actions)
	}
	if afterBackoff.Instances[inst.ID].ActualState != LinkStateDegraded {
		t.Fatalf("after backoff instance = %+v, want degraded repair", afterBackoff.Instances[inst.ID])
	}
}

func TestReconcileLinkInstancesEstablishedSAWinsOverBackoff(t *testing.T) {
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
	inst := NewLinkInstance(spec, LinkStateConnecting, now)
	inst = MarkLinkApplyFailure(inst, BackoffPolicy{InitialSeconds: 10, MaxSeconds: 10}, now, errors.New("waiting for established SA"))

	recovered := ReconcileLinkInstances(ReconcileInputs{
		Desired:   []TransportLinkSpec{spec},
		Instances: map[string]LinkInstance{inst.ID: inst},
		SAs: []SAState{{
			Name:        spec.TransportID,
			ChildSA:     ChildSAName(spec),
			XFRMIfID:    spec.XFRMIfID,
			Endpoint:    "198.51.100.20",
			Established: true,
		}},
		Now: now.Add(time.Second),
	})
	if action := firstAction(recovered, ReconcileActionAdopt); action == nil || action.Reason != "driver state recovered" {
		t.Fatalf("recovered actions = %+v", recovered.Actions)
	}
	got := recovered.Instances[inst.ID]
	if got.ActualState != LinkStateUp || got.FailureCount != 0 || got.BackoffUntil != 0 || got.LastError != "" {
		t.Fatalf("recovered instance = %+v, want up with cleared backoff", got)
	}
}

func setIPsecNATProfile(t *testing.T, ns *zone.NetworkState, peer zone.ZonePath, nat NATProfile, now time.Time) {
	t.Helper()
	zs := ns.Zones[peer]
	fingerprint := "fp-" + string(peer)
	zs.Records[RecordKeyProfile] = record(t, peer, RecordKeyProfile, RecordTypeProfile, ProfileRecord{
		Version:                 1,
		Enabled:                 true,
		Provider:                ProviderStrongSwan,
		IKEIdentity:             string(peer),
		TransportKeyFingerprint: fingerprint,
		Accept:                  AcceptInbound,
		AddressFamilies:         []string{FamilyIPv4, FamilyIPv6},
		PathModes:               []string{PathModeFamilyRedundant, PathModeExhaustive},
		NAT:                     nat,
		UpdatedAt:               now.Unix(),
	})
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

func familiesInOrder(points []ContactPoint, families ...string) bool {
	if len(points) != len(families) {
		return false
	}
	for i, family := range families {
		if points[i].Family != family || !strings.Contains(points[i].RankReason, points[i].Source) {
			return false
		}
	}
	return true
}

func firstAction(result ReconcileResult, action string) *ReconcileAction {
	for i := range result.Actions {
		if result.Actions[i].Action == action {
			return &result.Actions[i]
		}
	}
	return nil
}
