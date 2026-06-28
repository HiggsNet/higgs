package ipsec

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"time"

	"github.com/Catofes/higgs/pkg/core/zone"
	higgscrypto "github.com/Catofes/higgs/pkg/crypto"
)

const (
	SkipLocalZone            = "local_zone"
	SkipRevokedZone          = "revoked_zone"
	SkipMissingRecords       = "missing_ipsec_records"
	SkipDisabledProfile      = "disabled_profile"
	SkipUnsupportedPathMode  = "unsupported_path_mode"
	SkipUnsupportedFamily    = "unsupported_address_family"
	SkipAcceptIntentMismatch = "accept_intent_mismatch"
	SkipNoContactPoints      = "no_contact_points"
	SkipNoInboundNATEvidence = "no_inbound_nat_evidence"
	SkipPolicyDenied         = "policy_denied"
	SkipPolicyNoMatch        = "policy_no_match"
	SkipMaxPeers             = "max_peers"
	SkipPlannerError         = "planner_error"
)

type LinkPlannerOptions struct {
	Now                 time.Time
	DNSResolver         DNSResolver
	AllowPrivateLocal   bool
	ContactPointQuality map[zone.ZonePath]map[string]ContactPointQuality
}

type LinkPlan struct {
	Desired []TransportLinkSpec
	Skipped []PlanSkip
	Roles   map[string]string // instance ID -> InitiatorRole
}

type PlanSkip struct {
	GroupID string
	Peer    zone.ZonePath
	Reason  string
	Detail  string
}

func PlanTransportLinks(ctx context.Context, ns *zone.NetworkState, local zone.ZonePath, groups []LinkGroupSpec, opts LinkPlannerOptions) (LinkPlan, error) {
	if ns == nil {
		return LinkPlan{}, fmt.Errorf("network state is nil")
	}
	if !local.Valid() || local.IsRoot() {
		return LinkPlan{}, fmt.Errorf("local zone must be a non-root zone")
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	peers := sortedZones(ns)
	plan := LinkPlan{Roles: map[string]string{}}
	for _, group := range groups {
		if err := group.Validate(); err != nil {
			return plan, err
		}
		group = group.Normalized()
		connectRules, err := ParseMeshPolicyRules(group.ConnectRules)
		if err != nil {
			return plan, err
		}
		denyRules, err := ParseMeshPolicyRules(group.DenyRules)
		if err != nil {
			return plan, err
		}
		selectedPeers := 0
		linkIndex := 0
		for _, peer := range peers {
			if peer == local {
				plan.skip(group.ID, peer, SkipLocalZone, "")
				continue
			}
			if ns.IsZoneRevoked(peer, now) {
				plan.skip(group.ID, peer, SkipRevokedZone, "")
				continue
			}
			specs, ok, skip, nextIndex, err := planPeerLink(ctx, ns, local, peer, group, connectRules, denyRules, selectedPeers, linkIndex, now, opts)
			if err != nil {
				plan.skip(group.ID, peer, SkipPlannerError, err.Error())
				continue
			}
			if !ok {
				plan.Skipped = append(plan.Skipped, skip)
				continue
			}
			for _, spec := range specs {
				plan.Desired = append(plan.Desired, spec)
				plan.Roles[LinkInstanceID(spec)] = spec.InitiatorRole
			}
			selectedPeers++
			linkIndex = nextIndex
		}
	}
	sort.SliceStable(plan.Desired, func(i, j int) bool {
		if plan.Desired[i].OverlayID != plan.Desired[j].OverlayID {
			return plan.Desired[i].OverlayID < plan.Desired[j].OverlayID
		}
		if plan.Desired[i].PeerZone != plan.Desired[j].PeerZone {
			return plan.Desired[i].PeerZone < plan.Desired[j].PeerZone
		}
		return plan.Desired[i].TransportID < plan.Desired[j].TransportID
	})
	return plan, nil
}

func planPeerLink(ctx context.Context, ns *zone.NetworkState, local, peer zone.ZonePath, group LinkGroupSpec, connectRules, denyRules []MeshPolicyRule, selectedPeers, linkIndex int, now time.Time, opts LinkPlannerOptions) ([]TransportLinkSpec, bool, PlanSkip, int, error) {
	records, err := ExtractNodeRecords(ns, peer, now)
	if err != nil {
		return nil, false, PlanSkip{GroupID: group.ID, Peer: peer, Reason: SkipMissingRecords, Detail: err.Error()}, linkIndex, nil
	}
	if records.Profile == nil || records.Addresses == nil || records.Ports == nil || records.TransportKey == nil {
		return nil, false, PlanSkip{GroupID: group.ID, Peer: peer, Reason: SkipMissingRecords}, linkIndex, nil
	}
	effectiveGroup, ok, skip, err := applyMeshPolicyRules(group, peer, records, connectRules, denyRules)
	if err != nil {
		return nil, false, PlanSkip{}, linkIndex, err
	}
	if !ok {
		return nil, false, skip, linkIndex, nil
	}
	group = effectiveGroup
	if group.MaxPeers > 0 && selectedPeers >= group.MaxPeers {
		return nil, false, PlanSkip{GroupID: group.ID, Peer: peer, Reason: SkipMaxPeers}, linkIndex, nil
	}
	if !records.Profile.Enabled {
		return nil, false, PlanSkip{GroupID: group.ID, Peer: peer, Reason: SkipDisabledProfile}, linkIndex, nil
	}
	if !oneOf(group.DefaultPathMode, records.Profile.PathModes...) {
		return nil, false, PlanSkip{GroupID: group.ID, Peer: peer, Reason: SkipUnsupportedPathMode, Detail: group.DefaultPathMode}, linkIndex, nil
	}
	if !familiesOverlap(records.Profile.AddressFamilies, recordFamilies(records.Addresses)) {
		return nil, false, PlanSkip{GroupID: group.ID, Peer: peer, Reason: SkipUnsupportedFamily}, linkIndex, nil
	}
	localAccept := localAcceptFromState(ns, local, now)
	remoteAccept := records.Profile.Accept
	role := InitiatorRoleForPeer(local, peer, localAccept, remoteAccept)
	if role == "" && !canLoadResponder(localAccept) {
		return nil, false, PlanSkip{GroupID: group.ID, Peer: peer, Reason: SkipAcceptIntentMismatch, Detail: fmt.Sprintf("local=%s remote=%s", localAccept, remoteAccept)}, linkIndex, nil
	}

	var contacts []ContactPoint
	// Both primary and secondary-standby need contact points: primary dials
	// immediately, secondary-standby may need them for takeover. Responder-only
	// roles (empty role) do not resolve remote contacts.
	if role != "" {
		allContacts, err := ResolveContactPoints(ctx, records.Addresses, records.Ports, now, AddressCandidateOptions{
			DNSResolver:       opts.DNSResolver,
			SourceOrder:       group.AddressSourceOrder,
			AllowedSources:    group.AddressSourceOrder,
			AllowPrivateLocal: opts.AllowPrivateLocal,
			Now:               now,
			ContactQuality:    opts.ContactPointQuality[peer],
		})
		if err != nil {
			return nil, false, PlanSkip{}, linkIndex, err
		}
		contacts = SelectContactPointsWithOptions(allContacts, group.DefaultPathMode, AddressCandidateOptions{
			SourceOrder:    group.AddressSourceOrder,
			Now:            now,
			ContactQuality: opts.ContactPointQuality[peer],
		})
		if remoteNeedsInboundNATEvidence(records.Profile) {
			contacts = filterInboundNATEvidence(contacts)
			if len(contacts) == 0 {
				return nil, false, PlanSkip{GroupID: group.ID, Peer: peer, Reason: SkipNoInboundNATEvidence, Detail: natEvidenceDetail(records.Profile)}, linkIndex, nil
			}
		}
		if len(contacts) == 0 {
			return nil, false, PlanSkip{GroupID: group.ID, Peer: peer, Reason: SkipNoContactPoints}, linkIndex, nil
		}
	}

	var specs []TransportLinkSpec
	nextIndex := linkIndex
	switch group.DefaultPathMode {
	case PathModeFamilyRedundant:
		byFamily := groupContactPointsByFamily(contacts)
		if len(byFamily) == 0 {
			// Responder-only spec (no contacts).
			spec, err := newSpecForFamily(local, peer, group, records, nil, "", linkIndex)
			if err != nil {
				return nil, false, PlanSkip{}, linkIndex, err
			}
			spec.InitiatorRole = role
			specs = append(specs, spec)
			nextIndex = linkIndex + 1
			break
		}
		familyIdx := 0
		for _, family := range sortedFamilies(byFamily) {
			familyContacts := byFamily[family]
			spec, err := newSpecForFamily(local, peer, group, records, familyContacts, family, linkIndex+familyIdx)
			if err != nil {
				return nil, false, PlanSkip{}, linkIndex, err
			}
			spec.InitiatorRole = role
			specs = append(specs, spec)
			familyIdx++
		}
		nextIndex = linkIndex + len(byFamily)
	default:
		spec, err := newSpecForFamily(local, peer, group, records, contacts, "", linkIndex)
		if err != nil {
			return nil, false, PlanSkip{}, linkIndex, err
		}
		spec.InitiatorRole = role
		specs = append(specs, spec)
		nextIndex = linkIndex + 1
	}

	localGeneration := localPortGeneration(ns, local, now)
	localIKE := localIKEPortFromState(ns, local, now)
	for i := range specs {
		spec := &specs[i]
		if IsActiveInitiatorRole(spec.InitiatorRole) {
			if point, ok := firstContactPoint(spec.ContactPoints); ok {
				spec.Generation = point.Generation
			}
		} else if localGeneration != 0 {
			spec.Generation = localGeneration
		}
		if localIKE != 0 {
			spec.LocalIKEPort = localIKE
		}
	}
	return specs, true, PlanSkip{}, nextIndex, nil
}

func newSpecForFamily(local, peer zone.ZonePath, group LinkGroupSpec, records *NodeRecords, contacts []ContactPoint, family string, linkIndex int) (TransportLinkSpec, error) {
	transportID := StableTransportID(local, peer, group.ID)
	if family != "" {
		transportID = StableTransportID(local, peer, group.ID, family)
	}
	spec, err := NewTransportLinkSpecWithOptions(local, peer, group.ID, records, contacts, TransportLinkOptions{
		TransportID:     transportID,
		Provider:        group.Provider,
		PathMode:        group.DefaultPathMode,
		NetNS:           group.NetNS.Target(),
		LocalTunnelAddr: netip.Addr{},
		PeerTunnelAddr:  netip.Addr{},
	})
	if err != nil {
		return TransportLinkSpec{}, err
	}
	addressIndex := linkIndex
	switch group.normalizedTunnelAddress().Mode {
	case TunnelAddressDerivedLinkLocal, TunnelAddressDerivedPool:
		addressIndex = stableTunnelAddressIndex(local, peer, group.ID, family)
	}
	localAddr, peerAddr, err := group.DeriveTunnelAddresses(local, peer, addressIndex)
	if err != nil {
		return TransportLinkSpec{}, err
	}
	if group.normalizedTunnelAddress().Mode == TunnelAddressSequentialPool && peer < local {
		localAddr, peerAddr = peerAddr, localAddr
	}
	spec.LocalTunnelAddr = localAddr
	spec.PeerTunnelAddr = peerAddr
	return spec, nil
}

func stableTunnelAddressIndex(local, peer zone.ZonePath, overlayID, family string) int {
	hash := higgscrypto.Hash([]byte(local), []byte{0}, []byte(peer), []byte{0}, []byte(overlayID), []byte{0}, []byte(family))
	return int(binary.BigEndian.Uint32(hash[:4]) & 0x7fffffff)
}

func canLoadResponder(localAccept string) bool {
	return localAccept == AcceptInbound || localAccept == AcceptBidirectional
}

func localAcceptFromState(ns *zone.NetworkState, local zone.ZonePath, now time.Time) string {
	if ns == nil || !local.Valid() {
		return AcceptBidirectional
	}
	records, err := ExtractNodeRecords(ns, local, now)
	if err != nil {
		return AcceptBidirectional
	}
	if records.Profile != nil && records.Profile.Accept != "" {
		return records.Profile.Accept
	}
	return AcceptBidirectional
}

func localPortGeneration(ns *zone.NetworkState, local zone.ZonePath, now time.Time) uint64 {
	if ns == nil || ns.Zones[local] == nil {
		return 0
	}
	records, err := ExtractNodeRecords(ns, local, now)
	if err != nil {
		return 0
	}
	if records.Ports != nil && records.Ports.Current != nil {
		return records.Ports.Current.Generation
	}
	return 0
}

func localIKEPortFromState(ns *zone.NetworkState, local zone.ZonePath, now time.Time) uint16 {
	if ns == nil || ns.Zones[local] == nil {
		return 0
	}
	records, err := ExtractNodeRecords(ns, local, now)
	if err != nil {
		return 0
	}
	return localIKEPort(records)
}

func localIKEPort(records *NodeRecords) uint16 {
	if records == nil || records.Ports == nil || records.Ports.Current == nil {
		return 0
	}
	binding := records.Ports.Current.IKE
	// Local is the port charon actually binds to. If it is non-default,
	// tell StrongSwan explicitly. If it is the default IKE port, leave
	// LocalIKEPort zero so charon uses its normal listener.
	if binding.Local != 0 && binding.Local != DefaultIKEPort {
		return binding.Local
	}
	return 0
}

func groupContactPointsByFamily(contacts []ContactPoint) map[string][]ContactPoint {
	out := map[string][]ContactPoint{}
	for _, point := range contacts {
		family := point.Family
		if family == "" {
			family = inferIPFamily(point.Address)
		}
		if family == "" {
			continue
		}
		out[family] = append(out[family], point)
	}
	return out
}

func sortedFamilies(byFamily map[string][]ContactPoint) []string {
	families := make([]string, 0, len(byFamily))
	for family := range byFamily {
		families = append(families, family)
	}
	sort.Strings(families)
	return families
}

func applyMeshPolicyRules(group LinkGroupSpec, peer zone.ZonePath, records *NodeRecords, connectRules, denyRules []MeshPolicyRule) (LinkGroupSpec, bool, PlanSkip, error) {
	for _, rule := range denyRules {
		if meshRuleMatchesPeer(rule, peer, records) {
			return LinkGroupSpec{}, false, PlanSkip{GroupID: group.ID, Peer: peer, Reason: SkipPolicyDenied, Detail: rule.Raw}, nil
		}
	}
	if len(connectRules) == 0 {
		return group, true, PlanSkip{}, nil
	}
	for _, rule := range connectRules {
		if !meshRuleMatchesPeer(rule, peer, records) {
			continue
		}
		effective := applyMeshRuleToGroup(group, rule)
		if err := effective.Validate(); err != nil {
			return LinkGroupSpec{}, false, PlanSkip{}, err
		}
		return effective.Normalized(), true, PlanSkip{}, nil
	}
	return LinkGroupSpec{}, false, PlanSkip{GroupID: group.ID, Peer: peer, Reason: SkipPolicyNoMatch}, nil
}

func meshRuleMatchesPeer(rule MeshPolicyRule, peer zone.ZonePath, records *NodeRecords) bool {
	if rule.ZonePattern != "" && !rule.MatchesZone(peer) {
		return false
	}
	// Role/tag selectors are parsed and validated, but peer labels are not part of
	// the signed IPsec records yet. Until that source exists, they never match.
	if rule.Role != "" || rule.Tag != "" {
		return false
	}
	if rule.Accept != "" && (records == nil || records.Profile == nil || records.Profile.Accept != rule.Accept) {
		return false
	}
	if rule.Family != "" && rule.Family != RuleFamilyDual {
		if records == nil || records.Profile == nil || !oneOf(rule.Family, records.Profile.AddressFamilies...) {
			return false
		}
		if records.Addresses == nil || !oneOf(rule.Family, recordFamilies(records.Addresses)...) {
			return false
		}
	}
	return true
}

func applyMeshRuleToGroup(group LinkGroupSpec, rule MeshPolicyRule) LinkGroupSpec {
	out := group
	if rule.PathMode != "" {
		out.DefaultPathMode = rule.PathMode
	}
	if len(rule.Sources) > 0 {
		out.AddressSourceOrder = append([]string(nil), rule.Sources...)
	}
	if rule.MaxPeers >= 0 {
		out.MaxPeers = rule.MaxPeers
	}
	return out
}

func sortedZones(ns *zone.NetworkState) []zone.ZonePath {
	out := make([]zone.ZonePath, 0, len(ns.Zones))
	for peer := range ns.Zones {
		if peer.IsRoot() {
			continue
		}
		out = append(out, peer)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func (p *LinkPlan) skip(groupID string, peer zone.ZonePath, reason, detail string) {
	p.Skipped = append(p.Skipped, PlanSkip{GroupID: groupID, Peer: peer, Reason: reason, Detail: detail})
}

func recordFamilies(record *AddressRecord) []string {
	if record == nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, address := range record.Addresses {
		for _, family := range addressFamilies(address) {
			if seen[family] {
				continue
			}
			seen[family] = true
			out = append(out, family)
		}
	}
	return out
}

func familiesOverlap(left, right []string) bool {
	for _, l := range left {
		for _, r := range right {
			if l == r {
				return true
			}
		}
	}
	return false
}

func remoteNeedsInboundNATEvidence(profile *ProfileRecord) bool {
	if profile == nil {
		return false
	}
	return profile.NAT.Hint == NATHintBehindNAT || profile.NAT.InboundReachable == NATReachableFalse
}

func filterInboundNATEvidence(points []ContactPoint) []ContactPoint {
	out := make([]ContactPoint, 0, len(points))
	for _, point := range points {
		if contactHasInboundNATEvidence(point) {
			out = append(out, point)
		}
	}
	return out
}

func contactHasInboundNATEvidence(point ContactPoint) bool {
	if point.Reachability == ReachabilityPublic {
		return true
	}
	if point.Reachability == ReachabilityNATObserved && point.ObservedPort {
		return true
	}
	ip := net.ParseIP(point.Address)
	return point.Family == FamilyIPv6 && ip != nil && !isPrivateOrLinkLocal(ip) && !ip.IsUnspecified()
}

func natEvidenceDetail(profile *ProfileRecord) string {
	if profile == nil {
		return ""
	}
	if profile.NAT.Hint != "" && profile.NAT.InboundReachable != "" {
		return fmt.Sprintf("nat.hint=%s inbound_reachable=%s requires public IPv6/address, port mapping, observed external port, hole punching, or relay", profile.NAT.Hint, profile.NAT.InboundReachable)
	}
	if profile.NAT.Hint != "" {
		return fmt.Sprintf("nat.hint=%s requires public IPv6/address, port mapping, observed external port, hole punching, or relay", profile.NAT.Hint)
	}
	return fmt.Sprintf("inbound_reachable=%s requires public IPv6/address, port mapping, observed external port, hole punching, or relay", profile.NAT.InboundReachable)
}
