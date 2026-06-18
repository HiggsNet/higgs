package ipsec

import (
	"context"
	"fmt"
	"net"
	"sort"
	"time"

	"github.com/Catofes/higgs/pkg/core/zone"
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
			spec, ok, skip, err := planPeerLink(ctx, ns, local, peer, group, connectRules, denyRules, selectedPeers, linkIndex, now, opts)
			if err != nil {
				plan.skip(group.ID, peer, SkipPlannerError, err.Error())
				continue
			}
			if !ok {
				plan.Skipped = append(plan.Skipped, skip)
				continue
			}
			plan.Desired = append(plan.Desired, spec)
			plan.Roles[LinkInstanceID(spec)] = spec.InitiatorRole
			selectedPeers++
			linkIndex++
		}
	}
	sort.SliceStable(plan.Desired, func(i, j int) bool {
		if plan.Desired[i].OverlayID != plan.Desired[j].OverlayID {
			return plan.Desired[i].OverlayID < plan.Desired[j].OverlayID
		}
		return plan.Desired[i].PeerZone < plan.Desired[j].PeerZone
	})
	return plan, nil
}

func planPeerLink(ctx context.Context, ns *zone.NetworkState, local, peer zone.ZonePath, group LinkGroupSpec, connectRules, denyRules []MeshPolicyRule, selectedPeers, linkIndex int, now time.Time, opts LinkPlannerOptions) (TransportLinkSpec, bool, PlanSkip, error) {
	records, err := ExtractNodeRecords(ns, peer, now)
	if err != nil {
		return TransportLinkSpec{}, false, PlanSkip{GroupID: group.ID, Peer: peer, Reason: SkipMissingRecords, Detail: err.Error()}, nil
	}
	if records.Profile == nil || records.Addresses == nil || records.Ports == nil || records.TransportKey == nil {
		return TransportLinkSpec{}, false, PlanSkip{GroupID: group.ID, Peer: peer, Reason: SkipMissingRecords}, nil
	}
	effectiveGroup, ok, skip, err := applyMeshPolicyRules(group, peer, records, connectRules, denyRules)
	if err != nil {
		return TransportLinkSpec{}, false, PlanSkip{}, err
	}
	if !ok {
		return TransportLinkSpec{}, false, skip, nil
	}
	group = effectiveGroup
	if group.MaxPeers > 0 && selectedPeers >= group.MaxPeers {
		return TransportLinkSpec{}, false, PlanSkip{GroupID: group.ID, Peer: peer, Reason: SkipMaxPeers}, nil
	}
	if !records.Profile.Enabled {
		return TransportLinkSpec{}, false, PlanSkip{GroupID: group.ID, Peer: peer, Reason: SkipDisabledProfile}, nil
	}
	if !oneOf(group.DefaultPathMode, records.Profile.PathModes...) {
		return TransportLinkSpec{}, false, PlanSkip{GroupID: group.ID, Peer: peer, Reason: SkipUnsupportedPathMode, Detail: group.DefaultPathMode}, nil
	}
	if !familiesOverlap(records.Profile.AddressFamilies, recordFamilies(records.Addresses)) {
		return TransportLinkSpec{}, false, PlanSkip{GroupID: group.ID, Peer: peer, Reason: SkipUnsupportedFamily}, nil
	}
	role := InitiatorRoleForPeer(local, peer, group.Direction, records.Profile.Accept)
	if role == "" {
		return TransportLinkSpec{}, false, PlanSkip{GroupID: group.ID, Peer: peer, Reason: SkipAcceptIntentMismatch, Detail: records.Profile.Accept}, nil
	}
	var contacts []ContactPoint
	if group.Direction != DirectionInbound {
		allContacts, err := ResolveContactPoints(ctx, records.Addresses, records.Ports, now, AddressCandidateOptions{
			DNSResolver:       opts.DNSResolver,
			SourceOrder:       group.AddressSourceOrder,
			AllowedSources:    group.AddressSourceOrder,
			AllowPrivateLocal: opts.AllowPrivateLocal,
			Now:               now,
			ContactQuality:    opts.ContactPointQuality[peer],
		})
		if err != nil {
			return TransportLinkSpec{}, false, PlanSkip{}, err
		}
		contacts = SelectContactPointsWithOptions(allContacts, group.DefaultPathMode, AddressCandidateOptions{
			SourceOrder:    group.AddressSourceOrder,
			Now:            now,
			ContactQuality: opts.ContactPointQuality[peer],
		})
		if remoteNeedsInboundNATEvidence(records.Profile) {
			contacts = filterInboundNATEvidence(contacts)
			if len(contacts) == 0 {
				return TransportLinkSpec{}, false, PlanSkip{GroupID: group.ID, Peer: peer, Reason: SkipNoInboundNATEvidence, Detail: natEvidenceDetail(records.Profile)}, nil
			}
		}
		if len(contacts) == 0 {
			return TransportLinkSpec{}, false, PlanSkip{GroupID: group.ID, Peer: peer, Reason: SkipNoContactPoints}, nil
		}
	}
	spec, err := NewTransportLinkSpecForGroup(local, peer, group, records, contacts, linkIndex)
	if err != nil {
		return TransportLinkSpec{}, false, PlanSkip{}, err
	}
	if ns.Zones[local] != nil {
		localRecords, err := ExtractNodeRecords(ns, local, now)
		if err != nil {
			return TransportLinkSpec{}, false, PlanSkip{}, err
		}
		if localRecords.Ports != nil && localRecords.Ports.Current != nil {
			spec.LocalIKEPort = dialPort(localRecords.Ports.Current.IKE)
			if group.Direction == DirectionInbound {
				spec.Generation = localRecords.Ports.Current.Generation
			}
		}
	}
	if group.Direction != DirectionInbound {
		if point, ok := firstContactPoint(contacts); ok {
			spec.Generation = point.Generation
		}
	}
	spec.InitiatorRole = role
	return spec, true, PlanSkip{}, nil
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
	if rule.Direction != "" {
		out.Direction = rule.Direction
	}
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
