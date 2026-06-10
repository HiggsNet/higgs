package ipsec

import (
	"context"
	"fmt"
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
	SkipMaxPeers             = "max_peers"
	SkipPlannerError         = "planner_error"
)

type LinkPlannerOptions struct {
	Now               time.Time
	DNSResolver       DNSResolver
	AllowPrivateLocal bool
}

type LinkPlan struct {
	Desired []TransportLinkSpec
	Skipped []PlanSkip
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
	plan := LinkPlan{}
	for _, group := range groups {
		if err := group.Validate(); err != nil {
			return plan, err
		}
		group = group.Normalized()
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
			if group.MaxPeers > 0 && selectedPeers >= group.MaxPeers {
				plan.skip(group.ID, peer, SkipMaxPeers, "")
				continue
			}
			spec, ok, skip, err := planPeerLink(ctx, ns, local, peer, group, linkIndex, now, opts)
			if err != nil {
				plan.skip(group.ID, peer, SkipPlannerError, err.Error())
				continue
			}
			if !ok {
				plan.Skipped = append(plan.Skipped, skip)
				continue
			}
			plan.Desired = append(plan.Desired, spec)
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

func planPeerLink(ctx context.Context, ns *zone.NetworkState, local, peer zone.ZonePath, group LinkGroupSpec, linkIndex int, now time.Time, opts LinkPlannerOptions) (TransportLinkSpec, bool, PlanSkip, error) {
	records, err := ExtractNodeRecords(ns, peer, now)
	if err != nil {
		return TransportLinkSpec{}, false, PlanSkip{GroupID: group.ID, Peer: peer, Reason: SkipMissingRecords, Detail: err.Error()}, nil
	}
	if records.Profile == nil || records.Addresses == nil || records.Ports == nil || records.TransportKey == nil {
		return TransportLinkSpec{}, false, PlanSkip{GroupID: group.ID, Peer: peer, Reason: SkipMissingRecords}, nil
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
	initiate := ShouldInitiate(local, peer, group.Direction, records.Profile.Accept)
	if group.Direction != DirectionInbound && !initiate {
		return TransportLinkSpec{}, false, PlanSkip{GroupID: group.ID, Peer: peer, Reason: SkipAcceptIntentMismatch, Detail: records.Profile.Accept}, nil
	}
	var contacts []ContactPoint
	if group.Direction != DirectionInbound {
		allContacts, err := ResolveContactPoints(ctx, records.Addresses, records.Ports, now, AddressCandidateOptions{
			DNSResolver:       opts.DNSResolver,
			SourceOrder:       group.AddressSourceOrder,
			AllowedSources:    group.AddressSourceOrder,
			AllowPrivateLocal: opts.AllowPrivateLocal,
		})
		if err != nil {
			return TransportLinkSpec{}, false, PlanSkip{}, err
		}
		contacts = SelectContactPoints(allContacts, group.DefaultPathMode)
		if len(contacts) == 0 {
			return TransportLinkSpec{}, false, PlanSkip{GroupID: group.ID, Peer: peer, Reason: SkipNoContactPoints}, nil
		}
	}
	spec, err := NewTransportLinkSpecForGroup(local, peer, group, records, contacts, linkIndex)
	if err != nil {
		return TransportLinkSpec{}, false, PlanSkip{}, err
	}
	return spec, true, PlanSkip{}, nil
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
