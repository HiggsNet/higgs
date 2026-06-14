package routing

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/Catofes/higgs/pkg/core/zone"
)

// RouteEntry represents an active, authorized route announcement.
type RouteEntry struct {
	Record       *zone.Record
	Source       zone.ZonePath
	Prefix       netip.Prefix
	Announcement *RouteAnnouncementRecord
}

// AssignmentEntry represents an active IPAM assignment record.
type AssignmentEntry struct {
	Prefix     netip.Prefix
	AssignedTo zone.ZonePath
	Source     zone.ZonePath
	Record     *zone.Record
	Assignment *IPAMAssignmentRecord
}

// PoolEntry represents an active IPAM pool record.
type PoolEntry struct {
	Prefix      netip.Prefix
	DelegatedTo zone.ZonePath
	Source      zone.ZonePath
	Record      *zone.Record
	Pool        *IPAMPoolRecord
}

// RouteAuthorizationError captures a non-fatal validation problem.
type RouteAuthorizationError struct {
	Zone   zone.ZonePath
	Prefix netip.Prefix
	Code   string
	Detail string
}

// AuthorizedRouteSet is the result of reconciling announcements with IPAM state.
type AuthorizedRouteSet struct {
	Announced   map[zone.ZonePath]map[netip.Prefix]*RouteEntry
	Assignments map[netip.Prefix]*AssignmentEntry
	Pools       map[netip.Prefix]*PoolEntry
	Errors      []RouteAuthorizationError
}

// BuildAuthorizedRouteSet builds an authorized route set from verified active state.
func BuildAuthorizedRouteSet(ns *zone.NetworkState, now time.Time) (*AuthorizedRouteSet, error) {
	if ns == nil {
		return nil, errors.New("network state is nil")
	}

	ars := &AuthorizedRouteSet{
		Announced:   make(map[zone.ZonePath]map[netip.Prefix]*RouteEntry),
		Assignments: make(map[netip.Prefix]*AssignmentEntry),
		Pools:       make(map[netip.Prefix]*PoolEntry),
	}

	var pending []*RouteEntry

	for path, zs := range ns.Zones {
		revoked := ns.IsZoneRevoked(path, now)

		for key, rec := range zs.Records {
			switch {
			case strings.HasPrefix(key, RecordKeyPrefixIPAMPools):
				pool, err := ParseIPAMPoolRecord(rec)
				if err != nil {
					ars.addError(path, netip.Prefix{}, "ipam_pool_invalid", err.Error())
					continue
				}
				p := mustParsePrefix(pool.Prefix)
				ars.Pools[p] = &PoolEntry{
					Prefix:      p,
					DelegatedTo: pool.DelegatedTo,
					Source:      path,
					Record:      rec,
					Pool:        pool,
				}

			case strings.HasPrefix(key, RecordKeyPrefixIPAMAssignments):
				assignment, err := ParseIPAMAssignmentRecord(rec)
				if err != nil {
					ars.addError(path, netip.Prefix{}, "ipam_assignment_invalid", err.Error())
					continue
				}
				p := mustParsePrefix(assignment.Prefix)
				ars.Assignments[p] = &AssignmentEntry{
					Prefix:     p,
					AssignedTo: assignment.AssignedTo,
					Source:     path,
					Record:     rec,
					Assignment: assignment,
				}

			case strings.HasPrefix(key, RecordKeyPrefixRoutes):
				ann, err := ParseRouteAnnouncementRecord(rec)
				if err != nil {
					ars.addError(path, netip.Prefix{}, "route_announcement_invalid", err.Error())
					continue
				}
				if !ann.Active {
					continue
				}
				if revoked {
					ars.addError(path, mustParsePrefix(ann.Prefix), "route_zone_revoked", "zone is revoked")
					continue
				}
				p := mustParsePrefix(ann.Prefix)
				pending = append(pending, &RouteEntry{
					Record:       rec,
					Source:       path,
					Prefix:       p,
					Announcement: ann,
				})
			}
		}
	}

	// Authorize pending announcements against assignments.
	var authorized []*RouteEntry
	for _, entry := range pending {
		if assignment := findAssignmentForPrefix(ars, entry.Source, entry.Prefix); assignment != nil {
			authorized = append(authorized, entry)
		} else {
			ars.addError(entry.Source, entry.Prefix, "route_unauthorized_no_assignment", "no matching assignment")
		}
	}

	// Resolve overlapping prefixes.
	keep := resolveOverlaps(authorized, ars, ns)

	for _, entry := range keep {
		if ars.Announced[entry.Source] == nil {
			ars.Announced[entry.Source] = make(map[netip.Prefix]*RouteEntry)
		}
		ars.Announced[entry.Source][entry.Prefix] = entry
	}

	// Stable ordering for easier test assertions and debugging.
	sort.Slice(ars.Errors, func(i, j int) bool {
		if ars.Errors[i].Zone != ars.Errors[j].Zone {
			return ars.Errors[i].Zone < ars.Errors[j].Zone
		}
		if ars.Errors[i].Prefix.String() != ars.Errors[j].Prefix.String() {
			return ars.Errors[i].Prefix.String() < ars.Errors[j].Prefix.String()
		}
		return ars.Errors[i].Code < ars.Errors[j].Code
	})

	return ars, nil
}

// IsZoneAncestor reports whether ancestor is the same zone as child or one of
// its parent zones.
func IsZoneAncestor(ancestor, child zone.ZonePath) bool {
	if ancestor == child {
		return true
	}
	for _, a := range child.Ancestors() {
		if a == ancestor {
			return true
		}
	}
	return false
}

// IsInDelegationChain reports whether candidate is equal to target or is a
// descendant of target that has been delegated through the network state.
// It checks parent zone Delegations first, then falls back to the child's
// ParentProof cache.
func IsInDelegationChain(ns *zone.NetworkState, candidate, target zone.ZonePath) bool {
	if ns == nil {
		return false
	}
	if candidate == target {
		return true
	}
	if !IsZoneAncestor(target, candidate) {
		return false
	}

	current := candidate
	for current != target {
		parent := current.Parent()
		if parent == current {
			return false
		}

		parentState := ns.Zones[parent]
		if parentState != nil && parentState.Delegations[current] != nil {
			current = parent
			continue
		}

		childState := ns.Zones[current]
		if childState != nil && len(childState.ParentProof) > 0 {
			// ParentProof[0] is the direct parent->current delegation.
			if childState.ParentProof[0].ZoneName == current {
				current = parent
				continue
			}
		}

		return false
	}
	return true
}

// findAssignmentForPrefix finds an assignment that authorizes prefix within
// zone z or one of its ancestor zones.
func findAssignmentForPrefix(ars *AuthorizedRouteSet, z zone.ZonePath, prefix netip.Prefix) *AssignmentEntry {
	for _, ancestor := range z.Ancestors() {
		for _, entry := range ars.Assignments {
			if entry.Source != ancestor {
				continue
			}
			if !containsPrefix(entry.Prefix, prefix) {
				continue
			}
			// The assignment must be usable by the announcing zone.
			// Valid cases:
			//   1. AssignedTo == z (self-announcement)
			//   2. AssignedTo is an ancestor of z (z announces a sub-prefix
			//      assigned to an ancestor)
			//   3. AssignedTo is a descendant of z AND the assignment record
			//      itself lives in z (parent aggregate of a child-assigned prefix)
			assignedToUsable := IsZoneAncestor(entry.AssignedTo, z) ||
				(IsZoneAncestor(z, entry.AssignedTo) && entry.Source == z)
			if assignedToUsable {
				return entry
			}
		}
	}
	return nil
}

func containsPrefix(outer, inner netip.Prefix) bool {
	if outer.Bits() > inner.Bits() {
		return false
	}
	return outer.Contains(inner.Masked().Addr())
}

func (ars *AuthorizedRouteSet) addError(z zone.ZonePath, p netip.Prefix, code, detail string) {
	ars.Errors = append(ars.Errors, RouteAuthorizationError{
		Zone:   z,
		Prefix: p,
		Code:   code,
		Detail: detail,
	})
}

func resolveOverlaps(entries []*RouteEntry, ars *AuthorizedRouteSet, ns *zone.NetworkState) []*RouteEntry {
	bad := make(map[*RouteEntry]bool)

	for i := 0; i < len(entries); i++ {
		for j := i + 1; j < len(entries); j++ {
			a, b := entries[i], entries[j]
			if !a.Prefix.Overlaps(b.Prefix) {
				continue
			}

			contained := containsPrefix(a.Prefix, b.Prefix) || containsPrefix(b.Prefix, a.Prefix)
			inChain := IsInDelegationChain(ns, a.Source, b.Source) || IsInDelegationChain(ns, b.Source, a.Source)

			if !contained || !inChain {
				bad[a] = true
				bad[b] = true
			}
		}
	}

	if len(bad) == 0 {
		return entries
	}

	for entry := range bad {
		ars.addError(entry.Source, entry.Prefix, "route_overlap_unauthorized",
			fmt.Sprintf("overlapping prefix %s with another zone not in the same delegation chain", entry.Prefix))
	}

	keep := make([]*RouteEntry, 0, len(entries)-len(bad))
	for _, entry := range entries {
		if !bad[entry] {
			keep = append(keep, entry)
		}
	}
	return keep
}

func mustParsePrefix(s string) netip.Prefix {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		panic(fmt.Sprintf("invalid prefix %q: %v", s, err))
	}
	return p.Masked()
}
