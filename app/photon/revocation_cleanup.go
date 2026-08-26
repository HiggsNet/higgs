package main

import (
	"fmt"
	"slices"
	"sort"
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

// ComputeRevocationImpact computes the full impact of a revocation on the
// local daemon's runtime state. It is a pure function that reads from verified
// active state and local runtime state; it does not mutate anything.
//
// The impact includes:
//   - The revoked zone and its descendant subtree (zones under the revoked path)
//   - LinkInstances whose peer zone is in the subtree
//   - SyncPeers entries whose peer ID maps to a revoked zone
//   - Bootstrap peers that are configured but now revoked
//   - IPAM prefixes assigned to revoked zones (from route authorization errors)
func ComputeRevocationImpact(state *stateFile, revokedZone zone.ZonePath, now time.Time) inspect.RevocationImpact {
	impact := inspect.RevocationImpact{
		RevokedZone: revokedZone,
		Layers:      make(map[string]*inspect.RevocationLayerStatus),
	}
	if state == nil || state.Network == nil || !revokedZone.Valid() {
		return impact
	}

	// Determine source zone from active revocation.
	if rev := state.Network.ActiveRevocation(revokedZone, now); rev != nil {
		impact.SourceZone = rev.ParentZone
	}

	// Compute descendant subtree: any zone whose path has revokedZone as a
	// strict prefix.
	impact.RevokedSubtree = computeRevokedSubtree(state.Network, revokedZone, now)

	// Build a set for fast lookup: revokedZone + all descendants.
	revokedSet := make(map[zone.ZonePath]bool, len(impact.RevokedSubtree)+1)
	revokedSet[revokedZone] = true
	for _, z := range impact.RevokedSubtree {
		revokedSet[z] = true
	}

	// Affected LinkInstances.
	for id, inst := range state.LinkInstances {
		if revokedSet[inst.PeerZone] {
			impact.AffectedLinkInstances = append(impact.AffectedLinkInstances, id)
		}
	}
	sort.Strings(impact.AffectedLinkInstances)

	// Affected SyncPeers.
	for peerID := range state.SyncPeers {
		zp := zone.ZonePath(peerID)
		if revokedSet[zp] {
			impact.AffectedSyncPeers = append(impact.AffectedSyncPeers, peerID)
		}
	}
	inspect.SortZoneStrings(impact.AffectedSyncPeers)

	// Configured bootstrap peers that are revoked.
	if state.Network != nil {
		for _, z := range impact.RevokedSubtree {
			if isConfiguredBootstrapPeer(state, string(z)) {
				impact.ConfiguredButRevoked = append(impact.ConfiguredButRevoked, string(z))
			}
		}
		if isConfiguredBootstrapPeer(state, string(revokedZone)) {
			impact.ConfiguredButRevoked = append(impact.ConfiguredButRevoked, string(revokedZone))
		}
	}
	inspect.SortZoneStrings(impact.ConfiguredButRevoked)

	// Initialize all layer statuses as pending.
	for _, layer := range []string{inspect.RevocationLayerIPsec, inspect.RevocationLayerRouting, inspect.RevocationLayerFirewall, inspect.RevocationLayerGossip} {
		impact.Layers[layer] = &inspect.RevocationLayerStatus{Status: inspect.RevocationStatusPending}
	}

	return impact
}

// computeRevokedSubtree returns all descendant zones of revokedZone that exist
// in the active state. A descendant is any zone path that starts with
// revokedZone as a parent prefix. The revoked zone itself is not included in
// the result (only strict descendants).
func computeRevokedSubtree(ns *zone.NetworkState, revokedZone zone.ZonePath, _ time.Time) []zone.ZonePath {
	if ns == nil || !revokedZone.Valid() {
		return nil
	}
	var out []zone.ZonePath
	for z := range ns.Zones {
		if z == revokedZone || z.IsRoot() {
			continue
		}
		// Check if z is a descendant of revokedZone: revokedZone must appear
		// in z's ancestor chain (excluding z itself).
		isDescendant := false
		for _, ancestor := range z.Ancestors() {
			if ancestor == z {
				continue
			}
			if ancestor == revokedZone {
				isDescendant = true
				break
			}
		}
		if isDescendant {
			out = append(out, z)
		}
	}
	inspect.SortZonePaths(out)
	return out
}

// isConfiguredBootstrapPeer checks if a peer ID appears in the bootstrap
// config. This is a best-effort check using the sync config embedded in state.
func isConfiguredBootstrapPeer(_ *stateFile, _ string) bool {
	// The sync config is not directly in stateFile, but bootstrap peers are
	// accessible via the Runtime/App config. Since this function is called
	// from a pure state context, we check if the peer appears in SyncPeers
	// with a bootstrap-derived discovered address. For a complete check, the
	// daemon passes its config separately.
	// This is a conservative implementation: we return false if we can't
	// determine it, and the daemon-level call supplements this with actual
	// config.
	return false
}

// isConfiguredBootstrapPeerWithConfig checks if a peer ID appears in the
// bootstrap config. This is the config-aware version called by the daemon.
func isConfiguredBootstrapPeerWithConfig(config *syncConfigFile, peerID string) bool {
	if config == nil {
		return false
	}
	for _, peer := range config.Bootstrap {
		if peer.ID == peerID {
			return true
		}
	}
	return false
}

// CleanupRevokedPeerCache removes or marks revoked peer entries from the local
// SyncPeers cache. This implements Phase 6.5.5: revoked zones must not continue
// to appear as discovered peers, maintain observed paths, or participate in
// object pull candidates.
//
// Cleanup actions:
//   - Clear discovered_addr / discovered_at for revoked peers
//   - Clear observed_addr / observed grace addrs for revoked peers
//   - Clear datagram / object-pull stats (they are no longer relevant)
//   - Keep the SyncPeer entry itself with a Revoked marker so that debug output
//     can show configured_but_revoked; the entry is cleaned via normal
//     offline cleanup policy after a retention window.
func CleanupRevokedPeerCache(state *stateFile, revokedZones map[zone.ZonePath]bool) {
	if state == nil || len(revokedZones) == 0 {
		return
	}
	for peerID, ps := range state.SyncPeers {
		zp := zone.ZonePath(peerID)
		if !revokedZones[zp] {
			continue
		}
		// Clear runtime-relevant fields but keep the entry for diagnostics.
		ps.DiscoveredAddr = ""
		ps.DiscoveredAtUnix = 0
		ps.ObservedAddr = ""
		ps.ObservedFirstSeenUnix = 0
		ps.ObservedLastSeenUnix = 0
		ps.ObservedLastSyncUnix = 0
		ps.ObservedUntilUnix = 0
		ps.ObservedFailureCount = 0
		ps.ObservedGraceAddrs = nil
		// Drop diagnostics left by older state files. Current daemon diagnostics
		// live in PeerObservability and are removed by the daemon cleanup path.
		// Clear backoff so it doesn't interfere with future diagnostics.
		ps.BackoffUntilUnix = 0
		ps.FailureCount = 0
		ps.LastError = "zone revoked"
		state.SyncPeers[peerID] = ps
	}
}

// peerNeedsRevocationCleanup reports whether CleanupRevokedPeerCache would
// change the runtime-owned fields of one peer. Keeping this comparison next to
// the mutator prevents the daemon fast path from drifting away from the
// deny-first cleanup semantics.
func peerNeedsRevocationCleanup(peer syncPeerState) bool {
	return peer.DiscoveredAddr != "" ||
		peer.DiscoveredAtUnix != 0 ||
		peer.ObservedAddr != "" ||
		peer.ObservedFirstSeenUnix != 0 ||
		peer.ObservedLastSeenUnix != 0 ||
		peer.ObservedLastSyncUnix != 0 ||
		peer.ObservedUntilUnix != 0 ||
		peer.ObservedFailureCount != 0 ||
		peer.ObservedGraceAddrs != nil ||
		peer.BackoffUntilUnix != 0 ||
		peer.FailureCount != 0 ||
		peer.LastError != "zone revoked"
}

// CollectAllRevokedZones returns all zones that are currently revoked,
// including descendants. This expands on collectRevokedPeerZones by scanning
// all zones in the active state, not just those with LinkInstances/SyncPeers.
func CollectAllRevokedZones(state *stateFile, now time.Time) map[zone.ZonePath]bool {
	out := make(map[zone.ZonePath]bool)
	if state == nil || state.Network == nil {
		return out
	}
	for z := range state.Network.Zones {
		if z.IsRoot() {
			continue
		}
		if state.Network.IsZoneRevoked(z, now) {
			out[z] = true
		}
	}
	return out
}

// purgePlan describes the local state that a manual revoked-zone GC would
// remove. It is computed without mutating state so the CLI can print a dry-run
// preview and reuse the same logic when applying.
type purgePlan struct {
	// Zones are the revoked zone paths whose ZoneState bodies will be deleted
	// from Network.Zones, sorted ascending. Includes descendant subtrees.
	Zones []zone.ZonePath `json:"zones,omitempty"`
	// LinkInstances lists LinkInstance IDs whose PeerZone is in Zones.
	LinkInstances []string `json:"link_instances,omitempty"`
	// SyncPeers lists peer IDs (zone FQDNs) whose SyncPeers entries are removed.
	SyncPeers []string `json:"sync_peers,omitempty"`
	// ManagedZoneSkipped lists revoked zones excluded because they are the
	// local node's ManagedZone or one of its ancestors.
	// Reported for transparency; never deleted.
	ManagedZoneSkipped []zone.ZonePath `json:"managed_zone_skipped,omitempty"`
}

// overlapsLocalIdentity reports whether z is the local node's managed zone or
// an ancestor of it. Such zones form this node's own identity chain and must
// never be purged locally. Descendant zones can still be purged when their
// delegations are revoked.
func overlapsLocalIdentity(z, managed zone.ZonePath) bool {
	if managed == "" || managed == zone.RootZone || !z.Valid() {
		return false
	}
	if z == managed {
		return true
	}
	// z is a parent of managed.
	return isZoneDescendantOf(managed, z)
}

// planPurgeRevokedZones computes the local state to remove for revoked zones
// without mutating state. When target is empty every currently-revoked zone is
// considered; otherwise only target (which must itself be revoked) and its
// descendant subtree are considered. Zones overlapping the local node's
// ManagedZone or its ancestor chain are never planned for removal.
func planPurgeRevokedZones(state *stateFile, now time.Time, target zone.ZonePath) (*purgePlan, error) {
	plan := &purgePlan{}
	if state == nil || state.Network == nil {
		return plan, nil
	}

	// Determine the candidate revoked-zone set.
	var candidates map[zone.ZonePath]bool
	if target == "" {
		candidates = CollectAllRevokedZones(state, now)
	} else {
		if !target.Valid() || target == zone.RootZone {
			return nil, fmt.Errorf("invalid purge zone: %s", target)
		}
		if !state.Network.IsZoneRevoked(target, now) {
			return nil, fmt.Errorf("zone is not revoked: %s", target)
		}
		if overlapsLocalIdentity(target, state.ManagedZone) {
			return nil, fmt.Errorf("refusing to purge local identity zone: %s", target)
		}
		candidates = map[zone.ZonePath]bool{target: true}
		for _, z := range computeRevokedSubtree(state.Network, target, now) {
			candidates[z] = true
		}
	}

	// Safety filter: never delete anything overlapping the local identity chain.
	for z := range candidates {
		if overlapsLocalIdentity(z, state.ManagedZone) {
			plan.ManagedZoneSkipped = append(plan.ManagedZoneSkipped, z)
			delete(candidates, z)
		}
	}

	zones := make([]zone.ZonePath, 0, len(candidates))
	for z := range candidates {
		zones = append(zones, z)
	}
	slices.Sort(zones)
	plan.Zones = zones

	for id, inst := range state.LinkInstances {
		if candidates[inst.PeerZone] {
			plan.LinkInstances = append(plan.LinkInstances, id)
		}
	}
	sort.Strings(plan.LinkInstances)

	for peerID := range state.SyncPeers {
		if candidates[zone.ZonePath(peerID)] {
			plan.SyncPeers = append(plan.SyncPeers, peerID)
		}
	}
	sort.Strings(plan.SyncPeers)

	slices.Sort(plan.ManagedZoneSkipped)
	return plan, nil
}

// executePurgePlan performs the hard deletions described by plan on state. It
// removes the revoked ZoneState bodies from Network.Zones, the matching
// LinkInstances, and the matching SyncPeers entries. It deliberately leaves
// parent Revocations tombstones in place (required to enforce the epoch-bump
// invariant on any future re-delegation) and does not touch records in any
// still-valid zone, which gossip would re-sync anyway.
func executePurgePlan(state *stateFile, plan *purgePlan) {
	if state == nil || plan == nil {
		return
	}
	for _, z := range plan.Zones {
		delete(state.Network.Zones, z)
	}
	for _, id := range plan.LinkInstances {
		delete(state.LinkInstances, id)
	}
	for _, peerID := range plan.SyncPeers {
		delete(state.SyncPeers, peerID)
		delete(state.PeerCleanups, peerID)
	}
}

// AllRevocationImpact computes impact for all currently-revoked zones and
// returns a combined result for debug/diagnostic output.
func AllRevocationImpact(state *stateFile, config *syncConfigFile, now time.Time) []inspect.RevocationImpact {
	if state == nil || state.Network == nil {
		return nil
	}
	revokedZones := CollectAllRevokedZones(state, now)
	if len(revokedZones) == 0 {
		return nil
	}
	// Sort for stable output.
	zones := make([]zone.ZonePath, 0, len(revokedZones))
	for z := range revokedZones {
		zones = append(zones, z)
	}
	inspect.SortZonePaths(zones)
	var out []inspect.RevocationImpact
	for _, z := range zones {
		impact := ComputeRevocationImpact(state, z, now)
		// Supplement configured_but_revoked with actual config.
		if config != nil {
			if isConfiguredBootstrapPeerWithConfig(config, string(z)) {
				impact.ConfiguredButRevoked = appendIfMissing(impact.ConfiguredButRevoked, string(z))
			}
			for _, sub := range impact.RevokedSubtree {
				if isConfiguredBootstrapPeerWithConfig(config, string(sub)) {
					impact.ConfiguredButRevoked = appendIfMissing(impact.ConfiguredButRevoked, string(sub))
				}
			}
			inspect.SortZoneStrings(impact.ConfiguredButRevoked)
		}
		out = append(out, impact)
	}
	return out
}

func appendIfMissing(slice []string, val string) []string {
	if slices.Contains(slice, val) {
		return slice
	}
	return append(slice, val)
}
