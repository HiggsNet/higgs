package main

import (
	"slices"
	"sort"
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
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
func ComputeRevocationImpact(network *zone.NetworkState, links map[string]linkInstanceState, peers map[string]syncPeerState, revokedZone zone.ZonePath, now time.Time) inspect.RevocationImpact {
	impact := inspect.RevocationImpact{
		RevokedZone: revokedZone,
		Layers:      make(map[string]*inspect.RevocationLayerStatus),
	}
	if network == nil || !revokedZone.Valid() {
		return impact
	}

	// Determine source zone from active revocation.
	if rev := network.ActiveRevocation(revokedZone, now); rev != nil {
		impact.SourceZone = rev.ParentZone
	}

	// Compute descendant subtree: any zone whose path has revokedZone as a
	// strict prefix.
	impact.RevokedSubtree = computeRevokedSubtree(network, revokedZone, now)

	// Build a set for fast lookup: revokedZone + all descendants.
	revokedSet := make(map[zone.ZonePath]bool, len(impact.RevokedSubtree)+1)
	revokedSet[revokedZone] = true
	for _, z := range impact.RevokedSubtree {
		revokedSet[z] = true
	}

	// Affected LinkInstances.
	for id, inst := range links {
		if revokedSet[inst.PeerZone] {
			impact.AffectedLinkInstances = append(impact.AffectedLinkInstances, id)
		}
	}
	sort.Strings(impact.AffectedLinkInstances)

	// Affected SyncPeers.
	for peerID := range peers {
		zp := zone.ZonePath(peerID)
		if revokedSet[zp] {
			impact.AffectedSyncPeers = append(impact.AffectedSyncPeers, peerID)
		}
	}
	inspect.SortZoneStrings(impact.AffectedSyncPeers)

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
	if state == nil || state.Network == nil {
		return make(map[zone.ZonePath]bool)
	}
	return collectAllRevokedZones(state.Network, now)
}

func collectAllRevokedZones(network *zone.NetworkState, now time.Time) map[zone.ZonePath]bool {
	out := make(map[zone.ZonePath]bool)
	if network == nil {
		return out
	}
	for z := range network.Zones {
		if z.IsRoot() {
			continue
		}
		if network.IsZoneRevoked(z, now) {
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

func mergePurgePlan(common corestate.PurgeRevokedPlan, runtime *linuxRuntimeState) *purgePlan {
	plan := &purgePlan{
		Zones:              append([]zone.ZonePath(nil), common.Zones...),
		SyncPeers:          append([]string(nil), common.CheckpointPeers...),
		ManagedZoneSkipped: append([]zone.ZonePath(nil), common.ManagedZoneSkipped...),
	}
	zoneSet := make(map[zone.ZonePath]bool, len(plan.Zones))
	for _, path := range plan.Zones {
		zoneSet[path] = true
	}
	if runtime != nil {
		for id, instance := range runtime.LinkInstances {
			if zoneSet[instance.PeerZone] {
				plan.LinkInstances = append(plan.LinkInstances, id)
			}
		}
	}
	slices.Sort(plan.LinkInstances)
	return plan
}

// AllRevocationImpact computes impact for all currently-revoked zones and
// returns a combined result for debug/diagnostic output.
func AllRevocationImpact(network *zone.NetworkState, links map[string]linkInstanceState, peers map[string]syncPeerState, config *syncConfigFile, now time.Time) []inspect.RevocationImpact {
	if network == nil {
		return nil
	}
	revokedZones := collectAllRevokedZones(network, now)
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
		impact := ComputeRevocationImpact(network, links, peers, z, now)
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
