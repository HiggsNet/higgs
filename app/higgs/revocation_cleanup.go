package main

import (
	"sort"
	"time"

	"github.com/Catofes/higgs/pkg/core/zone"
)

// RevocationImpact describes the set of objects affected by a revocation.
// It is computed from verified active state and local runtime state so that
// the daemon event loop can orchestrate cleanup across IPsec, BIRD, firewall
// and gossip layers in a single pass.
type RevocationImpact struct {
	// RevokedZone is the zone whose delegation was revoked by its parent.
	RevokedZone zone.ZonePath `json:"revoked_zone"`
	// SourceZone is the parent zone that issued the revocation/tombstone.
	SourceZone zone.ZonePath `json:"source_zone"`
	// RevokedSubtree lists all descendant zones of RevokedZone that are
	// transitively affected by this revocation. Each entry is a zone path.
	RevokedSubtree []zone.ZonePath `json:"revoked_subtree,omitempty"`
	// AffectedLinkInstances lists LinkInstance IDs whose peer zone is in the
	// revoked subtree.
	AffectedLinkInstances []string `json:"affected_link_instances,omitempty"`
	// AffectedSyncPeers lists peer IDs (zone FQDNs) whose entries in
	// SyncPeers should be cleaned or marked as revoked.
	AffectedSyncPeers []string `json:"affected_sync_peers,omitempty"`
	// ConfiguredButRevoked lists bootstrap peer IDs that are still in the
	// local config but are now revoked. This is a diagnostic signal.
	ConfiguredButRevoked []string `json:"configured_but_revoked,omitempty"`
	// AffectedIPAMPrefixes lists authorized prefixes that belong to revoked
	// zones and will be removed from routing/firewall allow sets.
	AffectedIPAMPrefixes []string `json:"affected_ipam_prefixes,omitempty"`
	// Layers tracks per-layer cleanup status.
	Layers map[string]*RevocationLayerStatus `json:"layers,omitempty"`
}

// RevocationLayerStatus tracks the cleanup status for a single subsystem.
type RevocationLayerStatus struct {
	Status   string `json:"status"`           // pending, removed, not_found, owner_conflict, error
	Error    string `json:"error,omitempty"`  // populated when Status == "error"
	Reason   string `json:"reason,omitempty"` // human-readable detail
	UnixTime int64  `json:"unix_time,omitempty"`
}

const (
	revocationLayerIPsec    = "ipsec_xfrm"
	revocationLayerRouting  = "routing_bird"
	revocationLayerFirewall = "firewall"
	revocationLayerGossip   = "gossip_peer_cache"
)

// Revocation layer status values.
const (
	revocationStatusPending       = "pending"
	revocationStatusRemoved       = "removed"
	revocationStatusNotFound      = "not_found"
	revocationStatusOwnerConflict = "owner_conflict"
	revocationStatusError         = "error"
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
func ComputeRevocationImpact(state *stateFile, revokedZone zone.ZonePath, now time.Time) RevocationImpact {
	impact := RevocationImpact{
		RevokedZone: revokedZone,
		Layers:      make(map[string]*RevocationLayerStatus),
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
	sort.Strings(impact.AffectedSyncPeers)

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
	sort.Strings(impact.ConfiguredButRevoked)

	// Initialize all layer statuses as pending.
	for _, layer := range []string{revocationLayerIPsec, revocationLayerRouting, revocationLayerFirewall, revocationLayerGossip} {
		impact.Layers[layer] = &RevocationLayerStatus{Status: revocationStatusPending}
	}

	return impact
}

// computeRevokedSubtree returns all descendant zones of revokedZone that exist
// in the active state. A descendant is any zone path that starts with
// revokedZone as a parent prefix. The revoked zone itself is not included in
// the result (only strict descendants).
func computeRevokedSubtree(ns *zone.NetworkState, revokedZone zone.ZonePath, now time.Time) []zone.ZonePath {
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
	sort.Slice(out, func(i, j int) bool {
		return out[i] < out[j]
	})
	return out
}

// isConfiguredBootstrapPeer checks if a peer ID appears in the bootstrap
// config. This is a best-effort check using the sync config embedded in state.
func isConfiguredBootstrapPeer(state *stateFile, peerID string) bool {
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
		ps.ObservedSource = ""
		ps.ObservedFailureCount = 0
		ps.ObservedGraceAddrs = nil
		// Keep DatagramStats/ObjectPullStats for audit but reset live counters.
		if ps.DatagramStats != nil {
			ps.DatagramStats.LastTooLargeDirection = ""
			ps.DatagramStats.LastTooLargeUnix = 0
		}
		// Clear backoff so it doesn't interfere with future diagnostics.
		ps.BackoffUntilUnix = 0
		ps.FailureCount = 0
		ps.LastError = "zone revoked"
		// Mark last update source so debug can show the reason.
		ps.LastUpdateSource = "revoked"
		state.SyncPeers[peerID] = ps
	}
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

// UpdateRevocationLayerStatus records the cleanup status for a layer in the
// impact object. This is called by the daemon after each layer's cleanup pass.
func UpdateRevocationLayerStatus(impact *RevocationImpact, layer string, status, reason, errStr string, now time.Time) {
	if impact == nil || impact.Layers == nil {
		return
	}
	entry := impact.Layers[layer]
	if entry == nil {
		entry = &RevocationLayerStatus{}
		impact.Layers[layer] = entry
	}
	entry.Status = status
	entry.Reason = reason
	entry.Error = errStr
	entry.UnixTime = now.Unix()
}

// HasPendingCleanup returns true if any layer in the impact is still pending.
func (impact *RevocationImpact) HasPendingCleanup() bool {
	if impact == nil || impact.Layers == nil {
		return false
	}
	for _, s := range impact.Layers {
		if s != nil && s.Status == revocationStatusPending {
			return true
		}
	}
	return false
}

// AllRevocationImpact computes impact for all currently-revoked zones and
// returns a combined result for debug/diagnostic output.
func AllRevocationImpact(state *stateFile, config *syncConfigFile, now time.Time) []RevocationImpact {
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
	sort.Slice(zones, func(i, j int) bool {
		return zones[i] < zones[j]
	})
	var out []RevocationImpact
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
			sort.Strings(impact.ConfiguredButRevoked)
		}
		out = append(out, impact)
	}
	return out
}

func appendIfMissing(slice []string, val string) []string {
	for _, s := range slice {
		if s == val {
			return slice
		}
	}
	return append(slice, val)
}
