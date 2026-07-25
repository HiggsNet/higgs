package main

import (
	"sort"
	"time"

	"github.com/Catofes/higgs/internal/inspect"
	"github.com/Catofes/higgs/pkg/core/zone"
)

func peerLifecycleInputFromState(state *stateFile, peerID string, peerZone zone.ZonePath, now time.Time, cfg inspect.PeerLifecycleConfig, hasOverlayConfig bool) inspect.PeerLifecycleInput {
	input := inspect.PeerLifecycleInput{
		PeerID:           peerID,
		PeerZone:         peerZone,
		StateAvailable:   state != nil,
		HasOverlayConfig: hasOverlayConfig,
		Now:              now,
		Config:           cfg,
	}
	if state == nil {
		return input
	}
	ps := state.SyncPeers[peerID]
	input.LastSyncUnix = ps.LastSyncUnix
	input.ObservedLastSeenUnix = ps.ObservedLastSeenUnix
	input.HasIPsecConfig = hasIPsecConfig(state)
	if state.Network != nil {
		input.PeerZoneKnown = state.Network.Zones[peerZone] != nil
		input.ZoneRevoked = state.Network.IsZoneRevoked(peerZone, now)
		if peerZoneState := state.Network.Zones[peerZone]; peerZoneState != nil {
			input.PeerHasIPsecRecords = hasPeerIPsecRecords(peerZoneState)
		}
	}
	for _, inst := range state.LinkInstances {
		if inst.PeerZone != peerZone {
			continue
		}
		input.ActualLinks++
		if inst.ActualState == "up" {
			input.UpLinks++
		}
		if inst.LastTransition > input.LastTransitionUnix {
			input.LastTransitionUnix = inst.LastTransition
		}
	}
	if rec := state.IPsecReconcile; rec != nil {
		for _, d := range rec.Desired {
			if d.PeerZone == peerZone {
				input.DesiredLinks++
			}
		}
		for _, skip := range rec.Skipped {
			if skip.Peer == peerZone {
				input.PolicyDeniedReason = skip.Reason
				input.PolicyDeniedDetail = skip.Detail
				break
			}
		}
	}
	return input
}

// hasIPsecConfig returns true if the local node has IPsec link groups
// configured, meaning it participates in overlay mesh.
func hasIPsecConfig(state *stateFile) bool {
	// state alone doesn't carry config; this is a best-effort heuristic used
	// only when config is not injected. When config is available,
	// derivePeerStatuses injects this via the config-aware path.
	return state != nil && state.IPsecReconcile != nil && state.IPsecReconcile.DesiredLinks > 0
}

// derivePeerStatuses computes status for all known peers (from SyncPeers,
// LinkInstances and desired links). The result is sorted by peer id for stable
// output.
func derivePeerStatuses(
	state *stateFile,
	now time.Time,
	cfg inspect.PeerLifecycleConfig,
	hasOverlayConfig bool,
) []inspect.PeerStatusInfo {
	if state == nil {
		return nil
	}
	seen := make(map[string]bool)
	var out []inspect.PeerStatusInfo

	// Gather all candidate peers: SyncPeers, LinkInstances peer zones, desired
	// link peer zones, and active state zones with ipsec records.
	addPeer := func(peerID string, peerZone zone.ZonePath) {
		if peerID == "" || seen[peerID] {
			return
		}
		seen[peerID] = true
		info := inspect.BuildPeerLifecycleStatus(peerLifecycleInputFromState(state, peerID, peerZone, now, cfg, hasOverlayConfig))
		out = append(out, info)
	}

	for peerID := range state.SyncPeers {
		// Derive zone from peer id: peer id is typically the zone FQDN.
		addPeer(peerID, zone.ZonePath(peerID))
	}
	for _, inst := range state.LinkInstances {
		addPeer(string(inst.PeerZone), inst.PeerZone)
	}
	if rec := state.IPsecReconcile; rec != nil {
		for _, d := range rec.Desired {
			addPeer(string(d.PeerZone), d.PeerZone)
		}
		for _, skip := range rec.Skipped {
			addPeer(string(skip.Peer), skip.Peer)
		}
	}
	// Scan active state for zones that have ipsec profile records but aren't
	// in SyncPeers yet (eligible peers discovered via gossip).
	if state.Network != nil {
		for z, zs := range state.Network.Zones {
			if z == state.ManagedZone || z.IsRoot() {
				continue
			}
			if hasPeerIPsecRecords(zs) {
				addPeer(string(z), z)
			}
		}
	}

	sort.SliceStable(out, func(i, j int) bool {
		return inspect.ZonePathLess(out[i].PeerID, out[j].PeerID)
	})
	return out
}

// hasPeerIPsecRecords checks if a zone has any ipsec/* records published.
func hasPeerIPsecRecords(zs *zone.ZoneState) bool {
	if zs == nil || zs.Records == nil {
		return false
	}
	for key := range zs.Records {
		if len(key) >= 6 && key[:6] == "ipsec/" {
			return true
		}
	}
	return false
}

// collectRevokedPeerZones returns the set of peer zones that are currently
// revoked, expanded from LinkInstances and SyncPeers. This is used to feed
// the revoked set into IPsec/routing/firewall reconcile.
func collectRevokedPeerZones(state *stateFile, now time.Time) map[zone.ZonePath]bool {
	out := make(map[zone.ZonePath]bool)
	if state == nil || state.Network == nil {
		return out
	}
	for _, inst := range state.LinkInstances {
		if state.Network.IsZoneRevoked(inst.PeerZone, now) {
			out[inst.PeerZone] = true
		}
	}
	for peerID := range state.SyncPeers {
		zp := zone.ZonePath(peerID)
		if state.Network.IsZoneRevoked(zp, now) {
			out[zp] = true
		}
	}
	return out
}
