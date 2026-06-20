package main

import (
	"sort"
	"time"

	"github.com/Catofes/higgs/pkg/core/zone"
)

// Peer lifecycle states (Phase 6.4.1). These are derived at runtime from
// verified active state, local config and SyncPeers observations. They are
// never written to gossip active state and only influence local desired-state
// reconcile.
const (
	// peerStateEligible: trust chain and local policy allow this peer, but no
	// usable endpoint/ipsec/profile record has been observed yet.
	peerStateEligible = "eligible"
	// peerStateDiscovered: a usable endpoint/ipsec/profile record is available;
	// transport link has not entered connecting yet.
	peerStateDiscovered = "discovered"
	// peerStateConnecting: IPsec apply succeeded, awaiting SA establishment.
	peerStateConnecting = "connecting"
	// peerStateActive: at least one LinkInstance is up (established SA).
	peerStateActive = "active"
	// peerStateStale: short-term offline (within stale_after). Known endpoints,
	// desired link and firewall config are retained; reconnect retry frequency
	// is reduced.
	peerStateStale = "stale"
	// peerStateOffline: long-term offline (beyond offline_after). Active new
	// connection attempts enter low-frequency backoff; cleanup policy decides
	// whether existing SA/route are retained.
	peerStateOffline = "offline"
	// peerStatePolicyDenied: local MeshPolicy or trust chain denies this peer.
	peerStatePolicyDenied = "policy_denied"
	// peerStateConfigError: required local config (netns/link group) is missing
	// or inconsistent.
	peerStateConfigError = "config_error"
	// peerStateRevoked: the peer Zone or an ancestor delegation is revoked.
	// This state overrides any stale/offline/active observation: even if the SA
	// is still up, overlay access must be blocked.
	peerStateRevoked = "revoked"
)

// PeerLifecycleConfig holds stale/offline/cleanup thresholds. Zero values use
// defaults from defaultPeerLifecycleConfig().
type PeerLifecycleConfig struct {
	StaleAfter       time.Duration `yaml:"stale_after" json:"stale_after,omitempty"`
	OfflineAfter     time.Duration `yaml:"offline_after" json:"offline_after,omitempty"`
	CleanupAfter     time.Duration `yaml:"cleanup_after" json:"cleanup_after,omitempty"`
	KeepSAWhileStale bool          `yaml:"keep_sa_while_stale" json:"keep_sa_while_stale,omitempty"`
}

// defaultPeerLifecycleConfig returns conservative defaults so that transient
// network blips do not cause link teardown.
func defaultPeerLifecycleConfig() PeerLifecycleConfig {
	return PeerLifecycleConfig{
		StaleAfter:       15 * time.Minute,
		OfflineAfter:     12 * time.Hour,
		CleanupAfter:     48 * time.Hour,
		KeepSAWhileStale: true,
	}
}

// normalizedPeerLifecycleConfig merges cfg with defaults for any zero field.
func normalizedPeerLifecycleConfig(cfg PeerLifecycleConfig) PeerLifecycleConfig {
	def := defaultPeerLifecycleConfig()
	out := cfg
	// KeepSAWhileStale is false by default in Go; our policy default is true.
	// We can't distinguish "explicitly false" from "unset zero", so we use the
	// conservative default true only when the struct appears to be at zero
	// value (all durations are zero), i.e. the user didn't configure this
	// section at all.
	allZero := out.StaleAfter <= 0 && out.OfflineAfter <= 0 && out.CleanupAfter <= 0
	if allZero && !out.KeepSAWhileStale {
		out.KeepSAWhileStale = def.KeepSAWhileStale
	}
	if out.StaleAfter <= 0 {
		out.StaleAfter = def.StaleAfter
	}
	if out.OfflineAfter <= 0 {
		out.OfflineAfter = def.OfflineAfter
	}
	if out.CleanupAfter <= 0 {
		out.CleanupAfter = def.CleanupAfter
	}
	return out
}

// PeerStatusInfo is the derived runtime status for a single peer. It is
// computed on demand from verified state and SyncPeers observations; it is
// not persisted as the authoritative state (only timestamps/reasons that feed
// into it are persisted).
type PeerStatusInfo struct {
	PeerID            string        `json:"peer_id"`
	Zone              zone.ZonePath `json:"zone"`
	State             string        `json:"state"`
	Reason            string        `json:"reason,omitempty"`
	Detail            string        `json:"detail,omitempty"`
	LastSeenUnix      int64         `json:"last_seen_unix,omitempty"`
	LastSyncUnix      int64         `json:"last_sync_unix,omitempty"`
	LastEndpointUnix  int64         `json:"last_endpoint_change_unix,omitempty"`
	LastReconcileUnix int64         `json:"last_reconcile_unix,omitempty"`
	DesiredLinks      int           `json:"desired_links,omitempty"`
	ActualLinks       int           `json:"actual_links,omitempty"`
	UpLinks           int           `json:"up_links,omitempty"`
	OfflineSinceUnix  int64         `json:"offline_since_unix,omitempty"`
	NextCleanupUnix   int64         `json:"next_cleanup_unix,omitempty"`
}

// derivePeerStatus computes the lifecycle state of a peer from verified active
// state, SyncPeers observations, LinkInstances and local config.
//
// The state priority is:
//  1. revoked (overrides everything)
//  2. policy_denied / config_error (local MeshPolicy/trust denies peer)
//  3. active (at least one up link)
//  4. connecting (link apply succeeded, SA not yet observed)
//  5. discovered (endpoint/ipsec record available, no link yet)
//  6. eligible (trust chain ok, no endpoint)
//  7. stale (recently seen but beyond active window)
//  8. offline (beyond offline_after)
func derivePeerStatus(
	state *stateFile,
	peerID string,
	peerZone zone.ZonePath,
	now time.Time,
	cfg PeerLifecycleConfig,
) PeerStatusInfo {
	info := PeerStatusInfo{
		PeerID: peerID,
		Zone:   peerZone,
	}
	if state == nil {
		info.State = peerStateConfigError
		info.Reason = "state_nil"
		return info
	}
	cfg = normalizedPeerLifecycleConfig(cfg)
	ps := state.SyncPeers[peerID]
	info.LastSeenUnix = ps.ObservedLastSeenUnix
	if ps.LastSyncUnix > info.LastSeenUnix {
		info.LastSeenUnix = ps.LastSyncUnix
	}
	info.LastSyncUnix = ps.LastSyncUnix

	// Collect link instance stats for this peer zone.
	var upLinks, actualLinks, desiredLinks int
	var lastTransitionUnix int64
	for _, inst := range state.LinkInstances {
		if inst.PeerZone != peerZone {
			continue
		}
		actualLinks++
		if inst.ActualState == "up" {
			upLinks++
		}
		if inst.LastTransition > lastTransitionUnix {
			lastTransitionUnix = inst.LastTransition
		}
	}
	if rec := state.IPsecReconcile; rec != nil {
		for _, d := range rec.Desired {
			if d.PeerZone == peerZone {
				desiredLinks++
			}
		}
	}
	info.UpLinks = upLinks
	info.ActualLinks = actualLinks
	info.DesiredLinks = desiredLinks
	if lastTransitionUnix > info.LastReconcileUnix {
		info.LastReconcileUnix = lastTransitionUnix
	}

	// 1. Revoked overrides everything.
	if state.Network != nil && state.Network.IsZoneRevoked(peerZone, now) {
		info.State = peerStateRevoked
		info.Reason = "zone_revoked"
		return info
	}

	// Verify trust chain eligibility: the peer zone must exist and have a
	// delegation chain.
	if state.Network == nil || state.Network.Zones[peerZone] == nil {
		// Unknown peer zone: not eligible.
		info.State = peerStateConfigError
		info.Reason = "peer_zone_unknown"
		return info
	}

	// If we have desired links but MeshPolicy denied them, reflect that.
	if desiredLinks == 0 && hasIPsecConfig(state) {
		// Check if there's a deny reason recorded in the latest reconcile skip.
		if rec := state.IPsecReconcile; rec != nil {
			for _, skip := range rec.Skipped {
				if skip.Peer == peerZone {
					info.State = peerStatePolicyDenied
					info.Reason = skip.Reason
					info.Detail = skip.Detail
					return info
				}
			}
		}
		// No skip record but no desired link: peer may be eligible but lacks
		// required ipsec records (profile/address/port/transport-key).
		info.State = peerStateEligible
		info.Reason = "no_ipsec_records"
		return info
	}

	// 3. Active: at least one up link.
	if upLinks > 0 {
		info.State = peerStateActive
		info.Reason = "link_up"
		return info
	}

	// 4. Connecting: link apply succeeded but no SA yet.
	if actualLinks > 0 {
		info.State = peerStateConnecting
		info.Reason = "link_connecting"
		return info
	}

	// 5. Discovered: desired link exists (endpoint/profile available) but
	//    LinkInstance not created yet.
	if desiredLinks > 0 {
		info.State = peerStateDiscovered
		info.Reason = "link_pending"
		return info
	}

	// 6/7/8. Stale / offline based on last seen time. This applies regardless
	// of whether IPsec overlay config exists: a peer that was synced recently
	// but is now beyond the active window should be flagged stale/offline so
	// that reconcile and cleanup logic can react.
	lastActive := ps.LastSyncUnix
	if ps.ObservedLastSeenUnix > 0 && ps.ObservedLastSeenUnix > lastActive {
		lastActive = ps.ObservedLastSeenUnix
	}
	if lastActive == 0 {
		// Never synced: no overlay config means eligible; with overlay config
		// but no desired link, also eligible (missing ipsec records).
		if hasIPsecConfig(state) {
			info.State = peerStateEligible
			info.Reason = "no_ipsec_records"
		} else {
			info.State = peerStateEligible
			info.Reason = "no_overlay_config"
		}
		return info
	}
	lastActiveTime := time.Unix(lastActive, 0)
	elapsed := now.Sub(lastActiveTime)
	info.OfflineSinceUnix = lastActive
	if elapsed >= cfg.CleanupAfter {
		info.State = peerStateOffline
		info.Reason = "cleanup_after_exceeded"
		info.NextCleanupUnix = now.Unix()
		return info
	}
	if elapsed >= cfg.OfflineAfter {
		info.State = peerStateOffline
		info.Reason = "offline_after_exceeded"
		info.NextCleanupUnix = lastActiveTime.Add(cfg.CleanupAfter).Unix()
		return info
	}
	if elapsed >= cfg.StaleAfter {
		info.State = peerStateStale
		info.Reason = "stale_after_exceeded"
		info.NextCleanupUnix = lastActiveTime.Add(cfg.CleanupAfter).Unix()
		return info
	}

	// Recently seen but no active link: treat as discovered/eligible.
	if hasIPsecConfig(state) {
		info.State = peerStateDiscovered
		info.Reason = "recently_seen_no_link"
	} else {
		info.State = peerStateEligible
		info.Reason = "no_overlay_config"
	}
	return info
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
	cfg PeerLifecycleConfig,
	hasOverlayConfig bool,
) []PeerStatusInfo {
	if state == nil {
		return nil
	}
	seen := make(map[string]bool)
	var out []PeerStatusInfo

	// Gather all candidate peers: SyncPeers, LinkInstances peer zones, desired
	// link peer zones, and active state zones with ipsec records.
	addPeer := func(peerID string, peerZone zone.ZonePath) {
		if peerID == "" || seen[peerID] {
			return
		}
		seen[peerID] = true
		info := derivePeerStatus(state, peerID, peerZone, now, cfg)
		// If overlay config is available but this peer has no desired link,
		// refine the eligible/discovered distinction.
		if hasOverlayConfig && info.State == peerStateEligible && info.Reason == "no_ipsec_records" {
			// Check if the peer zone has ipsec profile record.
			if peerZoneState := state.Network.Zones[peerZone]; peerZoneState != nil {
				if hasPeerIPsecRecords(peerZoneState) {
					info.State = peerStateDiscovered
					info.Reason = "has_ipsec_records_no_link"
				}
			}
		}
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

	sort.Slice(out, func(i, j int) bool {
		return out[i].PeerID < out[j].PeerID
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

// peerStatusRequiresCleanup returns true if the peer's lifecycle state means
// long-term invalid SA/interface/route/firewall entries should be cleaned up.
// Only offline (beyond cleanup_after) and revoked states trigger cleanup;
// stale peers retain their SA per KeepSAWhileStale.
func peerStatusRequiresCleanup(info PeerStatusInfo, cfg PeerLifecycleConfig) bool {
	switch info.State {
	case peerStateRevoked:
		return true
	case peerStateOffline:
		if info.Reason == "cleanup_after_exceeded" {
			return true
		}
		return false
	default:
		return false
	}
}

// peerStatusIsHardChange returns true if the peer status change from oldState
// to newState requires teardown/recreate rather than a soft update. Hard
// changes include transitions involving revoked, policy_denied, config_error,
// or any change to/from active when the underlying key/profile changed.
func peerStatusIsHardChange(oldState, newState string) bool {
	if oldState == newState {
		return false
	}
	// Revocation is always a hard change (force teardown).
	if newState == peerStateRevoked || oldState == peerStateRevoked {
		return true
	}
	// Policy denied / config error are hard changes.
	if newState == peerStatePolicyDenied || newState == peerStateConfigError {
		return true
	}
	if oldState == peerStatePolicyDenied || oldState == peerStateConfigError {
		return true
	}
	return false
}

// shouldBlockReconnect returns true if the peer's state means new connection
// attempts should be blocked (not just backoff). Revoked peers must never
// reconnect.
func shouldBlockReconnect(info PeerStatusInfo) bool {
	switch info.State {
	case peerStateRevoked:
		return true
	case peerStatePolicyDenied:
		return true
	case peerStateConfigError:
		return true
	default:
		return false
	}
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
