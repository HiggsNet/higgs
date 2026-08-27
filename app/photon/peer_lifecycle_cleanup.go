package main

import (
	"context"
	"sort"
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

const (
	peerCleanupReasonOffline = "cleanup_after_exceeded"
	peerCleanupReasonRevoked = "zone_revoked"
)

func peerLifecycleLastActiveUnix(peer syncPeerState) int64 {
	lastActive := peer.LastSyncUnix
	if peer.ObservedLastSeenUnix > 0 && peer.ObservedLastSeenUnix > lastActive {
		lastActive = peer.ObservedLastSeenUnix
	}
	return lastActive
}

func peerLifecycleCleanupDue(peer syncPeerState, now time.Time, cfg inspect.PeerLifecycleConfig) bool {
	lastActive := peerLifecycleLastActiveUnix(peer)
	if lastActive == 0 {
		return false
	}
	cfg = inspect.NormalizePeerLifecycleConfig(cfg)
	return !now.Before(time.Unix(lastActive, 0).Add(cfg.CleanupAfter))
}

// peerLifecycleExcludedPeers returns local data-plane suppressions. A marked
// peer remains available to gossip so a successful sync can clear the marker,
// but IPsec must not recreate its owner-managed link from stale Zone records.
func peerLifecycleExcludedPeers(state *stateFile, now time.Time, cfg inspect.PeerLifecycleConfig) map[zone.ZonePath]string {
	out := make(map[zone.ZonePath]string)
	if state == nil {
		return out
	}
	for peerID, cleanup := range state.PeerCleanups {
		if cleanup.Reason == peerCleanupReasonOffline {
			out[zone.ZonePath(peerID)] = peerCleanupReasonOffline
		}
	}
	for peerID, peer := range state.SyncPeers {
		if peerLifecycleCleanupDue(peer, now, cfg) {
			out[zone.ZonePath(peerID)] = peerCleanupReasonOffline
		}
	}
	return out
}

func peerLifecycleCleanupRequired(state *stateFile, now time.Time, cfg inspect.PeerLifecycleConfig) bool {
	if state == nil {
		return false
	}
	cfg = inspect.NormalizePeerLifecycleConfig(cfg)
	revoked := CollectAllRevokedZones(state, now)
	for peerID, cleanup := range state.PeerCleanups {
		_, exists := state.SyncPeers[peerID]
		switch cleanup.Reason {
		case peerCleanupReasonRevoked:
			if !revoked[zone.ZonePath(peerID)] || cleanup.CleanupUnix <= 0 ||
				!now.Before(time.Unix(cleanup.CleanupUnix, 0).Add(cfg.CleanupAfter)) {
				return true
			}
		case peerCleanupReasonOffline:
			if exists {
				return true
			}
		default:
			return true
		}
	}
	for peerID, peer := range state.SyncPeers {
		if _, marked := state.PeerCleanups[peerID]; marked {
			continue
		}
		if revoked[zone.ZonePath(peerID)] || peerLifecycleCleanupDue(peer, now, cfg) {
			return true
		}
	}
	return false
}

// applyPeerLifecycleCleanup mutates only local daemon metadata. Revoked peers
// keep their diagnostic SyncPeers entry for one cleanup_after window. Peers
// that merely went offline have already had the whole window since their last
// activity, so their cache entry is removed immediately and a local marker
// prevents stale signed records from recreating data-plane links.
func applyPeerLifecycleCleanup(state *stateFile, now time.Time, cfg inspect.PeerLifecycleConfig) (removed []string, changed bool) {
	if state == nil {
		return nil, false
	}
	normalizeSyncPeers(state)
	cfg = inspect.NormalizePeerLifecycleConfig(cfg)
	revoked := CollectAllRevokedZones(state, now)

	for peerID, cleanup := range state.PeerCleanups {
		peer, exists := state.SyncPeers[peerID]
		switch cleanup.Reason {
		case peerCleanupReasonRevoked:
			if !revoked[zone.ZonePath(peerID)] {
				delete(state.PeerCleanups, peerID)
				changed = true
				continue
			}
			if cleanup.CleanupUnix <= 0 {
				cleanup.CleanupUnix = now.Unix()
				state.PeerCleanups[peerID] = cleanup
				changed = true
				continue
			}
			if now.Before(time.Unix(cleanup.CleanupUnix, 0).Add(cfg.CleanupAfter)) {
				continue
			}
			if exists {
				delete(state.SyncPeers, peerID)
				removed = append(removed, peerID)
			}
			delete(state.PeerCleanups, peerID)
			changed = true
		case peerCleanupReasonOffline:
			if exists && peer.LastSyncUnix > cleanup.LastActiveUnix {
				delete(state.PeerCleanups, peerID)
				changed = true
				continue
			}
			if exists {
				delete(state.SyncPeers, peerID)
				removed = append(removed, peerID)
				changed = true
			}
		default:
			delete(state.PeerCleanups, peerID)
			changed = true
		}
	}

	for peerID, peer := range state.SyncPeers {
		if _, marked := state.PeerCleanups[peerID]; marked {
			continue
		}
		lastActive := peerLifecycleLastActiveUnix(peer)
		if revoked[zone.ZonePath(peerID)] {
			state.PeerCleanups[peerID] = peerLifecycleCleanupState{
				LastActiveUnix: lastActive,
				CleanupUnix:    now.Unix(),
				Reason:         peerCleanupReasonRevoked,
			}
			changed = true
			continue
		}
		if !peerLifecycleCleanupDue(peer, now, cfg) {
			continue
		}
		state.PeerCleanups[peerID] = peerLifecycleCleanupState{
			LastActiveUnix: lastActive,
			CleanupUnix:    now.Unix(),
			Reason:         peerCleanupReasonOffline,
		}
		delete(state.SyncPeers, peerID)
		removed = append(removed, peerID)
		changed = true
	}
	sort.Strings(removed)
	return removed, changed
}

func (d *DaemonService) flushPeerLifecycleCleanup() bool {
	if d == nil || d.StateStore == nil || d.Sync == nil {
		return false
	}
	cfg := inspect.PeerLifecycleConfig{}
	if d.Sync.App != nil && d.Sync.App.Config != nil {
		cfg = d.Sync.App.Config.PeerLifecycle
	}
	now := d.Sync.now()
	if !d.StateStore.peerLifecycleCleanupProjection(now, cfg) {
		return false
	}
	state, revision := d.StateStore.Snapshot()
	removed, changed := applyPeerLifecycleCleanup(state, now, cfg)
	if !changed {
		return false
	}
	if _, _, err := d.StateStore.commitPeerCleanupsIfRevision(revision, state.PeerCleanups); err != nil {
		d.logWarn("peer_lifecycle", "cleanup_commit_failed", map[string]any{"error": err})
		return false
	}
	if _, err := d.StateStore.DeleteCommonPeerCheckpoints(context.Background(), removed); err != nil {
		d.logWarn("peer_lifecycle", "checkpoint_cleanup_failed", map[string]any{"error": err})
		return false
	}
	for _, peerID := range removed {
		d.PeerObservability.Delete(peerID)
	}
	d.logInfo("peer_lifecycle", "cleanup_applied", map[string]any{"peers": removed})
	return true
}
