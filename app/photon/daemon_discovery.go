package main

import (
	"net"
	"sort"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
)

type daemonPeerTransportUpdate struct {
	setAddrs       []*net.UDPAddr
	removeAddrs    bool
	observedPaths  []gossip.ObservedPath
	preferObserved bool
	removeObserved bool
}

type daemonDiscoveryPlan struct {
	knownPeerIDs []string
	peers        map[string]daemonPeerTransportUpdate
}

// updateDiscoveredPeers keeps endpoint control state in StateStore while
// deferring every transport mutation until the local-COW commit succeeds.
// Planning is replayable, so a stale global revision can be retried safely.
func (d *DaemonService) updateDiscoveredPeers() {
	if d == nil || d.Sync == nil || d.Sync.Config == nil || d.Sync.Transport == nil || d.StateStore == nil {
		return
	}
	now := d.Sync.now()
	var committedPlan daemonDiscoveryPlan
	_, changed, err := d.StateStore.updateSyncPeersWithView(func(view syncPeerMutationView) (map[string]syncPeerState, error) {
		updates, plan := planDaemonDiscoveredPeers(view, d.Sync.Config, now)
		committedPlan = plan
		return updates, nil
	})
	if err != nil {
		d.logWarn("endpoint", "discovered_peer_commit_failed", map[string]any{"error": err})
		return
	}

	// The plan corresponds to the revision that either committed or was found
	// to need no state change. No transport operation occurs on stale attempts.
	applyDaemonDiscoveryPlan(d.Sync.Transport, committedPlan)
	if !changed {
		return
	}
	if err := d.saveCommittedState(); err != nil {
		d.logWarn("endpoint", "discovered_peer_save_failed", map[string]any{"error": err})
	}
}

func planDaemonDiscoveredPeers(view syncPeerMutationView, config *syncConfigFile, now time.Time) (map[string]syncPeerState, daemonDiscoveryPlan) {
	updates := make(map[string]syncPeerState)
	plan := daemonDiscoveryPlan{peers: make(map[string]daemonPeerTransportUpdate)}
	if view.Network == nil || config == nil {
		return updates, plan
	}

	plan.knownPeerIDs = verifiedZonePeerIDs(view, config, now)
	discovered := gossip.ExtractPeerEndpointsAt(view.Network, now)
	bootstrapPeers := configuredKnownPeers(config)
	activeDiscovered := make(map[string]bool)

	// Bootstrap peers must remain dialable even before their zone or endpoint
	// record has been learned. Re-seed their configured addresses on every
	// discovery refresh so reloads and address-book cleanup cannot leave the
	// configuration visible in diagnostics but absent from the live transport.
	for peerID, bootstrapAddr := range bootstrapPeers {
		entries := discovered[peerID]
		current := view.SyncPeers[peerID]
		addrs := buildPeerAddrs(peerID, entries, bootstrapAddr, current, config.EndpointGrace, config.EndpointSourceOrder, now)
		if len(addrs) == 0 {
			continue
		}
		action := plan.peers[peerID]
		action.setAddrs = addrs
		plan.peers[peerID] = action
	}

	for peerID, entries := range discovered {
		if peerID == config.PeerID || peerID == string(view.ManagedZone) || len(entries) == 0 {
			continue
		}
		current := view.SyncPeers[peerID]
		addrs := buildPeerAddrs(peerID, entries, bootstrapPeers[peerID], current, config.EndpointGrace, config.EndpointSourceOrder, now)
		if len(addrs) == 0 {
			continue
		}
		activeDiscovered[peerID] = true
		action := plan.peers[peerID]
		action.setAddrs = addrs
		plan.peers[peerID] = action
		// A lifecycle-cleaned peer remains dialable so a successful gossip
		// exchange can prove recovery, but its cache entry stays absent until
		// that success clears the persisted suppression marker.
		if _, suppressed := view.PeerCleanups[peerID]; suppressed {
			continue
		}

		next := cloneSyncPeerState(current)
		addr := addrs[0].String()
		at := now.Unix()
		if next.DiscoveredAddr != addr || next.DiscoveredAtUnix != at {
			next.DiscoveredAddr = addr
			next.DiscoveredAtUnix = at
			updates[peerID] = next
		}
	}

	peerIDs := make([]string, 0, len(view.SyncPeers))
	for peerID := range view.SyncPeers {
		peerIDs = append(peerIDs, peerID)
	}
	sort.Strings(peerIDs)
	for _, peerID := range peerIDs {
		current := view.SyncPeers[peerID]
		next := cloneSyncPeerState(current)
		if staged, ok := updates[peerID]; ok {
			next = cloneSyncPeerState(staged)
		}
		action := plan.peers[peerID]
		peerChanged := false

		if current.ObservedAddr != "" && !observedPathActive(current, now) {
			action.removeObserved = true
			next.ObservedAddr = ""
			next.ObservedFirstSeenUnix = 0
			next.ObservedLastSeenUnix = 0
			next.ObservedLastSyncUnix = 0
			next.ObservedUntilUnix = 0
			next.ObservedFailureCount = 0
			peerChanged = true
		} else {
			// Legacy ordering seeds the observed path before refreshing the
			// discovered address, so preference is derived from the committed
			// peer rather than this plan's staged discovery fields.
			paths, prefer, ok := plannedObservedPaths(view, peerID, current, now)
			if ok {
				action.observedPaths = paths
				action.preferObserved = prefer
			} else {
				action.removeObserved = true
			}
		}

		if next.DiscoveredAddr != "" &&
			!activeDiscovered[peerID] &&
			!isBootstrapPeer(config, peerID) &&
			peerID != config.PeerID &&
			peerID != string(view.ManagedZone) &&
			len(discovered[peerID]) == 0 &&
			len(appendRecentSuccessfulDiscoveredAddr(nil, next, config.EndpointGrace, now)) == 0 {
			action.removeAddrs = true
			next.DiscoveredAddr = ""
			next.DiscoveredAtUnix = 0
			peerChanged = true
		}

		if peerChanged {
			updates[peerID] = next
		}
		plan.peers[peerID] = action
	}
	return updates, plan
}

func plannedObservedPaths(view syncPeerMutationView, peerID string, peer syncPeerState, now time.Time) ([]gossip.ObservedPath, bool, bool) {
	// pruneObservedGraceAddrs compacts its input slice in place, so detach the
	// immutable committed peer before using it to build the transport plan.
	peer = cloneSyncPeerState(peer)
	state := &stateFile{
		ManagedZone: view.ManagedZone,
		Network:     view.Network,
		SyncPeers:   map[string]syncPeerState{peerID: peer},
	}
	if !observedPathActive(peer, now) || !peerChainVerified(state, peerID, now) {
		return nil, false, false
	}
	addr, err := net.ResolveUDPAddr("udp", peer.ObservedAddr)
	if err != nil {
		return nil, false, false
	}
	paths := []gossip.ObservedPath{{Addr: addr, Until: time.Unix(peer.ObservedUntilUnix, 0)}}
	for _, entry := range pruneObservedGraceAddrs(peer.ObservedGraceAddrs, peer.ObservedAddr, now) {
		graceAddr, err := net.ResolveUDPAddr("udp", entry.Addr)
		if err != nil {
			continue
		}
		paths = append(paths, gossip.ObservedPath{Addr: graceAddr, Until: time.Unix(entry.UntilUnix, 0)})
	}
	return paths, observedPathPreferFirst(peer, now), true
}

func (d *DaemonService) seedObservedPeerPath(peerID string) {
	if d == nil || d.Sync == nil || d.Sync.Transport == nil || d.StateStore == nil || peerID == "" {
		return
	}
	now := d.Sync.now()
	paths, prefer, ok := d.StateStore.observedPathsProjection(peerID, now)
	if !ok {
		d.Sync.Transport.RemoveObservedPeerAddr(peerID)
		return
	}
	d.Sync.Transport.SetObservedPeerPaths(peerID, paths, prefer)
}

func verifiedZonePeerIDs(view syncPeerMutationView, config *syncConfigFile, now time.Time) []string {
	if view.Network == nil || config == nil {
		return nil
	}
	network := *view.Network
	configureValidation(&network)
	seen := make(map[string]bool)
	add := func(path zone.ZonePath) {
		peerID := string(path)
		if peerID == "" || peerID == config.PeerID || peerID == string(view.ManagedZone) {
			return
		}
		seen[peerID] = true
	}
	for path := range network.Zones {
		if photoncrypto.VerifyChain(&network, path, now) == nil {
			add(path)
		}
	}
	for parentPath, zs := range network.Zones {
		if zs == nil || len(zs.Delegations) == 0 || photoncrypto.VerifyChain(&network, parentPath, now) != nil {
			continue
		}
		for childPath := range zs.Delegations {
			if !network.IsZoneRevoked(childPath, now) {
				add(childPath)
			}
		}
	}
	out := make([]string, 0, len(seen))
	for peerID := range seen {
		out = append(out, peerID)
	}
	sort.Strings(out)
	return out
}

func applyDaemonDiscoveryPlan(transport *gossip.Transport, plan daemonDiscoveryPlan) {
	if transport == nil {
		return
	}
	for _, peerID := range plan.knownPeerIDs {
		transport.AddKnownPeerID(peerID)
	}
	peerIDs := make([]string, 0, len(plan.peers))
	for peerID := range plan.peers {
		peerIDs = append(peerIDs, peerID)
	}
	sort.Strings(peerIDs)
	for _, peerID := range peerIDs {
		action := plan.peers[peerID]
		if action.removeObserved {
			transport.RemoveObservedPeerAddr(peerID)
		} else if len(action.observedPaths) > 0 {
			transport.SetObservedPeerPaths(peerID, action.observedPaths, action.preferObserved)
		}
		if action.removeAddrs {
			transport.RemovePeerAddrs(peerID)
		} else if len(action.setAddrs) > 0 {
			transport.SetPeerAddrs(peerID, action.setAddrs)
		}
	}
}
