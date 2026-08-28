package main

import (
	"context"

	corehost "github.com/HiggsNet/photon/pkg/core/host"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
)

// updateDiscoveredPeers supplies detached owner data to HostRuntime. Peer
// selection, endpoint ordering, checkpoint patches and address-book updates
// are common runtime responsibilities.
func (d *DaemonService) updateDiscoveredPeers() {
	if d == nil || d.Sync == nil || d.Sync.Config == nil || d.Sync.Transport == nil || d.StateStore == nil || d.hostRuntime == nil {
		return
	}
	input := d.currentGossipDiscoveryInput()
	if err := d.hostRuntime.RefreshGossipDiscovery(context.Background(), input, d.Sync.now(), d.StateStore, d.Sync.Transport); err != nil {
		d.logWarn("endpoint", "discovered_peer_commit_failed", map[string]any{"error": err})
	}
}

func (d *DaemonService) seedObservedPeerPath(peerID string) {
	if d == nil || d.Sync == nil || d.Sync.Transport == nil || d.StateStore == nil || d.hostRuntime == nil || peerID == "" {
		return
	}
	if err := d.hostRuntime.RestoreGossipObservedPath(d.currentGossipDiscoveryInput(), peerID, d.Sync.now(), d.Sync.Transport); err != nil {
		d.logDebug("endpoint", "observed_path_restore_failed", map[string]any{"peer_id": peerID, "error": err})
	}
}

func (d *DaemonService) currentGossipDiscoveryInput() corehost.GossipDiscoveryInput {
	if d == nil || d.StateStore == nil || d.Sync == nil {
		return corehost.GossipDiscoveryInput{}
	}
	d.StateStore.writeMu.Lock()
	common := d.StateStore.common.ReadView()
	d.StateStore.mu.RLock()
	cleanups := clonePeerCleanups(d.StateStore.runtime.PeerCleanups)
	d.StateStore.mu.RUnlock()
	d.StateStore.writeMu.Unlock()
	return buildGossipDiscoveryInput(common, cleanups, d.Sync.Config)
}

func buildGossipDiscoveryInput(common corestate.View, cleanups map[string]peerLifecycleCleanupState, config *syncConfigFile) corehost.GossipDiscoveryInput {
	input := corehost.GossipDiscoveryInput{}
	if common.State == nil || config == nil {
		return input
	}
	input.LocalPeerID = config.PeerID
	input.ManagedZone = common.State.ManagedZone
	input.Network = common.State.Network
	if common.Gossip != nil {
		input.Peers = common.Gossip.Peers
	}
	input.Bootstrap = configuredKnownPeers(config)
	input.BootstrapPeers = make([]string, 0, len(config.Bootstrap))
	for _, peer := range config.Bootstrap {
		input.BootstrapPeers = append(input.BootstrapPeers, peer.ID)
	}
	input.EndpointGrace = config.EndpointGrace
	input.SourceOrder = append([]string(nil), config.EndpointSourceOrder...)
	input.Suppressed = make(map[string]bool, len(cleanups))
	for peerID := range cleanups {
		input.Suppressed[peerID] = true
	}
	return input
}
