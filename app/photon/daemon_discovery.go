package main

import (
	"context"

	corehost "github.com/HiggsNet/photon/pkg/core/host"
)

// updateDiscoveredPeers supplies detached owner data to HostRuntime. Peer
// selection, endpoint ordering, checkpoint patches and address-book updates
// are common runtime responsibilities.
func (d *DaemonService) updateDiscoveredPeers() {
	if d == nil || d.Sync == nil || d.Sync.Config == nil || d.Sync.Transport == nil || d.StateStore == nil || d.hostRuntime == nil {
		return
	}
	if err := d.hostRuntime.RefreshGossipDiscovery(context.Background(), d.currentGossipSuppressions(), d.Sync.now(), d.Sync.Transport); err != nil {
		d.logWarn("endpoint", "discovered_peer_commit_failed", map[string]any{"error": err})
	}
}

func (d *DaemonService) seedObservedPeerPath(peerID string) {
	if d == nil || d.Sync == nil || d.Sync.Transport == nil || d.StateStore == nil || d.hostRuntime == nil || peerID == "" {
		return
	}
	if err := d.hostRuntime.RestoreGossipObservedPath(peerID, d.currentGossipSuppressions(), d.Sync.now(), d.Sync.Transport); err != nil {
		d.logDebug("endpoint", "observed_path_restore_failed", map[string]any{"peer_id": peerID, "error": err})
	}
}

func (d *DaemonService) currentGossipSuppressions() map[string]bool {
	if d == nil || d.StateStore == nil {
		return nil
	}
	d.StateStore.mu.RLock()
	cleanups := clonePeerCleanups(d.StateStore.runtime.PeerCleanups)
	d.StateStore.mu.RUnlock()
	return peerCleanupSuppressions(cleanups)
}

func peerCleanupSuppressions(cleanups map[string]peerLifecycleCleanupState) map[string]bool {
	suppressed := make(map[string]bool, len(cleanups))
	for peerID := range cleanups {
		suppressed[peerID] = true
	}
	return suppressed
}

func gossipHostRuntimeConfig(config *syncConfigFile) corehost.GossipRuntimeConfig {
	if config == nil {
		return corehost.GossipRuntimeConfig{}
	}
	bootstrapPeers := make([]string, 0, len(config.Bootstrap))
	for _, peer := range config.Bootstrap {
		bootstrapPeers = append(bootstrapPeers, peer.ID)
	}
	return corehost.GossipRuntimeConfig{
		PeerID: config.PeerID,
		Limits: syncLimits(config),
		Discovery: corehost.GossipDiscoveryConfig{
			Bootstrap:      configuredKnownPeers(config),
			BootstrapPeers: bootstrapPeers,
			EndpointGrace:  config.EndpointGrace,
			SourceOrder:    append([]string(nil), config.EndpointSourceOrder...),
		},
	}
}
