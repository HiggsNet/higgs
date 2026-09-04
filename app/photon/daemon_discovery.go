package main

import (
	"context"

	photonstate "github.com/HiggsNet/photon/internal/state"
	corehost "github.com/HiggsNet/photon/pkg/core/host"
)

// updateDiscoveredPeers supplies detached owner data to HostRuntime. Peer
// selection, endpoint ordering, checkpoint patches and address-book updates
// are common runtime responsibilities.
func (d *Daemon) updateDiscoveredPeers() {
	if d == nil || d.StateStore == nil || d.hostRuntime == nil || d.hostRuntime.Transport() == nil {
		return
	}
	if err := d.hostRuntime.RefreshGossipDiscovery(context.Background(), d.currentGossipSuppressions(), d.now(), d.hostRuntime.Transport()); err != nil {
		d.logWarn("endpoint", "discovered_peer_commit_failed", map[string]any{"error": err})
	}
}

// currentGossipConfig derives app/platform gossip settings from the current
// app config and verified identity. Protocol execution keeps its own detached
// configuration inside host.Runtime.
func (d *Daemon) currentGossipConfig() *gossipStartupConfig {
	if d == nil || d.App == nil || d.App.Config == nil {
		return nil
	}
	config := gossipStartupConfigFromAppConfig(d.App.Config, nil)
	if d.hostRuntime != nil {
		driverConfig := d.hostRuntime.GossipConfig()
		if driverConfig.PeerID != "" {
			config.PeerID = driverConfig.PeerID
		}
		if driverConfig.Limits.MaxZones > 0 {
			config.MaxSyncZones = driverConfig.Limits.MaxZones
		}
		if driverConfig.Limits.MaxRecords > 0 {
			config.MaxSyncRecords = driverConfig.Limits.MaxRecords
		}
		if len(driverConfig.Discovery.BootstrapPeers) > 0 {
			config.Bootstrap = make([]syncConfigPeer, 0, len(driverConfig.Discovery.BootstrapPeers))
			for _, peerID := range driverConfig.Discovery.BootstrapPeers {
				peer := syncConfigPeer{ID: peerID}
				if addr := driverConfig.Discovery.Bootstrap[peerID]; addr != nil {
					peer.Addr = addr.String()
				}
				config.Bootstrap = append(config.Bootstrap, peer)
			}
		}
	}
	return config
}

func (d *Daemon) currentGossipSuppressions() map[string]bool {
	if d == nil || d.StateStore == nil {
		return nil
	}
	d.StateStore.mu.RLock()
	cleanups := photonstate.ClonePeerLifecycleCleanups(d.StateStore.runtime.PeerCleanups)
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

func gossipHostRuntimeConfig(config *gossipStartupConfig, app *appConfig, logger *appLogger) corehost.GossipRuntimeConfig {
	if config == nil {
		return corehost.GossipRuntimeConfig{}
	}
	bootstrapPeers := make([]string, 0, len(config.Bootstrap))
	for _, peer := range config.Bootstrap {
		bootstrapPeers = append(bootstrapPeers, peer.ID)
	}
	runtimeConfig := corehost.GossipRuntimeConfig{
		PeerID: config.PeerID,
		Limits: syncLimits(config),
		Log:    gossipRuntimeLogger(logger),
		Discovery: corehost.GossipDiscoveryConfig{
			Bootstrap:      configuredKnownPeers(config),
			BootstrapPeers: bootstrapPeers,
		},
	}
	if app != nil {
		runtimeConfig.Discovery.EndpointGrace = app.EndpointGrace
		runtimeConfig.Discovery.SourceOrder = append([]string(nil), app.EndpointSourceOrder...)
	}
	return runtimeConfig
}

func gossipRuntimeLogger(logger *appLogger) func(corehost.GossipRuntimeLog) {
	return func(event corehost.GossipRuntimeLog) {
		if logger == nil {
			return
		}
		fields := make(map[string]any, len(event.Fields)+3)
		for key, value := range event.Fields {
			fields[key] = value
		}
		if event.PeerID != "" {
			fields["peer_id"] = event.PeerID
		}
		if event.Phase != "" {
			fields["phase"] = event.Phase
		}
		if event.Err != nil {
			fields["error"] = event.Err
		}
		switch event.Level {
		case "warn":
			logger.Warn("sync", event.Event, fields)
		default:
			logger.Debug("sync", event.Event, fields)
		}
	}
}
