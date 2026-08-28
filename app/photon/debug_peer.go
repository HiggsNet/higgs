package main

import (
	"fmt"
	"os"
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
	inspecttext "github.com/HiggsNet/photon/internal/inspect/text"
	"github.com/HiggsNet/photon/internal/observability"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

func debugPeer(peerID string) error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	if view, ok, err := readCanonicalViewViaControl[inspect.PeerDebugView](rt, controlRequest{Method: "peer_debug", Zone: peerID}); err != nil {
		return err
	} else if ok {
		fmt.Printf("daemon: online peer_id=%s\n", view.PeerID)
		return inspecttext.WritePeerDebug(os.Stdout, view)
	}
	common, _, err := loadOfflineOwnerViews(rt)
	if err != nil {
		return err
	}
	if common.State == nil {
		return fmt.Errorf("common state is not initialized")
	}
	fmt.Fprintln(os.Stdout, "source: checkpoint (daemon offline; last-known gossip runtime)")
	config := syncConfigFromAppConfig(rt.Config, common.State)
	now := rt.Now()
	view, err := buildDebugPeerView(common.State.ManagedZone, common.State.Network, syncPeerReadView(common.Gossip), config, peerID, now)
	if err != nil {
		return err
	}
	return inspecttext.WritePeerDebug(os.Stdout, view)
}

func buildDebugPeerView(managedZone zone.ZonePath, network *zone.NetworkState, peers map[string]syncPeerState, config *syncConfigFile, peerID string, now time.Time) (inspect.PeerDebugView, error) {
	if network == nil {
		return inspect.PeerDebugView{}, fmt.Errorf("network is nil")
	}
	if !inspect.PeerKnown(inspectPeerSetInput(managedZone, network, peers, config, now), peerID) {
		return inspect.PeerDebugView{}, fmt.Errorf("%w: %s", zone.ErrZoneNotFound, peerID)
	}
	return buildGossipPeerView(network, peers, config, peerID, now), nil
}

func buildGossipPeerViews(managedZone zone.ZonePath, network *zone.NetworkState, peers map[string]syncPeerState, config *syncConfigFile, now time.Time) []inspect.PeerDebugView {
	if network == nil {
		return nil
	}
	peerIDs := inspect.BuildPeerIDs(inspectPeerSetInput(managedZone, network, peers, config, now))
	views := make([]inspect.PeerDebugView, 0, len(peerIDs))
	for _, peerID := range peerIDs {
		views = append(views, buildGossipPeerView(network, peers, config, peerID, now))
	}
	return views
}

func buildGossipPeerView(network *zone.NetworkState, peers map[string]syncPeerState, config *syncConfigFile, peerID string, now time.Time) inspect.PeerDebugView {
	known := configuredKnownPeers(config)
	peerState := peers[peerID]
	source, configuredAddr := gossipPeerSource(config, peerID, peerState)
	endpoints := inspectPeerEndpoints(peerID, peerState, observability.PeerDiagnostics{}, config, network, now)
	resolved := "-"
	if addr := known[peerID]; addr != nil {
		resolved = addr.String()
	}
	if selected := selectedPeerEndpointAddr(endpoints); selected != "" {
		resolved = selected
	}
	return buildPeerDebugView(peerID, source, configuredAddr, resolved, peerState, observability.PeerDiagnostics{}, now)
}

func buildPeerDebugView(peerID, source, configuredAddr, resolved string, peerState syncPeerState, diagnostics observability.PeerDiagnostics, now time.Time) inspect.PeerDebugView {
	return inspect.BuildPeerDebugFromRuntime(inspect.PeerRuntimeDebugInput{
		PeerID:         peerID,
		Source:         source,
		ConfiguredAddr: configuredAddr,
		ResolvedAddr:   resolved,
		State:          peerState,
		Diagnostics:    diagnostics,
		Now:            now,
	})
}

func bootstrapPeerSource(config *syncConfigFile, peerID string) (string, string) {
	if config == nil {
		return "unknown", ""
	}
	for _, peer := range config.Bootstrap {
		if peer.ID == peerID {
			return "bootstrap", peer.Addr
		}
	}
	return "unknown", ""
}

func gossipPeerSource(config *syncConfigFile, peerID string, peerState syncPeerState) (string, string) {
	if source, configuredAddr := bootstrapPeerSource(config, peerID); source == "bootstrap" {
		return source, configuredAddr
	}
	if peerState.ObservedAddr != "" {
		return "observed", ""
	}
	return "discovered", ""
}
