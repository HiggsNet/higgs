package main

import (
	"fmt"
	"os"
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
	inspecttext "github.com/HiggsNet/photon/internal/inspect/text"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

func debugPeer(peerID string) error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	state, err := rt.LoadState()
	if err != nil {
		return err
	}
	config, err := rt.SyncConfig(state)
	if err != nil {
		return err
	}
	now := rt.Now()
	view, err := buildDebugPeerView(state, config, peerID, now)
	if err != nil {
		return err
	}
	if response, ok, err := daemonStatusViaControl(rt); err != nil {
		return err
	} else if ok {
		fmt.Printf("daemon: online peer_id=%s\n", response.PeerID)
	}
	return inspecttext.WritePeerDebug(os.Stdout, view)
}

func buildDebugPeerView(state *stateFile, config *syncConfigFile, peerID string, now time.Time) (inspect.PeerDebugView, error) {
	if state == nil {
		return inspect.PeerDebugView{}, fmt.Errorf("state is nil")
	}
	if !inspect.PeerKnown(inspectPeerSetInput(state, config, now), peerID) {
		return inspect.PeerDebugView{}, fmt.Errorf("%w: %s", zone.ErrZoneNotFound, peerID)
	}
	return buildGossipPeerView(state, config, peerID, now), nil
}

func buildGossipPeerViews(state *stateFile, config *syncConfigFile, now time.Time) []inspect.PeerDebugView {
	if state == nil {
		return nil
	}
	peerIDs := inspect.BuildPeerIDs(inspectPeerSetInput(state, config, now))
	views := make([]inspect.PeerDebugView, 0, len(peerIDs))
	for _, peerID := range peerIDs {
		views = append(views, buildGossipPeerView(state, config, peerID, now))
	}
	return views
}

func buildGossipPeerView(state *stateFile, config *syncConfigFile, peerID string, now time.Time) inspect.PeerDebugView {
	known := configuredKnownPeers(config)
	peerState := state.SyncPeers[peerID]
	source, configuredAddr := gossipPeerSource(config, peerID, peerState)
	endpoints := inspectPeerEndpoints(peerID, peerState, config, state.Network, now)
	resolved := "-"
	if addr := known[peerID]; addr != nil {
		resolved = addr.String()
	}
	if selected := selectedPeerEndpointAddr(endpoints); selected != "" {
		resolved = selected
	}
	return buildPeerDebugView(peerID, source, configuredAddr, resolved, peerState, now)
}

func buildPeerDebugView(peerID, source, configuredAddr, resolved string, peerState syncPeerState, now time.Time) inspect.PeerDebugView {
	return inspect.BuildPeerDebugFromRuntime(inspect.PeerRuntimeDebugInput{
		PeerID:         peerID,
		Source:         source,
		ConfiguredAddr: configuredAddr,
		ResolvedAddr:   resolved,
		State:          peerState,
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
