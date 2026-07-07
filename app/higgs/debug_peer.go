package main

import (
	"fmt"
	"os"
	"time"

	"github.com/Catofes/higgs/internal/inspect"
	inspecttext "github.com/Catofes/higgs/internal/inspect/text"
)

func debugPeer(peerID string) error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	if response, ok, err := daemonStatusViaControl(rt); err != nil {
		return err
	} else if ok {
		fmt.Printf("daemon: online peer_id=%s\n", response.PeerID)
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
	known := configuredKnownPeers(config)
	peerState := state.SyncPeers[peerID]
	source, configuredAddr := bootstrapPeerSource(config, peerID)
	endpoints := inspectPeerEndpoints(peerID, peerState, config, state.Network, now)
	resolved := "-"
	if addr := known[peerID]; addr != nil {
		resolved = addr.String()
	}
	if selected := selectedPeerEndpointAddr(endpoints); selected != "" {
		resolved = selected
	}
	return inspecttext.WritePeerDebug(os.Stdout, buildPeerDebugView(peerID, source, configuredAddr, resolved, peerState, now))
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
	for _, peer := range config.Bootstrap {
		if peer.ID == peerID {
			return "bootstrap", peer.Addr
		}
	}
	return "unknown", ""
}
