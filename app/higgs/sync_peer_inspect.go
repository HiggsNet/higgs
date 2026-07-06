package main

import (
	"time"

	"github.com/Catofes/higgs/internal/inspect"
)

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
