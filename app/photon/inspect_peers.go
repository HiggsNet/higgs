package main

import (
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
	"github.com/HiggsNet/photon/pkg/core/observability"
)

func gossipPeersOptions(config *syncConfigFile, diagnostics map[string]observability.PeerDiagnostics, now time.Time) inspect.GossipPeersOptions {
	options := inspect.GossipPeersOptions{Diagnostics: diagnostics, Now: now}
	if config == nil {
		return options
	}
	options.LocalPeerID = config.PeerID
	known := configuredKnownPeers(config)
	for _, peer := range config.Bootstrap {
		bootstrap := inspect.PeerBootstrap{PeerID: peer.ID, Addr: peer.Addr}
		if addr := known[peer.ID]; addr != nil {
			bootstrap.ResolvedAddr = addr.String()
		}
		options.Bootstrap = append(options.Bootstrap, bootstrap)
	}
	return options
}
