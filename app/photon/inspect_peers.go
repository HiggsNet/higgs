package main

import (
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
	"github.com/HiggsNet/photon/internal/observability"
	"github.com/HiggsNet/photon/pkg/core/gossip"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

func inspectPeerSetInput(managedZone zone.ZonePath, network *zone.NetworkState, peers map[string]syncPeerState, config *syncConfigFile, now time.Time) inspect.PeerSetInput {
	input := inspect.PeerSetInput{}
	if managedZone != "" {
		input.LocalIDs = append(input.LocalIDs, string(managedZone))
	}
	if peers != nil {
		input.RuntimeIDs = make([]string, 0, len(peers))
		for id := range peers {
			input.RuntimeIDs = append(input.RuntimeIDs, id)
		}
	}
	for id := range gossip.ExtractPeerEndpointsAt(network, now) {
		input.SignedIDs = append(input.SignedIDs, id)
	}
	if config != nil {
		input.LocalIDs = append(input.LocalIDs, config.PeerID)
		input.BootstrapIDs = make([]string, 0, len(config.Bootstrap))
		for _, peer := range config.Bootstrap {
			input.BootstrapIDs = append(input.BootstrapIDs, peer.ID)
		}
	}
	return input
}

func inspectPeerEndpointInput(peerID string, ps syncPeerState, diagnostics observability.PeerDiagnostics, config *syncConfigFile, ns *zone.NetworkState, now time.Time) inspect.PeerEndpointInput {
	input := inspect.PeerEndpointInput{
		BootstrapAddr:  bootstrapAddrForPeer(config, peerID),
		SelectedAddr:   ps.DiscoveredAddr,
		ObservedAddr:   ps.ObservedAddr,
		ObservedSource: diagnostics.ObservedSource,
		Grace:          make([]inspect.PeerGraceEndpoint, 0, len(ps.ObservedGraceAddrs)),
	}
	discovered := gossip.ExtractPeerEndpointsAt(ns, now)
	for _, ep := range discovered[peerID] {
		input.Signed = append(input.Signed, inspect.PeerSignedEndpoint{
			Address:      ep.Address,
			Port:         ep.Port,
			Protocol:     ep.Protocol,
			Scope:        ep.Scope,
			Source:       ep.Source,
			Priority:     ep.Priority,
			LastObserved: ep.LastObserved,
		})
	}
	for _, grace := range ps.ObservedGraceAddrs {
		input.Grace = append(input.Grace, inspect.PeerGraceEndpoint{Addr: grace.Addr})
	}
	return input
}

func inspectPeerEndpoints(peerID string, ps syncPeerState, diagnostics observability.PeerDiagnostics, config *syncConfigFile, ns *zone.NetworkState, now time.Time) []inspect.PeerEndpointView {
	return inspect.BuildPeerEndpoints(inspectPeerEndpointInput(peerID, ps, diagnostics, config, ns, now))
}

func bootstrapAddrForPeer(config *syncConfigFile, peerID string) string {
	if config == nil {
		return ""
	}
	for _, peer := range config.Bootstrap {
		if peer.ID == peerID {
			return peer.Addr
		}
	}
	return ""
}

func selectedPeerEndpointAddr(endpoints []inspect.PeerEndpointView) string {
	for _, ep := range endpoints {
		if ep.Selected && ep.Addr != "" {
			return ep.Addr
		}
	}
	for _, ep := range endpoints {
		if ep.Addr != "" {
			return ep.Addr
		}
	}
	return ""
}
