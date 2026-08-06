package main

import (
	"os"

	"github.com/HiggsNet/photon/internal/inspect"
	inspecttext "github.com/HiggsNet/photon/internal/inspect/text"
	"github.com/HiggsNet/photon/pkg/core/gossip"
)

func debugEndpoints() error {
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
	port := listenPortFromAddr(config.ListenAddr)
	advertiseAddrs, reflectors := filterEndpointDiscoveryInputs(config, port)
	candidates, reflectorErr := collectSyncLocalEndpoints(port, advertiseAddrs, reflectors, config.ReflectorTimeout, config.FilterPrivateIPv4)
	localCandidates := make([]inspect.EndpointCandidateView, 0, len(candidates))
	for _, ep := range candidates {
		localCandidates = append(localCandidates, inspect.EndpointCandidateView{
			Address:  ep.IP.String(),
			Port:     ep.Port,
			Scope:    ep.Scope,
			Priority: ep.Priority,
			Source:   endpointSourceString(ep.Source),
		})
	}

	discovered := gossip.ExtractPeerEndpoints(state.Network)
	discoveredInput := make(map[string][]inspect.PeerSignedEndpoint, len(discovered))
	for peerID, endpoints := range discovered {
		for _, ep := range endpoints {
			discoveredInput[peerID] = append(discoveredInput[peerID], inspect.PeerSignedEndpoint{
				Address:      ep.Address,
				Port:         ep.Port,
				Scope:        ep.Scope,
				Priority:     ep.Priority,
				Protocol:     ep.Protocol,
				Source:       ep.Source,
				LastObserved: ep.LastObserved,
			})
		}
	}
	reflectorError := ""
	if reflectorErr != nil {
		reflectorError = reflectorErr.Error()
	}
	view := inspect.BuildEndpointDebug(inspect.EndpointDebugInput{
		ReflectorError:      reflectorError,
		HasPublicReflectors: len(gossip.ResolvePublicIPReflectors(reflectors)) > 0,
		LocalCandidates:     localCandidates,
		Discovered:          discoveredInput,
	})
	return inspecttext.WriteEndpointsDebug(os.Stdout, view)
}

func endpointSourceString(source gossip.LocalEndpointSource) string {
	switch source {
	case gossip.SourceAdvertise:
		return "advertise"
	case gossip.SourceInterface:
		return "interface"
	case gossip.SourceReflector:
		return "reflector"
	default:
		return "unknown"
	}
}
