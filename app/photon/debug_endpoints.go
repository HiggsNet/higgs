package main

import (
	"os"

	"github.com/HiggsNet/photon/internal/inspect"
	inspecttext "github.com/HiggsNet/photon/internal/inspect/text"
	"github.com/HiggsNet/photon/pkg/core/gossip"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
)

func debugEndpoints() error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	if view, ok, err := readCanonicalViewViaControl[inspect.EndpointDebugView](rt, controlRequest{Method: "endpoints_view"}); err != nil {
		return err
	} else if ok {
		return inspecttext.WriteEndpointsDebug(os.Stdout, view)
	}
	common, _, err := loadOfflineOwnerViews(rt)
	if err != nil {
		return err
	}
	if common.State == nil {
		return nil
	}
	view := buildEndpointDebugView(rt, common.State)
	return inspecttext.WriteEndpointsDebug(os.Stdout, view)
}

func buildEndpointDebugView(rt *Runtime, state *corestate.VerifiedState) inspect.EndpointDebugView {
	if rt == nil || rt.Config == nil || state == nil {
		return inspect.EndpointDebugView{}
	}
	config := syncConfigFromAppConfig(rt.Config, state)
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
	return inspect.BuildEndpointDebug(inspect.EndpointDebugInput{
		ReflectorError:      reflectorError,
		HasPublicReflectors: len(gossip.ResolvePublicIPReflectors(reflectors)) > 0,
		LocalCandidates:     localCandidates,
		Discovered:          discoveredInput,
	})
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
