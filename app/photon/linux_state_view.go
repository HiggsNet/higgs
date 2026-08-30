package main

import (
	"encoding/hex"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
)

func cloneLinuxRuntimeState(runtime *linuxRuntimeState) *linuxRuntimeState {
	if runtime == nil {
		return &linuxRuntimeState{}
	}
	return &linuxRuntimeState{
		IdentityKeyPath:   runtime.IdentityKeyPath,
		PeerCleanups:      clonePeerCleanups(runtime.PeerCleanups),
		IPsecTransportKey: cloneIPsecTransportKeyState(runtime.IPsecTransportKey),
		IPsecPortRecord:   cloneIPsecPortRecordState(runtime.IPsecPortRecord),
		LinkInstances:     cloneLinkInstances(runtime.LinkInstances),
		IPsecReconcile:    cloneIPsecReconcileState(runtime.IPsecReconcile),
		RoutingReconcile:  cloneRoutingReconcileState(runtime.RoutingReconcile),
		FirewallReconcile: cloneFirewallReconcileState(runtime.FirewallReconcile),
		EndpointACLs:      cloneEndpointACLs(runtime.EndpointACLs),
		BirdInstances:     cloneBirdInstances(runtime.BirdInstances),
		Admission:         cloneAdmissionState(runtime.Admission),
	}
}

func syncPeerReadView(checkpoint *corestate.GossipCheckpoint) map[string]syncPeerState {
	peers := make(map[string]syncPeerState)
	if checkpoint == nil {
		return peers
	}
	for peerID, item := range checkpoint.Peers {
		peer := syncPeerState{
			LastSyncUnix:            item.LastSyncUnix,
			LastAttemptUnix:         item.LastAttemptUnix,
			BackoffUntilUnix:        item.BackoffUntilUnix,
			LastRelayUnix:           item.LastRelayUnix,
			LastRelayCatalogRootHex: item.LastRelayCatalogRootHex,
			FailureCount:            item.FailureCount,
			DiscoveredAddr:          item.DiscoveredEndpoint,
			DiscoveredAtUnix:        item.DiscoveredAtUnix,
			ObservedAddr:            item.ObservedEndpoint,
			ObservedFirstSeenUnix:   item.ObservedFirstSeenUnix,
			ObservedLastSeenUnix:    item.ObservedLastSeenUnix,
			ObservedLastSyncUnix:    item.ObservedLastSyncUnix,
			ObservedUntilUnix:       item.ObservedUntilUnix,
			ObservedFailureCount:    item.ObservedFailureCount,
		}
		if item.LastFailure != nil {
			peer.LastError = item.LastFailure.Error()
		}
		for _, grace := range item.ObservedGraceEndpoints {
			peer.ObservedGraceAddrs = append(peer.ObservedGraceAddrs, observedGraceAddrState{
				Addr: grace.Endpoint, UntilUnix: grace.UntilUnix,
			})
		}
		if len(item.RejectedObjects) > 0 {
			peer.RejectedDigests = make(map[string]rejectedDigestState, len(item.RejectedObjects))
			for path, rejected := range item.RejectedObjects {
				key := string(path)
				peer.RejectedDigests[key] = rejectedDigestState{
					Zone: path, RootHashHex: hex.EncodeToString(rejected.RootHash), Reason: rejected.Reason,
					RejectedAtUnix: rejected.UpdatedUnix, UntilUnix: rejected.UntilUnix,
				}
			}
		}
		peers[peerID] = peer
	}
	return peers
}

func clonePeerCleanups(in map[string]peerLifecycleCleanupState) map[string]peerLifecycleCleanupState {
	if in == nil {
		return nil
	}
	out := make(map[string]peerLifecycleCleanupState, len(in))
	for peerID, cleanup := range in {
		out[peerID] = cleanup
	}
	return out
}
