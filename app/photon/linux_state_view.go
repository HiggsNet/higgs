package main

import (
	"crypto/ed25519"
	"encoding/hex"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

// composeLinuxStateView builds the temporary aggregate consumed by existing
// Linux read projections and controller planners. Ownership remains split:
// common owns verified facts and gossip checkpoints, while runtime owns Linux
// controller/configuration fields. The returned stateFile is detached and
// must never be persisted as a state root or written back into either owner.
func composeLinuxStateView(common corestate.View, runtime *linuxRuntimeState) *stateFile {
	view := &stateFile{
		Network:   zone.NewNetworkState(),
		SyncPeers: make(map[string]syncPeerState),
	}
	if common.State != nil {
		view.ManagedZone = common.State.ManagedZone
		view.RootPrivateKey = append(ed25519.PrivateKey(nil), common.State.RootPrivateKey...)
		view.ZonePrivateKey = append(ed25519.PrivateKey(nil), common.State.IdentityPrivateKey...)
		view.Network = zone.CloneNetworkState(common.State.Network)
		if view.Network == nil {
			view.Network = zone.NewNetworkState()
		}
		configureValidation(view.Network)
	}
	view.SyncPeers = syncPeerReadView(common.Gossip)
	applyLinuxRuntimeReadView(view, runtime)
	return view
}

func applyLinuxRuntimeReadView(view *stateFile, runtime *linuxRuntimeState) {
	if view == nil || runtime == nil {
		return
	}
	view.IdentityKeyPath = runtime.IdentityKeyPath
	view.PeerCleanups = clonePeerCleanups(runtime.PeerCleanups)
	view.IPsecTransportKey = cloneIPsecTransportKeyState(runtime.IPsecTransportKey)
	view.IPsecPortRecord = cloneIPsecPortRecordState(runtime.IPsecPortRecord)
	view.LinkInstances = cloneLinkInstances(runtime.LinkInstances)
	view.IPsecReconcile = cloneIPsecReconcileState(runtime.IPsecReconcile)
	view.RoutingReconcile = cloneRoutingReconcileState(runtime.RoutingReconcile)
	view.FirewallReconcile = cloneFirewallReconcileState(runtime.FirewallReconcile)
	view.EndpointACLs = cloneEndpointACLs(runtime.EndpointACLs)
	view.BirdInstances = cloneBirdInstances(runtime.BirdInstances)
	view.Admission = cloneAdmissionState(runtime.Admission)
}

func cloneLinuxRuntimeState(runtime *linuxRuntimeState) *linuxRuntimeState {
	if runtime == nil {
		return &linuxRuntimeState{}
	}
	view := &stateFile{}
	applyLinuxRuntimeReadView(view, runtime)
	return linuxRuntimeStateFromLegacy(view)
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
