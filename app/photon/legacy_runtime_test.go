package main

import (
	"slices"
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
	photonlinux "github.com/HiggsNet/photon/internal/photonlinux"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func (sr *SyncRuntime) publishIPsecRecords(state *stateFile) error {
	plan, err := sr.ipsecProtocolPlan(verifiedStateForTest(state), linuxRuntimeStateFromLegacy(state))
	if err != nil {
		return err
	}
	changed := false
	for _, raw := range plan.Intents {
		intent := raw.(corestate.PutProtocolRecordIntent)
		record, err := buildSignedRecordAt(state, intent.Zone, intent.Key, intent.Value, intent.Type, sr.now())
		if err != nil {
			return err
		}
		if err := state.Network.PutAt(record, sr.now()); err != nil {
			return err
		}
		changed = true
	}
	if !ipsecTransportKeyStateEqual(state.IPsecTransportKey, plan.TransportKey) {
		state.IPsecTransportKey = cloneIPsecTransportKeyState(plan.TransportKey)
		changed = true
	}
	if !ipsecPortRecordStateEqual(state.IPsecPortRecord, plan.PortRecord) {
		state.IPsecPortRecord = cloneIPsecPortRecordState(plan.PortRecord)
		changed = true
	}
	if !changed {
		return nil
	}
	if err := sr.App.SaveState(state); err != nil {
		return err
	}
	if sr != nil && state != nil {
		sr.logger().Debug("ipsec", "publish_saved", map[string]any{"managed_zone": state.ManagedZone})
	}
	return nil
}

func xfrmLinkStateMatchesCandidate(state ipsec.XFRMLinkState, spec ipsec.TransportLinkSpec) bool {
	matches, _ := photonlinux.XFRMLinkStateMatchReason(state, spec)
	return matches
}

func assignIPAMWithRuntime(rt *Runtime, path zone.ZonePath, prefix string, assignedTo zone.ZonePath, shared bool) error {
	return assignIPAMWithRuntimeTag(rt, path, prefix, assignedTo, shared, "")
}

func revokeIPAMAssignmentWithRuntime(rt *Runtime, path zone.ZonePath, prefix string) error {
	return revokeIPAMAssignmentWithRuntimeTo(rt, path, prefix, "")
}

func derivePeerStatus(state *stateFile, peerID string, peerZone zone.ZonePath, now time.Time, cfg inspect.PeerLifecycleConfig) inspect.PeerStatusInfo {
	if state == nil {
		return inspect.BuildPeerLifecycleStatus(inspect.PeerLifecycleInput{PeerID: peerID, PeerZone: peerZone, StateAvailable: false, Now: now, Config: cfg})
	}
	return inspect.BuildPeerLifecycleStatus(peerLifecycleInput(state.Network, testGossipCheckpointFromLegacyPeers(state.SyncPeers), state.PeerCleanups, state.LinkInstances, state.IPsecReconcile, peerID, peerZone, now, cfg, false))
}

func peerLifecycleCleanupZones(state *stateFile, now time.Time, cfg inspect.PeerLifecycleConfig) []zone.ZonePath {
	if state == nil {
		return nil
	}
	hasOverlay := state.IPsecReconcile != nil && state.IPsecReconcile.DesiredLinks > 0
	peers := derivePeerStatuses(state.ManagedZone, state.Network, testGossipCheckpointFromLegacyPeers(state.SyncPeers), state.PeerCleanups, state.LinkInstances, state.IPsecReconcile, now, inspect.NormalizePeerLifecycleConfig(cfg), hasOverlay)
	seen := make(map[zone.ZonePath]bool)
	var out []zone.ZonePath
	for _, peer := range peers {
		if inspect.PeerStatusRequiresCleanup(peer) && !seen[peer.Zone] {
			seen[peer.Zone] = true
			out = append(out, peer.Zone)
		}
	}
	slices.Sort(out)
	return out
}

func testGossipCheckpointFromLegacyPeers(peers map[string]syncPeerState) *corestate.GossipCheckpoint {
	checkpoint, _ := projectLegacyGossipCheckpoint(peers)
	return checkpoint
}
