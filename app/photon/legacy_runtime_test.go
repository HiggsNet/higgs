package main

import (
	"context"
	"io"
	"slices"
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
	inspecttext "github.com/HiggsNet/photon/internal/inspect/text"
	photonlinux "github.com/HiggsNet/photon/internal/photonlinux"
	"github.com/HiggsNet/photon/pkg/core/gossip"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/routing/bird"
	photonservice "github.com/HiggsNet/photon/pkg/service"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func (d *DaemonService) setState(state *stateFile) {
	if d == nil {
		return
	}
	replacement := newTestDaemonService(d.Sync.App, state, d.Sync.Config, d.Interval)
	d.StateStore = replacement.StateStore
}

func (d *DaemonService) currentState() *stateFile {
	if d == nil || d.StateStore == nil {
		return nil
	}
	state, _ := snapshotTestDaemonState(d.StateStore)
	return state
}

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

func writeDebugLinks(w io.Writer, rt *Runtime, state *stateFile, filter string) error {
	runtime := linuxRuntimeStateFromLegacy(state)
	view := buildStoredLinkInspection(rt, runtime.LinkInstances, runtime.IPsecReconcile, runtime.BirdInstances, nil)
	view.Filter = filter
	return inspecttext.WriteLinksDebug(w, view)
}

func (d *DaemonService) recordBirdHealthObservationUnavailable(netnsName string, overlays []string) {
	if d == nil || d.StateStore == nil {
		return
	}
	readCommittedForTest(d.StateStore, func(state *stateFile) {
		d.recordBirdHealthObservationUnavailableForLinks(state.LinkInstances, state.IPsecReconcile, netnsName, overlays)
	})
}

func (d *DaemonService) recordBirdHealthObservation(netnsName string, overlays []string, observed *bird.BirdObservedState) {
	if d == nil || d.StateStore == nil {
		return
	}
	readCommittedForTest(d.StateStore, func(state *stateFile) {
		d.recordBirdHealthObservationForLinks(state.LinkInstances, state.IPsecReconcile, netnsName, overlays, observed)
	})
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

func pullObjectTCP(addr string, req *gossip.ObjectPullRequest) (*gossip.ObjectPullResponse, error) {
	return (photonlinux.GossipObjectPullClient{}).Exchange(context.Background(), addr, req)
}

func objectPullLookup(getState func() *stateFile) func(*gossip.ObjectPullRequest) *gossip.ObjectPullResponse {
	return func(req *gossip.ObjectPullRequest) *gossip.ObjectPullResponse {
		state := getState()
		var network *zone.NetworkState
		if state != nil {
			network = state.Network
		}
		response := gossip.BuildObjectPullResponse(network, req, time.Now())
		return response
	}
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

func UpdateRevocationLayerStatus(impact *inspect.RevocationImpact, layer string, status, reason, errStr string, now time.Time) {
	if impact == nil || impact.Layers == nil {
		return
	}
	entry := impact.Layers[layer]
	if entry == nil {
		entry = &inspect.RevocationLayerStatus{}
		impact.Layers[layer] = entry
	}
	entry.Status, entry.Reason, entry.Error, entry.UnixTime = status, reason, errStr, now.Unix()
}

func publishSOCKS5ServiceWithRuntime(rt *Runtime, region, address string, port uint16) error {
	return publishSOCKS5EndpointsWithRuntime(rt, []photonservice.SOCKS5Endpoint{{Region: region, Address: address, Port: port}})
}
