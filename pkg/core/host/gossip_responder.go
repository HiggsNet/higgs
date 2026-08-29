package host

import (
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

// GossipFetchZoneResponse is detached responder input derived from one
// committed Store read. Platform code may choose UDP send mechanics and emit
// diagnostics, but it cannot rebuild or reinterpret verified state.
type GossipFetchZoneResponse struct {
	Found    bool
	Plan     gossip.DatagramPlan
	Snapshot *corestate.ZoneSnapshot
}

func (runtime *Runtime) GossipFetchZoneResponse(path zone.ZonePath, budget int, now time.Time) GossipFetchZoneResponse {
	if runtime == nil || runtime.gossipState == nil {
		return GossipFetchZoneResponse{}
	}
	view := runtime.gossipState.ReadView()
	if view.State == nil || view.State.Network == nil || view.State.Network.Zones[path] == nil {
		return GossipFetchZoneResponse{}
	}
	network := view.State.Network
	response := GossipFetchZoneResponse{Found: true, Plan: gossip.PlanSnapshotDatagrams(network, []zone.ZonePath{path}, budget, now)}
	if network.IsZoneRevoked(path, now) {
		return response
	}
	response.Snapshot, _ = corestate.Snapshot(network, path)
	return response
}

// GossipObjectPullResponse serves a read-only TCP object pull from the same
// committed Store owned by Runtime. A missing Store is treated like an empty
// source rather than allowing platform composition to read another state root.
func (runtime *Runtime) GossipObjectPullResponse(request *gossip.ObjectPullRequest, now time.Time) *gossip.ObjectPullResponse {
	if runtime == nil || runtime.gossipState == nil {
		return &gossip.ObjectPullResponse{Error: "invalid request"}
	}
	view := runtime.gossipState.ReadView()
	var network *zone.NetworkState
	if view.State != nil {
		network = view.State.Network
	}
	return gossip.BuildObjectPullResponse(network, request, now)
}
