package host

import (
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

func TestRuntimeBuildsFetchAndObjectPullResponsesFromBoundStore(t *testing.T) {
	now := time.Unix(1000, 0)
	path := zone.ZonePath("peer.catofes.")
	network := zone.NewNetworkState()
	network.Zones[path] = zone.NewZoneState(path, &zone.ZoneAuthority{Zone: path, Epoch: 1, Threshold: 1})
	store := corestate.NewStore(&corestate.VerifiedState{ManagedZone: "local.catofes.", Network: network}, nil)
	runtime := NewRuntime(NewClock(func() time.Time { return now }), DefaultEventBuffer, store, GossipRuntimeConfig{PeerID: "local.catofes."})
	defer runtime.Stop()

	fetch := runtime.GossipFetchZoneResponse(path, gossip.DefaultDatagramBudget, now)
	if !fetch.Found || fetch.Snapshot == nil || fetch.Snapshot.Zone != path || len(fetch.Plan.Announces) != 1 {
		t.Fatalf("fetch response = %#v", fetch)
	}
	pull := runtime.GossipObjectPullResponse(&gossip.ObjectPullRequest{Type: gossip.ObjectPullZone, Zone: path}, now)
	if pull == nil || !pull.OK || pull.Snapshot == nil || pull.Snapshot.Zone != path {
		t.Fatalf("object pull response = %#v", pull)
	}
	if missing := runtime.GossipFetchZoneResponse("missing.catofes.", gossip.DefaultDatagramBudget, now); missing.Found || missing.Snapshot != nil || len(missing.Plan.Announces) != 0 {
		t.Fatalf("missing fetch response = %#v", missing)
	}
}
