package host

import (
	"github.com/HiggsNet/photon/pkg/core/gossip"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

// GossipObjectPullCompletion is the platform-neutral result returned by an
// object-pull controller. Runtime owns its conversion to an FSM event and the
// queue backpressure contract.
type GossipObjectPullCompletion struct {
	PeerID   string
	Zone     zone.ZonePath
	Snapshot *corestate.ZoneSnapshot
	Err      error
}

// PostGossipObjectPullCompletion returns an asynchronous pull result to the
// same ordered event queue used by UDP packets and gossip timers.
func (runtime *Runtime) PostGossipObjectPullCompletion(completion GossipObjectPullCompletion) error {
	return runtime.PostGossip(&gossip.ObjectPullResultEvent{
		PeerID:   completion.PeerID,
		Zone:     completion.Zone,
		Snapshot: completion.Snapshot,
		Err:      completion.Err,
	})
}
