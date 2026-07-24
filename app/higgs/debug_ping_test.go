package main

import (
	"testing"

	pingdebug "github.com/Catofes/higgs/internal/ping"
	"github.com/Catofes/higgs/pkg/core/zone"
	"github.com/Catofes/higgs/pkg/health"
)

// pingDebugTargets builds the health targets for a fixture state with a
// dual-stack non-rotating link to node-b. and a rotating IPv6 link to node-c.
func pingDebugTargets(t *testing.T) []health.ProbeTarget {
	t.Helper()
	state := &stateFile{
		ManagedZone: zone.ZonePath("local."),
		LinkInstances: map[string]linkInstanceState{
			"link-b": {ActualState: "up"},
			"link-c": {
				ActualState:           "up",
				InterfaceName:         "hgs-old",
				LocalTunnelAddr:       "fd00::1",
				PeerTunnelAddr:        "fd00::2",
				StagedGeneration:      2,
				RotatePhase:           "testing_new",
				StagedInterfaceName:   "hgs-new",
				StagedLocalTunnelAddr: "fd00::3",
				StagedPeerTunnelAddr:  "fd00::4",
			},
		},
		IPsecReconcile: &ipsecReconcileState{
			Desired: []desiredLinkState{
				{InstanceID: "link-b", GroupID: "g", PeerZone: zone.ZonePath("node-b."), LocalTunnelAddr: "10.0.0.1", PeerTunnelAddr: "10.0.0.2"},
				{InstanceID: "link-b", GroupID: "g", PeerZone: zone.ZonePath("node-b."), LocalTunnelAddr: "fd00::1", PeerTunnelAddr: "fd00::2"},
				{InstanceID: "link-c", GroupID: "g", PeerZone: zone.ZonePath("node-c."), LocalTunnelAddr: "fd00::1", PeerTunnelAddr: "fd00::2"},
			},
		},
	}
	return healthTargetsFromState(state, string(state.ManagedZone), nil)
}

func TestPingDebugTargetsIncludeActiveOldAndStagedRoles(t *testing.T) {
	targets := pingDebugTargets(t)
	if got := len(targets); got != 4 {
		t.Fatalf("fixture targets = %d, want 4", got)
	}
	cSel := pingdebug.SelectTargetsResolved(targets, "node-c.", pingdebug.ResolveOptions(pingdebug.Options{}))
	roles := map[string]bool{}
	for _, sel := range cSel {
		roles[pingdebug.Role(sel)] = true
	}
	if !roles["old"] || !roles["staged"] {
		t.Fatalf("node-c. roles = %v, want old+staged", roles)
	}
}
