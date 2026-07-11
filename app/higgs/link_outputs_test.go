package main

import (
	"testing"

	higgsstate "github.com/Catofes/higgs/internal/state"
	"github.com/Catofes/higgs/pkg/core/zone"
	"github.com/Catofes/higgs/pkg/transport/ipsec"
)

func TestLinkOutputsProjectIPsecRuntimeWithoutLifecycleState(t *testing.T) {
	state := &stateFile{
		LinkInstances: map[string]linkInstanceState{
			"instance-a": {
				ID:               "instance-a",
				LinkID:           "link-a",
				GroupID:          "blue",
				PeerZone:         "node-b.catofes.",
				TransportKind:    ipsec.ProviderStrongSwan,
				PathKey:          "family:ipv6",
				ActualState:      "up",
				InterfaceName:    "hgs0",
				LocalTunnelAddr:  "fe80::1%hgs0 netns=h2",
				PeerTunnelAddr:   "fe80::2%hgs0 netns=h2",
				RemoteGeneration: 3,
				Endpoint:         "198.51.100.2:4500",
				LastTransition:   123,
				Owner:            linkOwnerState{Token: "must-not-leak"},
			},
		},
	}

	got := linkOutputsFromState(state)
	if len(got) != 1 {
		t.Fatalf("outputs = %d, want 1", len(got))
	}
	link := got[0]
	if link.ID != "link-a" || link.GroupID != "blue" || link.PeerZone != zone.ZonePath("node-b.catofes.") {
		t.Fatalf("identity = %+v", link)
	}
	if link.Provider != ipsec.ProviderStrongSwan || link.RuntimeRole != higgsstate.LinkRuntimeActive || link.Generation != 3 {
		t.Fatalf("runtime identity = %+v", link)
	}
	if link.NetNS != "h2" || link.InterfaceName != "hgs0" || link.LocalAddr.String() != "fe80::1" || link.PeerAddr.String() != "fe80::2" {
		t.Fatalf("babel-facing scope = %+v", link)
	}
	if link.Readiness.Session != higgsstate.LinkReadyReady || link.Readiness.Interface != higgsstate.LinkReadyReady || link.Readiness.Routing != higgsstate.LinkReadyUnknown || link.Readiness.Health != higgsstate.LinkReadyUnknown {
		t.Fatalf("readiness = %+v", link.Readiness)
	}
}

func TestLinkOutputsProjectStagedRuntimeSeparately(t *testing.T) {
	state := &stateFile{
		LinkInstances: map[string]linkInstanceState{
			"link-a": {
				ID:                    "link-a",
				GroupID:               "blue",
				ActualState:           "up",
				InterfaceName:         "hgs-old",
				LocalTunnelAddr:       "fe80::1%hgs-old netns=h2",
				PeerTunnelAddr:        "fe80::2%hgs-old netns=h2",
				RemoteGeneration:      1,
				StagedGeneration:      2,
				RotatePhase:           "testing_new",
				StagedInterfaceName:   "hgs-new",
				StagedLocalTunnelAddr: "fe80::3%hgs-new netns=h2",
				StagedPeerTunnelAddr:  "fe80::4%hgs-new netns=h2",
				StagedIKEName:         "provider-private-runtime-name",
				StagedChildSAName:     "provider-private-child-name",
			},
		},
	}

	got := linkOutputsFromState(state)
	if len(got) != 2 {
		t.Fatalf("outputs = %+v, want active and staged", got)
	}
	byRole := map[string]higgsstate.LinkOutput{}
	for _, link := range got {
		byRole[link.RuntimeRole] = link
	}
	if active := byRole[higgsstate.LinkRuntimeActive]; active.ID != "link-a" || active.InterfaceName != "hgs-old" || active.Generation != 1 {
		t.Fatalf("active = %+v", active)
	}
	if staged := byRole[higgsstate.LinkRuntimeStaged]; staged.ID != "link-a#staged" || staged.InterfaceName != "hgs-new" || staged.Generation != 2 || staged.PeerAddr.String() != "fe80::4" {
		t.Fatalf("staged = %+v", staged)
	}
}
