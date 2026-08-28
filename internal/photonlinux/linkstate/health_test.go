package linkstate

import (
	"net/netip"
	"testing"

	photonstate "github.com/HiggsNet/photon/internal/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func TestHealthTargetsDistinguishOldAndStagedRuntime(t *testing.T) {
	oldLocal := netip.MustParseAddr("fe80::10")
	oldPeer := netip.MustParseAddr("fe80::20")
	newLocal := netip.MustParseAddr("fe80::11")
	newPeer := netip.MustParseAddr("fe80::21")
	outputs := []photonstate.LinkOutput{
		{
			ID: "link-1", GroupID: "blue", PeerZone: zone.ZonePath("peer.example."),
			PathKey: "family:ipv6", NetNS: "photon-blue", InterfaceName: "phx-old",
			LocalAddr: oldLocal, PeerAddr: oldPeer, RuntimeRole: photonstate.LinkRuntimeActive, State: "up",
		},
		{
			ID: "link-1#staged", GroupID: "blue", PeerZone: zone.ZonePath("peer.example."),
			PathKey: "family:ipv6", NetNS: "photon-blue", InterfaceName: "phx-new",
			LocalAddr: newLocal, PeerAddr: newPeer, RuntimeRole: photonstate.LinkRuntimeStaged, State: "up",
		},
	}

	targets := HealthTargets(outputs, "local.example.")
	if len(targets) != 2 {
		t.Fatalf("targets = %d, want 2", len(targets))
	}
	if old := targets[0]; old.ProbeID != "link-1#old" || old.ProbeRole != "old" || old.Staged {
		t.Fatalf("old target = %+v", old)
	}
	if staged := targets[1]; staged.InstanceID != "link-1" || staged.ProbeID != "link-1#staged" || staged.ProbeRole != "staged" || !staged.Staged {
		t.Fatalf("staged target = %+v", staged)
	}
	if targets[0].UnderlayFamily != ipsec.FamilyIPv6 || targets[1].UnderlayFamily != ipsec.FamilyIPv6 {
		t.Fatalf("underlay families = %q/%q, want ipv6", targets[0].UnderlayFamily, targets[1].UnderlayFamily)
	}
}

func TestHealthTargetsSkipOutputsWithoutTunnelAddresses(t *testing.T) {
	outputs := []photonstate.LinkOutput{{
		ID: "link-1", RuntimeRole: photonstate.LinkRuntimeActive, State: "up",
	}}
	if targets := HealthTargets(outputs, "local.example."); len(targets) != 0 {
		t.Fatalf("targets = %+v, want none", targets)
	}
}
