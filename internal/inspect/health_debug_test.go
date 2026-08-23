package inspect

import "testing"

func TestBuildHealthDebugViewSortsTargets(t *testing.T) {
	view := BuildHealthDebugView(HealthDebugView{
		Targets: []HealthProbeTargetView{
			{InstanceID: "b", ProbeRole: "staged", ProbeID: "b-staged"},
			{InstanceID: "a", ProbeRole: "active", ProbeID: "a-active"},
			{InstanceID: "b", ProbeRole: "active", ProbeID: "b-active"},
		},
	})

	if got := view.Targets; len(got) != 3 ||
		got[0].ProbeID != "a-active" ||
		got[1].ProbeID != "b-active" ||
		got[2].ProbeID != "b-staged" {
		t.Fatalf("targets = %+v, want sorted by instance and role", got)
	}
}

func TestBuildHealthViewSortsByPeerOrRTT(t *testing.T) {
	view := HealthDebugView{
		Targets: []HealthProbeTargetView{
			{ProbeID: "slow", InstanceID: "link-a", PeerZone: "node-a."},
			{ProbeID: "missing", InstanceID: "link-c", PeerZone: "node-c."},
			{ProbeID: "fast", InstanceID: "link-b", PeerZone: "node-b."},
		},
		Live: []HealthLiveView{
			{ProbeID: "slow", EWMARTTMs: 80},
			{ProbeID: "fast", EWMARTTMs: 10},
		},
	}

	byPeer := BuildHealthView(view, HealthSortPeer)
	if byPeer.Targets[0].ProbeID != "missing" || byPeer.Targets[1].ProbeID != "fast" || byPeer.Targets[2].ProbeID != "slow" {
		t.Fatalf("peer sort = %+v", byPeer.Targets)
	}
	byRTT := BuildHealthView(view, HealthSortRTT)
	if byRTT.Targets[0].ProbeID != "fast" || byRTT.Targets[1].ProbeID != "slow" || byRTT.Targets[2].ProbeID != "missing" {
		t.Fatalf("rtt sort = %+v", byRTT.Targets)
	}
}

func TestBuildHealthViewPeerSortMatchesLinksZoneOrdering(t *testing.T) {
	view := BuildHealthView(HealthDebugView{Targets: []HealthProbeTargetView{
		{ProbeID: "child", InstanceID: "c", PeerZone: "node-a.example."},
		{ProbeID: "parent", InstanceID: "p", PeerZone: "example."},
		{ProbeID: "last", InstanceID: "z", PeerZone: "node-z.example."},
	}}, HealthSortPeer)

	want := []string{"last", "child", "parent"}
	for i, probeID := range want {
		if view.Targets[i].ProbeID != probeID {
			t.Fatalf("targets[%d] = %q, want %q; targets=%+v", i, view.Targets[i].ProbeID, probeID, view.Targets)
		}
	}
}
