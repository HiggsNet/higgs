package inspect

import "testing"

func TestBuildPingDebugViewSortsAndGroupsTargets(t *testing.T) {
	view := BuildPingDebugView(PingDebugView{
		AvailableZones: []string{"node-c.", "node-b."},
		Targets: []PingTargetView{
			{InstanceID: "b", Role: "staged", Family: "ipv6", ProbeID: "b-staged"},
			{InstanceID: "a", Family: "ipv6", ProbeID: "a-v6"},
			{InstanceID: "a", Role: "active", Family: "ipv4", ProbeID: "a-v4"},
		},
	})

	if got := view.AvailableZones; len(got) != 2 || got[0] != "node-b." || got[1] != "node-c." {
		t.Fatalf("available zones = %v, want sorted", got)
	}
	if len(view.Instances) != 2 {
		t.Fatalf("instances = %+v, want 2 groups", view.Instances)
	}
	if view.Instances[0].InstanceID != "a" || view.Instances[1].InstanceID != "b" {
		t.Fatalf("instance order = %+v, want a then b", view.Instances)
	}
	rows := view.Instances[0].Rows
	if len(rows) != 2 || rows[0].Family != "ipv4" || rows[1].Family != "ipv6" {
		t.Fatalf("rows for a = %+v, want active ipv4 before ipv6", rows)
	}
}

func TestPingTargetDefaults(t *testing.T) {
	target := PingTargetView{ProbeID: "probe-a"}
	if got := PingTargetInstanceID(target); got != "probe-a" {
		t.Fatalf("PingTargetInstanceID = %q, want probe-a", got)
	}
	if got := PingTargetRole(target); got != "active" {
		t.Fatalf("PingTargetRole = %q, want active", got)
	}
}
