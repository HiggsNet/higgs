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
