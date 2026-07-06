package inspect

import "testing"

func TestBuildFirewallDebugView(t *testing.T) {
	view := BuildFirewallDebug(FirewallDebugInput{
		Backend: "dry-run",
		Instances: []FirewallInstanceInput{
			{
				ID:            "higgstesth2",
				Scope:         "higgstesth2",
				Enabled:       true,
				Mode:          FirewallModeManaged,
				Backend:       "auto",
				DefaultPolicy: "drop",
			},
			{
				ID:            "host",
				Scope:         "host",
				Enabled:       true,
				Mode:          FirewallModeManaged,
				IsHost:        true,
				HostIKE:       true,
				HostNATT:      true,
				RedirectGrace: true,
			},
		},
		Snapshot: map[string]FirewallInstanceSnapshot{
			"higgstesth2": {Generation: 5, OwnedObjects: 10, PolicyHash: "abc123"},
		},
	})
	if view.Backend != "dry-run" {
		t.Fatalf("backend = %q, want dry-run", view.Backend)
	}
	if len(view.Instances) != 2 {
		t.Fatalf("instances = %d, want 2", len(view.Instances))
	}
	if got := view.Instances[0]; got.ID != "higgstesth2" || got.Generation != 5 || got.OwnedObjects != 10 || got.PolicyHash != "abc123" {
		t.Fatalf("first instance = %+v, want reconcile fields", got)
	}
	if got := view.Instances[1]; !got.IsHost || !got.HostIKE || !got.HostNATT || !got.RedirectGrace {
		t.Fatalf("host instance = %+v, want host flags", got)
	}
}

func TestBuildFirewallDebugDefaultsAndDisabledMode(t *testing.T) {
	view := BuildFirewallDebug(FirewallDebugInput{
		Instances: []FirewallInstanceInput{
			{ID: "enabled", Enabled: true},
			{ID: "disabled", Enabled: false, Mode: FirewallModeManaged},
		},
	})
	if got := view.Instances[0].Mode; got != FirewallModeManaged {
		t.Fatalf("enabled default mode = %q, want managed", got)
	}
	if got := view.Instances[1].Mode; got != "disabled" {
		t.Fatalf("disabled mode = %q, want disabled", got)
	}
}
