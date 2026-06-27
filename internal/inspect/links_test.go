package inspect

import "testing"

func TestBuildLinksPrefersPlannedDesiredOverLastSnapshot(t *testing.T) {
	got := BuildLinks(LinkInput{
		Instances: []LinkInstance{{
			ID:          "link-a",
			PeerZone:    "node-b.example.",
			GroupID:     "main",
			ActualState: "up",
			Endpoint:    "198.51.100.1:4500",
		}},
		LastDesired: []DesiredLink{{
			InstanceID:      "link-a",
			DesiredSpecHash: "old",
			Endpoint:        "198.51.100.1:4500",
		}},
		PlannedDesired: []DesiredLink{{
			InstanceID:      "link-a",
			DesiredSpecHash: "new",
			Endpoint:        "198.51.100.2:4500",
			LocalTunnelAddr: "fd00::1",
		}},
		ActualSAs: []LinkSA{{
			Name:        "link-a",
			Established: true,
		}},
		Health: []LinkHealth{{
			InstanceID: "link-a",
			State:      "healthy",
		}},
	})

	if got.Summary.PlannedDesired != 1 || got.Summary.LinkInstances != 1 || got.Summary.ActualSAs != 1 {
		t.Fatalf("summary = %+v", got.Summary)
	}
	if len(got.Links) != 1 {
		t.Fatalf("links = %d, want 1", len(got.Links))
	}
	link := got.Links[0]
	if link.Desired == nil || link.Desired.DesiredSpecHash != "new" {
		t.Fatalf("desired = %+v, want planned snapshot", link.Desired)
	}
	if link.Endpoint != "198.51.100.1:4500" {
		t.Fatalf("endpoint = %q, want persisted actual endpoint", link.Endpoint)
	}
	if link.ActualSA == nil || !link.ActualSA.Established {
		t.Fatalf("actual sa = %+v, want established", link.ActualSA)
	}
	if link.Health == nil || link.Health.State != "healthy" {
		t.Fatalf("health = %+v, want healthy", link.Health)
	}
}

func TestBuildLinksShowsMissingPlannedLinksWhenNoInstancesExist(t *testing.T) {
	got := BuildLinks(LinkInput{
		PlannedDesired: []DesiredLink{{
			InstanceID:    "link-b",
			GroupID:       "main",
			PeerZone:      "node-b.example.",
			InterfaceName: "hgs0",
			XFRMIfID:      42,
		}},
	})

	if !got.Summary.HasMissingPlanned {
		t.Fatalf("summary = %+v, want missing planned marker", got.Summary)
	}
	if len(got.Links) != 1 {
		t.Fatalf("links = %d, want 1", len(got.Links))
	}
	link := got.Links[0]
	if !link.Missing || link.State != "missing" || link.InterfaceName != "hgs0" || link.XFRMIfID != 42 {
		t.Fatalf("link = %+v, want missing planned link", link)
	}
}
