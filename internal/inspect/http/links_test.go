package http

import (
	"encoding/json"
	"testing"

	"github.com/Catofes/photon/internal/inspect"
)

func TestLinksFromInspectionPreservesObserverSchema(t *testing.T) {
	got := LinksFromInspection(inspect.LinkInspection{
		Summary: inspect.LinkSummary{
			LastRunUnix:  123,
			DesiredLinks: 1,
			ActualSAs:    1,
			LastError:    "boom",
		},
		Actions: []inspect.LinkAction{{Action: "adopt", InstanceID: "link-1"}},
		Skipped: []inspect.LinkSkip{{GroupID: "blue", Reason: "missing_peer"}},
		Links: []inspect.LinkView{{
			ID:              "link-1",
			PeerZone:        "node-b.catofes.",
			GroupID:         "blue",
			State:           "up",
			ActualState:     "up",
			Endpoint:        "198.51.100.10:4500",
			InterfaceName:   "phx0",
			XFRMIfID:        42,
			DesiredSpecHash: "abcdef0123456789",
			Desired:         &inspect.DesiredLink{PeerTunnelAddr: "fd00::2%phx0"},
			ActualSA:        &inspect.LinkSA{ReqID: 77, RemoteIdentity: "node-b.catofes."},
			Routing:         inspect.LinkRouting{BirdState: "running"},
		}},
	})
	if len(got.Instances) != 1 {
		t.Fatalf("instances = %d, want 1", len(got.Instances))
	}
	data, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if decoded["last_run_unix"] != float64(123) || decoded["desired_links"] != float64(1) {
		t.Fatalf("summary fields missing: %#v", decoded)
	}
	instances := decoded["instances"].([]any)
	link := instances[0].(map[string]any)
	if link["peer_zone"] != "node-b.catofes." || link["xfrm_if_id"] != float64(42) {
		t.Fatalf("link fields missing: %#v", link)
	}
	if link["raw"] == nil {
		t.Fatalf("raw link view omitted: %#v", link)
	}
}
