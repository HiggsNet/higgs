package ipsec

import "testing"

func TestParseSAStatesFromVICIListSAs(t *testing.T) {
	states := parseSAStates(map[string]any{
		"ipsec-main-ab": map[string]any{
			"local-host":  "198.51.100.10",
			"local-port":  "4500",
			"local-id":    "node-a.catofes.",
			"remote-host": "2001:db8::20",
			"remote-port": "4500",
			"remote-id":   "node-b.catofes.",
			"child-sas": map[string]any{
				"ipsec-main-ab-child": map[string]any{
					"reqid":     "17",
					"if-id-in":  "77",
					"if-id-out": "78",
				},
			},
		},
	})
	if len(states) != 1 {
		t.Fatalf("states len = %d, want 1: %+v", len(states), states)
	}
	got := states[0]
	if got.Name != "ipsec-main-ab" || got.ChildSA != "ipsec-main-ab-child" {
		t.Fatalf("names = %+v", got)
	}
	if got.LocalIdentity != "node-a.catofes." || got.RemoteIdentity != "node-b.catofes." {
		t.Fatalf("identities = %+v", got)
	}
	if got.LocalEndpoint != "198.51.100.10:4500" || got.RemoteEndpoint != "[2001:db8::20]:4500" || got.Endpoint != got.RemoteEndpoint {
		t.Fatalf("endpoints = %+v", got)
	}
	if got.XFRMIfID != 78 || got.ReqID != 17 || !got.Established {
		t.Fatalf("child fields = %+v", got)
	}
}
