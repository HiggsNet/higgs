package main

import (
	"testing"

	"github.com/Catofes/higgs/pkg/core/zone"
)

func TestPendingPredecessorFetches(t *testing.T) {
	ns := zone.NewNetworkState()
	ns.Zones["node-b.catofes."] = zone.NewZoneState("node-b.catofes.", &zone.ZoneAuthority{
		Zone:      "node-b.catofes.",
		Threshold: 1,
	})
	ns.Zones["node-b.catofes."].PendingRecords["identity"] = []*zone.Record{
		{Zone: "node-b.catofes.", Key: "identity", Version: 3},
		{Zone: "node-b.catofes.", Key: "identity", Version: 1},
	}

	fetches := pendingPredecessorFetches(ns)
	if len(fetches) != 1 {
		t.Fatalf("fetches len = %d, want 1", len(fetches))
	}
	if fetches[0].Zone != "node-b.catofes." || fetches[0].Key != "identity" || fetches[0].Version != 2 {
		t.Fatalf("fetch = %#v, want node-b.catofes./identity v2", fetches[0])
	}
}
