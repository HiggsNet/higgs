package zone

import "testing"

func TestZonePathParentAndAncestors(t *testing.T) {
	zp := ZonePath("node1.pek.catofes.")

	if got, want := zp.Parent(), ZonePath("pek.catofes."); got != want {
		t.Fatalf("Parent() = %q, want %q", got, want)
	}

	got := zp.Ancestors()
	want := []ZonePath{"node1.pek.catofes.", "pek.catofes.", "catofes.", "."}
	if len(got) != len(want) {
		t.Fatalf("Ancestors() len = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Ancestors()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestNetworkStateGetFallback(t *testing.T) {
	ns := NewNetworkState()
	ns.Zones[RootZone] = NewZoneState(RootZone, nil)
	ns.Zones["catofes."] = NewZoneState("catofes.", nil)
	ns.Zones["pek.catofes."] = NewZoneState("pek.catofes.", nil)

	rootRecord := &Record{Zone: RootZone, Key: "policy/allowed-transports", Value: []byte("wireguard")}
	siteRecord := &Record{Zone: "catofes.", Key: "policy/mtu", Value: []byte("1400")}

	if err := ns.Put(rootRecord); err != nil {
		t.Fatalf("Put(rootRecord): %v", err)
	}
	if err := ns.Put(siteRecord); err != nil {
		t.Fatalf("Put(siteRecord): %v", err)
	}

	got, err := ns.Get("pek.catofes./policy/mtu")
	if err != nil {
		t.Fatalf("Get(site fallback): %v", err)
	}
	if got != siteRecord {
		t.Fatalf("Get(site fallback) returned wrong record")
	}

	got, err = ns.Get("pek.catofes./policy/allowed-transports")
	if err != nil {
		t.Fatalf("Get(root fallback): %v", err)
	}
	if got != rootRecord {
		t.Fatalf("Get(root fallback) returned wrong record")
	}
}
