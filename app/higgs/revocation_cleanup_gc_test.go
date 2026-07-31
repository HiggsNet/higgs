package main

import (
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/Catofes/higgs/pkg/core/zone"
)

// addRevocationTombstoneForTest installs a minimal revocation record that
// ActiveRevocation/IsZoneRevoked recognises (correct ChildZone/ParentZone,
// effective timestamp) without requiring a cryptographic signature. The
// matching delegation is removed, mirroring what revokeDelegationInState does.
func addRevocationTombstoneForTest(t *testing.T, state *stateFile, child, parent zone.ZonePath) {
	t.Helper()
	parentState := state.Network.Zones[parent]
	if parentState == nil {
		t.Fatalf("parent zone not found: %s", parent)
	}
	if parentState.Revocations == nil {
		parentState.Revocations = make(map[zone.ZonePath]*zone.DelegationRevocation)
	}
	parentState.Revocations[child] = &zone.DelegationRevocation{
		ChildZone:             child,
		ParentZone:            parent,
		RevokedAuthorityEpoch: 1,
		RevokedAt:             100,
	}
	delete(parentState.Delegations, child)
}

func TestOverlapsLocalIdentity(t *testing.T) {
	managed := zone.ZonePath("node-a.catofes.")
	cases := []struct {
		name string
		z    zone.ZonePath
		want bool
	}{
		{"self", "node-a.catofes.", true},
		{"descendant", "eth0.node-a.catofes.", false},
		{"ancestor", "catofes.", true},
		{"root ancestor", zone.RootZone, true},
		{"unrelated", "node-b.catofes.", false},
	}
	for _, c := range cases {
		if got := overlapsLocalIdentity(c.z, managed); got != c.want {
			t.Errorf("%s: overlapsLocalIdentity(%s) = %v, want %v", c.name, c.z, got, c.want)
		}
	}
	if overlapsLocalIdentity("node-b.catofes.", "") {
		t.Errorf("empty managed zone should never overlap")
	}
}

func TestPlanPurgeRevokedZones_AllCollectsSubtreeAndRefs(t *testing.T) {
	state, _ := buildTestNetworkState(t)
	now := time.Unix(123, 0)

	// Revoke node-b and add a descendant leaf so the subtree expansion is
	// exercised. node-b is a child of catofes.
	state.Network.Zones["leaf.node-b.catofes."] = zone.NewZoneState("leaf.node-b.catofes.", nil)
	addRevocationTombstoneForTest(t, state, "node-b.catofes.", "catofes.")

	// Local runtime residue pointing at the revoked zones.
	state.LinkInstances = map[string]linkInstanceState{
		"link-b":     {ID: "link-b", PeerZone: "node-b.catofes."},
		"link-leaf":  {ID: "link-leaf", PeerZone: "leaf.node-b.catofes."},
		"link-other": {ID: "link-other", PeerZone: "node-c.catofes."},
	}
	state.SyncPeers = map[string]syncPeerState{
		"node-b.catofes.":      {},
		"leaf.node-b.catofes.": {},
		"node-c.catofes.":      {},
	}

	plan, err := planPurgeRevokedZones(state, now, "")
	if err != nil {
		t.Fatalf("planPurgeRevokedZones(all): %v", err)
	}
	wantZones := []zone.ZonePath{"leaf.node-b.catofes.", "node-b.catofes."}
	if !equalZonePaths(plan.Zones, wantZones) {
		t.Errorf("Zones = %v, want %v", plan.Zones, wantZones)
	}
	wantLinks := []string{"link-b", "link-leaf"}
	if !equalStrings(plan.LinkInstances, wantLinks) {
		t.Errorf("LinkInstances = %v, want %v", plan.LinkInstances, wantLinks)
	}
	wantPeers := []string{"leaf.node-b.catofes.", "node-b.catofes."}
	if !equalStrings(plan.SyncPeers, wantPeers) {
		t.Errorf("SyncPeers = %v, want %v", plan.SyncPeers, wantPeers)
	}
	if len(plan.ManagedZoneSkipped) != 0 {
		t.Errorf("ManagedZoneSkipped = %v, want empty", plan.ManagedZoneSkipped)
	}
}

func TestPlanPurgeRevokedZones_SingleZoneAddsSubtree(t *testing.T) {
	state, _ := buildTestNetworkState(t)
	now := time.Unix(123, 0)
	state.Network.Zones["leaf.node-b.catofes."] = zone.NewZoneState("leaf.node-b.catofes.", nil)
	addRevocationTombstoneForTest(t, state, "node-b.catofes.", "catofes.")

	plan, err := planPurgeRevokedZones(state, now, "node-b.catofes.")
	if err != nil {
		t.Fatalf("planPurgeRevokedZones(node-b): %v", err)
	}
	if !equalZonePaths(plan.Zones, []zone.ZonePath{"leaf.node-b.catofes.", "node-b.catofes."}) {
		t.Errorf("Zones = %v, want node-b + leaf", plan.Zones)
	}
}

func TestPlanPurgeRevokedZones_SingleZoneRejectsNonRevoked(t *testing.T) {
	state, _ := buildTestNetworkState(t)
	now := time.Unix(123, 0)
	// catofes. exists and is not revoked.
	if _, err := planPurgeRevokedZones(state, now, "catofes."); err == nil {
		t.Fatalf("expected error for non-revoked zone, got nil")
	}
}

func TestPlanPurgeRevokedZones_RefusesLocalIdentity(t *testing.T) {
	state, _ := buildTestNetworkState(t)
	now := time.Unix(123, 0)
	// ManagedZone is node-a.catofes. Make it appear revoked and confirm the
	// guard still refuses to plan its own deletion.
	addRevocationTombstoneForTest(t, state, "node-a.catofes.", "catofes.")
	state.Network.Zones["node-a.catofes."] = zone.NewZoneState("node-a.catofes.", nil)

	if _, err := planPurgeRevokedZones(state, now, "node-a.catofes."); err == nil {
		t.Fatalf("expected error purging managed zone, got nil")
	}
	// "all" mode must skip the managed zone rather than fail outright.
	plan, err := planPurgeRevokedZones(state, now, "")
	if err != nil {
		t.Fatalf("planPurgeRevokedZones(all): %v", err)
	}
	if !zonePathContains(plan.ManagedZoneSkipped, "node-a.catofes.") {
		t.Errorf("ManagedZoneSkipped = %v, want node-a.catofes.", plan.ManagedZoneSkipped)
	}
	if zonePathContains(plan.Zones, "node-a.catofes.") {
		t.Errorf("managed zone must never appear in Zones to delete: %v", plan.Zones)
	}
}

func TestPlanPurgeRevokedZones_AllowsRevokedChildOfManagedZone(t *testing.T) {
	state, _ := buildTestNetworkState(t)
	now := time.Unix(123, 0)
	state.ManagedZone = "catofes."
	addRevocationTombstoneForTest(t, state, "node-b.catofes.", "catofes.")

	plan, err := planPurgeRevokedZones(state, now, "")
	if err != nil {
		t.Fatalf("planPurgeRevokedZones(all): %v", err)
	}
	if !equalZonePaths(plan.Zones, []zone.ZonePath{"node-b.catofes."}) {
		t.Errorf("Zones = %v, want revoked child of managed zone", plan.Zones)
	}
	if len(plan.ManagedZoneSkipped) != 0 {
		t.Errorf("ManagedZoneSkipped = %v, want empty", plan.ManagedZoneSkipped)
	}
}

func TestExecutePurgePlan_DeletesAndPreservesTombstone(t *testing.T) {
	state, _ := buildTestNetworkState(t)
	now := time.Unix(123, 0)
	state.Network.Zones["leaf.node-b.catofes."] = zone.NewZoneState("leaf.node-b.catofes.", nil)
	addRevocationTombstoneForTest(t, state, "node-b.catofes.", "catofes.")
	state.LinkInstances = map[string]linkInstanceState{
		"link-b":     {ID: "link-b", PeerZone: "node-b.catofes."},
		"link-other": {ID: "link-other", PeerZone: "node-c.catofes."},
	}
	state.SyncPeers = map[string]syncPeerState{
		"node-b.catofes.": {},
		"node-c.catofes.": {},
	}

	plan, err := planPurgeRevokedZones(state, now, "")
	if err != nil {
		t.Fatalf("planPurgeRevokedZones: %v", err)
	}
	executePurgePlan(state, plan)

	for _, z := range []zone.ZonePath{"node-b.catofes.", "leaf.node-b.catofes."} {
		if state.Network.Zones[z] != nil {
			t.Errorf("zone %s still present after purge", z)
		}
	}
	if state.Network.Zones["catofes."] == nil || state.Network.Zones[zone.RootZone] == nil {
		t.Errorf("non-revoked zones must remain")
	}
	// Parent tombstone is preserved (epoch-bump invariant).
	if state.Network.Zones["catofes."].Revocations["node-b.catofes."] == nil {
		t.Errorf("parent revocation tombstone must be preserved")
	}
	if _, ok := state.LinkInstances["link-b"]; ok {
		t.Errorf("revoked link instance must be removed")
	}
	if _, ok := state.LinkInstances["link-other"]; !ok {
		t.Errorf("unrelated link instance must remain")
	}
	if _, ok := state.SyncPeers["node-b.catofes."]; ok {
		t.Errorf("revoked sync peer must be removed")
	}
	if _, ok := state.SyncPeers["node-c.catofes."]; !ok {
		t.Errorf("unrelated sync peer must remain")
	}
}

func TestExecutePurgePlan_PersistedDeletionDoesNotReloadZone(t *testing.T) {
	state, _ := buildTestNetworkState(t)
	now := time.Unix(123, 0)
	addRevocationTombstoneForTest(t, state, "node-b.catofes.", "catofes.")

	path := filepath.Join(t.TempDir(), "higgs.db")
	rt := &Runtime{Config: defaultAppConfig(), StatePath: path, Clock: func() time.Time { return now }}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState(initial): %v", err)
	}
	plan, err := planPurgeRevokedZones(state, now, "")
	if err != nil {
		t.Fatalf("planPurgeRevokedZones: %v", err)
	}
	executePurgePlan(state, plan)
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState(purged): %v", err)
	}

	got, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if got.Network.Zones["node-b.catofes."] != nil {
		t.Fatalf("purged zone reloaded from stale bucket")
	}
	if got.Network.Zones["catofes."].Revocations["node-b.catofes."] == nil {
		t.Fatalf("parent revocation tombstone was not preserved")
	}
}

func TestExecutePurgePlan_DryRunLeavesStateUntouched(t *testing.T) {
	state, _ := buildTestNetworkState(t)
	now := time.Unix(123, 0)
	addRevocationTombstoneForTest(t, state, "node-b.catofes.", "catofes.")

	plan, err := planPurgeRevokedZones(state, now, "")
	if err != nil {
		t.Fatalf("planPurgeRevokedZones: %v", err)
	}
	// Intentionally do NOT call executePurgePlan: dry-run must not mutate.
	if len(plan.Zones) == 0 {
		t.Fatalf("expected non-empty plan")
	}
	if state.Network.Zones["node-b.catofes."] == nil {
		t.Errorf("dry-run must not delete zone data")
	}
}

func equalZonePaths(got, want []zone.ZonePath) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func equalStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func zonePathContains(haystack []zone.ZonePath, needle zone.ZonePath) bool {
	return slices.Contains(haystack, needle)
}
