package main

import (
	"crypto/ed25519"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Catofes/higgs/pkg/core/zone"
	higgscrypto "github.com/Catofes/higgs/pkg/crypto"
	"github.com/Catofes/higgs/pkg/routing"
)

func TestCreateAndRevokeIPAMPoolDirect(t *testing.T) {
	rt, managed := buildIPAMTestRuntime(t)

	if err := createIPAMPoolWithRuntime(rt, managed, "10.0.0.0/16", "catofes."); err != nil {
		t.Fatalf("createIPAMPool failed: %v", err)
	}

	state, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState after create: %v", err)
	}
	key, err := routing.NormalizeIPAMPoolKey("10.0.0.0/16")
	if err != nil {
		t.Fatalf("NormalizeIPAMPoolKey: %v", err)
	}
	rec := state.Network.Zones[managed].Records[key]
	if rec == nil {
		t.Fatalf("pool record not found at key %s", key)
	}
	if rec.Type != routing.RecordTypeIPAMPool {
		t.Fatalf("record type = %q, want %q", rec.Type, routing.RecordTypeIPAMPool)
	}
	var pool routing.IPAMPoolRecord
	if err := json.Unmarshal(rec.Value, &pool); err != nil {
		t.Fatalf("unmarshal pool: %v", err)
	}
	if !pool.Active {
		t.Fatalf("pool.Active = false, want true")
	}
	if pool.Prefix != "10.0.0.0/16" {
		t.Fatalf("pool.Prefix = %q, want %q", pool.Prefix, "10.0.0.0/16")
	}
	if pool.DelegatedTo != "catofes." {
		t.Fatalf("pool.DelegatedTo = %q, want %q", pool.DelegatedTo, "catofes.")
	}
	if rec.Version != 1 {
		t.Fatalf("record version = %d, want 1", rec.Version)
	}

	if err := revokeIPAMPoolWithRuntime(rt, managed, "10.0.0.0/16"); err != nil {
		t.Fatalf("revokeIPAMPool failed: %v", err)
	}

	state, err = rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState after revoke: %v", err)
	}
	rec = state.Network.Zones[managed].Records[key]
	if rec == nil {
		t.Fatalf("revoke record not found at key %s", key)
	}
	if err := json.Unmarshal(rec.Value, &pool); err != nil {
		t.Fatalf("unmarshal revoke: %v", err)
	}
	if pool.Active {
		t.Fatalf("pool.Active = true, want false")
	}
	if pool.DelegatedTo != "catofes." {
		t.Fatalf("pool.DelegatedTo = %q, want %q after revoke", pool.DelegatedTo, "catofes.")
	}
	if rec.Version != 2 {
		t.Fatalf("record version = %d, want 2", rec.Version)
	}
}

func TestAssignAndRevokeIPAMDirect(t *testing.T) {
	rt, managed := buildIPAMTestRuntime(t)

	if err := assignIPAMWithRuntime(rt, managed, "10.0.1.0/24", "node.pek.catofes.", false); err != nil {
		t.Fatalf("assignIPAM failed: %v", err)
	}

	state, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState after assign: %v", err)
	}
	key, err := routing.NormalizeIPAMAssignmentKey("10.0.1.0/24")
	if err != nil {
		t.Fatalf("NormalizeIPAMAssignmentKey: %v", err)
	}
	rec := state.Network.Zones[managed].Records[key]
	if rec == nil {
		t.Fatalf("assignment record not found at key %s", key)
	}
	if rec.Type != routing.RecordTypeIPAMAssignment {
		t.Fatalf("record type = %q, want %q", rec.Type, routing.RecordTypeIPAMAssignment)
	}
	var assignment routing.IPAMAssignmentRecord
	if err := json.Unmarshal(rec.Value, &assignment); err != nil {
		t.Fatalf("unmarshal assignment: %v", err)
	}
	if !assignment.Active {
		t.Fatalf("assignment.Active = false, want true")
	}
	if assignment.Prefix != "10.0.1.0/24" {
		t.Fatalf("assignment.Prefix = %q, want %q", assignment.Prefix, "10.0.1.0/24")
	}
	if assignment.AssignedTo != "node.pek.catofes." {
		t.Fatalf("assignment.AssignedTo = %q, want %q", assignment.AssignedTo, "node.pek.catofes.")
	}

	if err := revokeIPAMAssignmentWithRuntime(rt, managed, "10.0.1.0/24"); err != nil {
		t.Fatalf("revokeIPAMAssignment failed: %v", err)
	}

	state, err = rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState after revoke: %v", err)
	}
	rec = state.Network.Zones[managed].Records[key]
	if err := json.Unmarshal(rec.Value, &assignment); err != nil {
		t.Fatalf("unmarshal revoke: %v", err)
	}
	if assignment.Active {
		t.Fatalf("assignment.Active = true, want false")
	}
	if assignment.AssignedTo != "node.pek.catofes." {
		t.Fatalf("assignment.AssignedTo = %q, want %q after revoke", assignment.AssignedTo, "node.pek.catofes.")
	}
}

func TestIPAMCanonicalizesPrefix(t *testing.T) {
	rt, managed := buildIPAMTestRuntime(t)

	if err := createIPAMPoolWithRuntime(rt, managed, "10.0.1.1/16", "catofes."); err != nil {
		t.Fatalf("createIPAMPool failed: %v", err)
	}

	state, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	key, err := routing.NormalizeIPAMPoolKey("10.0.1.1/16")
	if err != nil {
		t.Fatalf("NormalizeIPAMPoolKey: %v", err)
	}
	rec := state.Network.Zones[managed].Records[key]
	if rec == nil {
		t.Fatalf("record not found at key %s", key)
	}
	var pool routing.IPAMPoolRecord
	if err := json.Unmarshal(rec.Value, &pool); err != nil {
		t.Fatalf("unmarshal pool: %v", err)
	}
	if pool.Prefix != "10.0.0.0/16" {
		t.Fatalf("pool.Prefix = %q, want %q", pool.Prefix, "10.0.0.0/16")
	}
}

func TestRevokeIPAMPoolWithoutRecordFails(t *testing.T) {
	rt, managed := buildIPAMTestRuntime(t)

	err := revokeIPAMPoolWithRuntime(rt, managed, "10.0.2.0/24")
	if err == nil {
		t.Fatalf("revokeIPAMPool without record succeeded, want error")
	}
	if !strings.Contains(err.Error(), "no active") {
		t.Fatalf("error = %v, want no active", err)
	}
}

func TestRevokeIPAMAssignmentWithoutRecordFails(t *testing.T) {
	rt, managed := buildIPAMTestRuntime(t)

	err := revokeIPAMAssignmentWithRuntime(rt, managed, "10.0.2.0/24")
	if err == nil {
		t.Fatalf("revokeIPAMAssignment without record succeeded, want error")
	}
	if !strings.Contains(err.Error(), "no active") {
		t.Fatalf("error = %v, want no active", err)
	}
}

func TestRevokeAlreadyRevokedPoolFails(t *testing.T) {
	rt, managed := buildIPAMTestRuntime(t)
	if err := createIPAMPoolWithRuntime(rt, managed, "10.0.0.0/16", "catofes."); err != nil {
		t.Fatalf("createIPAMPool failed: %v", err)
	}
	if err := revokeIPAMPoolWithRuntime(rt, managed, "10.0.0.0/16"); err != nil {
		t.Fatalf("first revoke failed: %v", err)
	}
	err := revokeIPAMPoolWithRuntime(rt, managed, "10.0.0.0/16")
	if err == nil {
		t.Fatalf("second revoke succeeded, want error")
	}
	if !strings.Contains(err.Error(), "already revoked") {
		t.Fatalf("error = %v, want already revoked", err)
	}
}

func TestRevokeAlreadyRevokedAssignmentFails(t *testing.T) {
	rt, managed := buildIPAMTestRuntime(t)
	if err := assignIPAMWithRuntime(rt, managed, "10.0.1.0/24", "node.pek.catofes.", false); err != nil {
		t.Fatalf("assignIPAM failed: %v", err)
	}
	if err := revokeIPAMAssignmentWithRuntime(rt, managed, "10.0.1.0/24"); err != nil {
		t.Fatalf("first revoke failed: %v", err)
	}
	err := revokeIPAMAssignmentWithRuntime(rt, managed, "10.0.1.0/24")
	if err == nil {
		t.Fatalf("second revoke succeeded, want error")
	}
	if !strings.Contains(err.Error(), "already revoked") {
		t.Fatalf("error = %v, want already revoked", err)
	}
}

func TestIPAMMissingCapability(t *testing.T) {
	rt, managed := buildIPAMTestRuntimeWithoutIPAMCapability(t)

	err := createIPAMPoolWithRuntime(rt, managed, "10.0.0.0/16", "catofes.")
	if err == nil {
		t.Fatalf("createIPAMPool without capability succeeded, want error")
	}
	if !strings.Contains(err.Error(), "lacks allocate-ip") {
		t.Fatalf("error = %v, want lacks allocate-ip", err)
	}
}

func TestListIPAMAssignments(t *testing.T) {
	rt, managed := buildIPAMTestRuntime(t)

	// Pool covering the assignment is required by BuildAuthorizedRouteSet.
	if err := createIPAMPoolWithRuntime(rt, managed, "10.0.0.0/16", "catofes."); err != nil {
		t.Fatalf("createIPAMPool failed: %v", err)
	}
	if err := assignIPAMWithRuntime(rt, managed, "10.0.1.0/24", "node.pek.catofes.", false); err != nil {
		t.Fatalf("assignIPAM failed: %v", err)
	}

	if err := listIPAMAssignmentsWithRuntime(rt, ""); err != nil {
		t.Fatalf("listIPAMAssignments failed: %v", err)
	}

	if err := listIPAMAssignmentsWithRuntime(rt, "node.pek.catofes."); err != nil {
		t.Fatalf("listIPAMAssignments with filter failed: %v", err)
	}

	err := listIPAMAssignmentsWithRuntime(rt, "other.catofes.")
	if err != nil {
		t.Fatalf("listIPAMAssignments with non-matching filter failed: %v", err)
	}
}

func TestBuildIPAMMineReport(t *testing.T) {
	rt, managed := buildIPAMTestRuntime(t)

	if err := createIPAMPoolWithRuntime(rt, managed, "10.0.0.0/16", managed); err != nil {
		t.Fatalf("createIPAMPool failed: %v", err)
	}
	if err := assignIPAMWithRuntime(rt, managed, "10.0.1.0/24", managed, false); err != nil {
		t.Fatalf("assignIPAM failed: %v", err)
	}
	if err := assignIPAMWithRuntime(rt, managed, "10.0.2.0/24", "node.pek.catofes.", false); err != nil {
		t.Fatalf("assignIPAM other failed: %v", err)
	}

	report, err := buildIPAMMineReport(rt)
	if err != nil {
		t.Fatalf("buildIPAMMineReport failed: %v", err)
	}
	if report.ManagedZone != string(managed) {
		t.Fatalf("ManagedZone = %q, want %q", report.ManagedZone, managed)
	}
	if len(report.Assignments) != 1 {
		t.Fatalf("Assignments len = %d, want 1: %+v", len(report.Assignments), report.Assignments)
	}
	if report.Assignments[0].Prefix != "10.0.1.0/24" || report.Assignments[0].Source != string(managed) {
		t.Fatalf("Assignments[0] = %+v, want local 10.0.1.0/24", report.Assignments[0])
	}
	if len(report.Pools) != 1 {
		t.Fatalf("Pools len = %d, want 1: %+v", len(report.Pools), report.Pools)
	}
	if report.Pools[0].Prefix != "10.0.0.0/16" || report.Pools[0].DelegatedTo != string(managed) {
		t.Fatalf("Pools[0] = %+v, want local pool", report.Pools[0])
	}
	for _, want := range []string{"published_by_managed_zone", "delegated_to_managed_zone", "usable_by_managed_zone"} {
		if !stringSliceContains(report.Pools[0].Relation, want) {
			t.Fatalf("pool relation = %v, want %s", report.Pools[0].Relation, want)
		}
	}
}

func TestSharedAssignmentRoundTrip(t *testing.T) {
	rt, managed := buildIPAMTestRuntime(t)

	if err := assignIPAMWithRuntime(rt, managed, "10.0.1.0/24", "node.pek.catofes.", true); err != nil {
		t.Fatalf("assignIPAM shared failed: %v", err)
	}

	state, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState after assign: %v", err)
	}
	key, err := routing.NormalizeIPAMAssignmentKey("10.0.1.0/24")
	if err != nil {
		t.Fatalf("NormalizeIPAMAssignmentKey: %v", err)
	}
	rec := state.Network.Zones[managed].Records[key]
	if rec == nil {
		t.Fatalf("assignment record not found")
	}
	var assignment routing.IPAMAssignmentRecord
	if err := json.Unmarshal(rec.Value, &assignment); err != nil {
		t.Fatalf("unmarshal assignment: %v", err)
	}
	if !assignment.Shared {
		t.Fatalf("expected Shared=true, got false")
	}

	// Revoke and verify Shared flag is preserved in the revocation record.
	if err := revokeIPAMAssignmentWithRuntime(rt, managed, "10.0.1.0/24"); err != nil {
		t.Fatalf("revokeIPAMAssignment failed: %v", err)
	}

	state, err = rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState after revoke: %v", err)
	}
	rec = state.Network.Zones[managed].Records[key]
	if err := json.Unmarshal(rec.Value, &assignment); err != nil {
		t.Fatalf("unmarshal revoke: %v", err)
	}
	if assignment.Active {
		t.Fatalf("expected Active=false after revoke")
	}
	if !assignment.Shared {
		t.Fatalf("expected Shared=true preserved after revoke")
	}
}

func stringSliceContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func buildIPAMTestRuntime(t *testing.T) (*Runtime, zone.ZonePath) {
	t.Helper()
	return buildIPAMTestRuntimeWithCapability(t, true)
}

func buildIPAMTestRuntimeWithoutIPAMCapability(t *testing.T) (*Runtime, zone.ZonePath) {
	t.Helper()
	return buildIPAMTestRuntimeWithCapability(t, false)
}

func buildIPAMTestRuntimeWithCapability(t *testing.T, ipamCap bool) (*Runtime, zone.ZonePath) {
	t.Helper()
	dir := t.TempDir()
	rootPub, rootPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(root): %v", err)
	}
	catofesPub, catofesPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(catofes): %v", err)
	}
	zonePub, zonePriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(zone): %v", err)
	}

	managed := zone.ZonePath("pek.catofes.")
	parent := zone.ZonePath("catofes.")

	rootAuthority := &zone.ZoneAuthority{
		Zone:      zone.RootZone,
		Epoch:     1,
		Threshold: 1,
		Keys: []zone.AuthorizedKey{{
			Key: rootPub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermDelegate},
			}},
		}},
	}
	catofesAuthority := &zone.ZoneAuthority{
		Zone:      parent,
		Epoch:     1,
		Threshold: 1,
		Keys: []zone.AuthorizedKey{{
			Key: catofesPub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermDelegate},
			}},
		}},
	}

	perms := []zone.Permission{zone.PermWrite}
	if ipamCap {
		perms = append(perms, zone.PermAllocateIP)
	}
	childAuthority := &zone.ZoneAuthority{
		Zone:      managed,
		Epoch:     1,
		Threshold: 1,
		Keys: []zone.AuthorizedKey{{
			Key: zonePub,
			Capabilities: []zone.Capability{{
				Permissions: perms,
			}},
		}},
	}

	catofesDelegation := &zone.Delegation{
		ZoneName:  parent,
		Scope:     zone.DelegationScopeDirectChild,
		Authority: *catofesAuthority,
	}
	if err := higgscrypto.SignDelegation(catofesDelegation, zone.RootZone, rootPriv); err != nil {
		t.Fatalf("SignDelegation(catofes): %v", err)
	}
	pekDelegation := &zone.Delegation{
		ZoneName:  managed,
		Scope:     zone.DelegationScopeDirectChild,
		Authority: *childAuthority,
	}
	if err := higgscrypto.SignDelegation(pekDelegation, parent, catofesPriv); err != nil {
		t.Fatalf("SignDelegation(pek): %v", err)
	}

	ns := zone.NewNetworkState()
	ns.Zones[zone.RootZone] = zone.NewZoneState(zone.RootZone, rootAuthority)
	ns.Zones[parent] = zone.NewZoneState(parent, catofesAuthority)
	ns.Zones[managed] = zone.NewZoneState(managed, childAuthority)
	ns.Zones[zone.RootZone].Delegations[parent] = catofesDelegation
	ns.Zones[parent].Delegations[managed] = pekDelegation
	configureValidation(ns)
	if err := higgscrypto.VerifyChain(ns, managed, time.Unix(1000, 0)); err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}

	state := &stateFile{
		ManagedZone:    managed,
		ZonePrivateKey: zonePriv,
		Network:        ns,
	}

	config := defaultAppConfig()
	config.StatePath = filepath.Join(dir, "higgs.db")
	rt := &Runtime{Config: config, StatePath: config.StatePath, Clock: func() time.Time { return time.Unix(1000, 0) }}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	return rt, managed
}
