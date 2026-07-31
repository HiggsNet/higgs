package main

import (
	"bytes"
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

func TestAnnounceAndWithdrawRouteDirect(t *testing.T) {
	rt, managed := buildRouteTestRuntime(t)

	if err := mutateRouteWithRuntime(rt, managed, "10.0.1.0/24", true); err != nil {
		t.Fatalf("announceRoute failed: %v", err)
	}

	state, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState after announce: %v", err)
	}
	key, err := routing.NormalizeRouteAnnouncementKey("10.0.1.0/24")
	if err != nil {
		t.Fatalf("NormalizeRouteAnnouncementKey: %v", err)
	}
	rec := state.Network.Zones[managed].Records[key]
	if rec == nil {
		t.Fatalf("announcement record not found at key %s", key)
	}
	if rec.Type != routing.RecordTypeRouteAnnouncement {
		t.Fatalf("record type = %q, want %q", rec.Type, routing.RecordTypeRouteAnnouncement)
	}
	var ann routing.RouteAnnouncementRecord
	if err := json.Unmarshal(rec.Value, &ann); err != nil {
		t.Fatalf("unmarshal announcement: %v", err)
	}
	if !ann.Active {
		t.Fatalf("ann.Active = false, want true")
	}
	if ann.Prefix != "10.0.1.0/24" {
		t.Fatalf("ann.Prefix = %q, want %q", ann.Prefix, "10.0.1.0/24")
	}
	if rec.Version != 1 {
		t.Fatalf("record version = %d, want 1", rec.Version)
	}

	if err := mutateRouteWithRuntime(rt, managed, "10.0.1.0/24", false); err != nil {
		t.Fatalf("withdrawRoute failed: %v", err)
	}

	state, err = rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState after withdraw: %v", err)
	}
	rec = state.Network.Zones[managed].Records[key]
	if rec == nil {
		t.Fatalf("withdrawal record not found at key %s", key)
	}
	if err := json.Unmarshal(rec.Value, &ann); err != nil {
		t.Fatalf("unmarshal withdrawal: %v", err)
	}
	if ann.Active {
		t.Fatalf("ann.Active = true, want false")
	}
	if rec.Version != 2 {
		t.Fatalf("record version = %d, want 2", rec.Version)
	}
}

func TestAnnounceRouteCanonicalizesPrefix(t *testing.T) {
	rt, managed := buildRouteTestRuntime(t)

	if err := mutateRouteWithRuntime(rt, managed, "10.0.1.1/24", true); err != nil {
		t.Fatalf("announceRoute failed: %v", err)
	}

	state, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	key, err := routing.NormalizeRouteAnnouncementKey("10.0.1.1/24")
	if err != nil {
		t.Fatalf("NormalizeRouteAnnouncementKey: %v", err)
	}
	rec := state.Network.Zones[managed].Records[key]
	if rec == nil {
		t.Fatalf("record not found at key %s", key)
	}
	var ann routing.RouteAnnouncementRecord
	if err := json.Unmarshal(rec.Value, &ann); err != nil {
		t.Fatalf("unmarshal announcement: %v", err)
	}
	if ann.Prefix != "10.0.1.0/24" {
		t.Fatalf("ann.Prefix = %q, want %q", ann.Prefix, "10.0.1.0/24")
	}
}

func TestWithdrawWithoutAnnouncementFails(t *testing.T) {
	rt, managed := buildRouteTestRuntime(t)

	err := mutateRouteWithRuntime(rt, managed, "10.0.2.0/24", false)
	if err == nil {
		t.Fatalf("withdrawRoute without announcement succeeded, want error")
	}
	if !strings.Contains(err.Error(), "no active route announcement") {
		t.Fatalf("error = %v, want no active route announcement", err)
	}
}

func TestReannounceAfterWithdraw(t *testing.T) {
	rt, managed := buildRouteTestRuntime(t)
	prefix := "10.0.3.0/24"

	if err := mutateRouteWithRuntime(rt, managed, prefix, true); err != nil {
		t.Fatalf("first announce failed: %v", err)
	}
	if err := mutateRouteWithRuntime(rt, managed, prefix, false); err != nil {
		t.Fatalf("withdraw failed: %v", err)
	}
	if err := mutateRouteWithRuntime(rt, managed, prefix, true); err != nil {
		t.Fatalf("re-announce failed: %v", err)
	}

	state, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	key, err := routing.NormalizeRouteAnnouncementKey(prefix)
	if err != nil {
		t.Fatalf("NormalizeRouteAnnouncementKey: %v", err)
	}
	rec := state.Network.Zones[managed].Records[key]
	if rec == nil {
		t.Fatalf("record not found at key %s", key)
	}
	var ann routing.RouteAnnouncementRecord
	if err := json.Unmarshal(rec.Value, &ann); err != nil {
		t.Fatalf("unmarshal announcement: %v", err)
	}
	if !ann.Active {
		t.Fatalf("ann.Active = false, want true after re-announce")
	}
	if rec.Version != 3 {
		t.Fatalf("record version = %d, want 3", rec.Version)
	}
}

func TestAnnounceRouteInvalidPrefix(t *testing.T) {
	rt, managed := buildRouteTestRuntime(t)

	err := mutateRouteWithRuntime(rt, managed, "not-a-prefix", true)
	if err == nil {
		t.Fatalf("announceRoute with invalid prefix succeeded, want error")
	}
	if !strings.Contains(err.Error(), "invalid prefix") {
		t.Fatalf("error = %v, want invalid prefix", err)
	}
}

func TestAnnounceRouteRequiresWriteCapability(t *testing.T) {
	rt, managed := buildRouteTestRuntimeWithoutWriteCapability(t)

	err := mutateRouteWithRuntime(rt, managed, "10.0.1.0/24", true)
	if err == nil {
		t.Fatalf("announceRoute without write capability succeeded, want error")
	}
	if !strings.Contains(err.Error(), "authorized key lacks capability") {
		t.Fatalf("error = %v, want authorized key lacks capability", err)
	}
}

func TestWithdrawAlreadyWithdrawnFails(t *testing.T) {
	rt, managed := buildRouteTestRuntime(t)
	prefix := "10.0.4.0/24"

	if err := mutateRouteWithRuntime(rt, managed, prefix, true); err != nil {
		t.Fatalf("announce failed: %v", err)
	}
	if err := mutateRouteWithRuntime(rt, managed, prefix, false); err != nil {
		t.Fatalf("withdraw failed: %v", err)
	}
	err := mutateRouteWithRuntime(rt, managed, prefix, false)
	if err == nil {
		t.Fatalf("second withdraw succeeded, want error")
	}
	if !strings.Contains(err.Error(), "already withdrawn") {
		t.Fatalf("error = %v, want already withdrawn", err)
	}
}

func TestBuildRouteShowReportListsActiveAndAllAnnouncements(t *testing.T) {
	rt, managed := buildRouteTestRuntime(t)

	if err := mutateRouteWithRuntime(rt, managed, "10.0.1.0/24", true); err != nil {
		t.Fatalf("announce active route: %v", err)
	}
	if err := mutateRouteWithRuntime(rt, managed, "10.0.2.0/24", true); err != nil {
		t.Fatalf("announce withdrawn route: %v", err)
	}
	if err := mutateRouteWithRuntime(rt, managed, "10.0.2.0/24", false); err != nil {
		t.Fatalf("withdraw route: %v", err)
	}

	report, err := buildRouteShowReport(rt, "", false)
	if err != nil {
		t.Fatalf("buildRouteShowReport active: %v", err)
	}
	if len(report.Announcements) != 1 {
		t.Fatalf("active announcements len = %d, want 1: %+v", len(report.Announcements), report.Announcements)
	}
	if report.Announcements[0].Prefix != "10.0.1.0/24" || !report.Announcements[0].Active {
		t.Fatalf("active announcement = %+v", report.Announcements[0])
	}

	report, err = buildRouteShowReport(rt, managed, true)
	if err != nil {
		t.Fatalf("buildRouteShowReport all: %v", err)
	}
	if len(report.Announcements) != 2 {
		t.Fatalf("all announcements len = %d, want 2: %+v", len(report.Announcements), report.Announcements)
	}
	if report.Announcements[1].Prefix != "10.0.2.0/24" || report.Announcements[1].Active {
		t.Fatalf("withdrawn announcement = %+v", report.Announcements[1])
	}
}

func TestPrintRouteShowReportUsesFilteredVerboseTable(t *testing.T) {
	report := &routeShowReport{
		ManagedZone: "node-a.catofes.",
		Announcements: []routeShowRow{
			{
				Zone: "node-a.catofes.", Prefix: "10.0.1.0/24", Active: true,
				Authorized: true, Controller: "service", Version: 2,
				Key: "routes/announcements/10.0.1.0_24",
			},
			{Zone: "node-b.catofes.", Prefix: "10.0.2.0/24", Active: false},
		},
	}
	var output bytes.Buffer
	if err := printRouteShowReport(&output, report, true, "node-a", true); err != nil {
		t.Fatalf("printRouteShowReport: %v", err)
	}
	for _, want := range []string{
		"announcements: 1/2",
		"PREFIX", "ZONE", "STATE", "AUTHORIZATION", "CONTROLLER", "VERSION", "RECORD",
		"10.0.1.0/24", "node-a.catofes.", "active", "authorized", "service",
		"routes/announcements/10.0.1.0_24",
	} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("output missing %q:\n%s", want, output.String())
		}
	}
	if strings.Contains(output.String(), "node-b.catofes.") {
		t.Fatalf("filter leaked node-b:\n%s", output.String())
	}
}

func buildRouteTestRuntime(t *testing.T) (*Runtime, zone.ZonePath) {
	t.Helper()
	return buildRouteTestRuntimeWithWriteCapability(t, true)
}

func buildRouteTestRuntimeWithoutWriteCapability(t *testing.T) (*Runtime, zone.ZonePath) {
	t.Helper()
	return buildRouteTestRuntimeWithWriteCapability(t, false)
}

func buildRouteTestRuntimeWithWriteCapability(t *testing.T, writeCap bool) (*Runtime, zone.ZonePath) {
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

	perms := []zone.Permission{zone.PermDelegate}
	if writeCap {
		perms = append(perms, zone.PermWrite)
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
	addUnsignedIPAMPoolForTest(ns, zone.RootZone, "10.0.0.0/8", zone.RootZone)
	addUnsignedIPAMPoolForTest(ns, zone.RootZone, "10.0.0.0/16", parent)
	addUnsignedRouteAssignmentForTest(ns, parent, "10.0.0.0/16", managed)
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
	config.DataDir = dir
	config.StatePath = filepath.Join(dir, "higgs.db")
	rt := &Runtime{Config: config, StatePath: config.StatePath, Clock: func() time.Time { return time.Unix(1000, 0) }, DisableControl: true}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	return rt, managed
}

func addUnsignedRouteAssignmentForTest(ns *zone.NetworkState, source zone.ZonePath, prefix string, assignedTo zone.ZonePath) {
	canonical, err := routing.CanonicalizePrefix(prefix)
	if err != nil {
		panic(err)
	}
	key, err := routing.NormalizeIPAMAssignmentKey(prefix)
	if err != nil {
		panic(err)
	}
	value, err := json.Marshal(routing.IPAMAssignmentRecord{
		Version: 1, Prefix: canonical, AssignedTo: assignedTo, Active: true,
	})
	if err != nil {
		panic(err)
	}
	ns.Zones[source].Records[key] = &zone.Record{
		Zone: source, Key: key, Type: routing.RecordTypeIPAMAssignment, Value: value,
	}
}
