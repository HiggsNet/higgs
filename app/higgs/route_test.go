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

func TestAnnounceAndWithdrawRouteDirect(t *testing.T) {
	rt, managed := buildRouteTestRuntime(t)

	if err := announceRouteWithRuntime(rt, managed, "10.0.1.0/24"); err != nil {
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

	if err := withdrawRouteWithRuntime(rt, managed, "10.0.1.0/24"); err != nil {
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

	if err := announceRouteWithRuntime(rt, managed, "10.0.1.1/24"); err != nil {
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

	err := withdrawRouteWithRuntime(rt, managed, "10.0.2.0/24")
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

	if err := announceRouteWithRuntime(rt, managed, prefix); err != nil {
		t.Fatalf("first announce failed: %v", err)
	}
	if err := withdrawRouteWithRuntime(rt, managed, prefix); err != nil {
		t.Fatalf("withdraw failed: %v", err)
	}
	if err := announceRouteWithRuntime(rt, managed, prefix); err != nil {
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

	err := announceRouteWithRuntime(rt, managed, "not-a-prefix")
	if err == nil {
		t.Fatalf("announceRoute with invalid prefix succeeded, want error")
	}
	if !strings.Contains(err.Error(), "invalid prefix") {
		t.Fatalf("error = %v, want invalid prefix", err)
	}
}

func TestAnnounceRouteMissingCapability(t *testing.T) {
	rt, managed := buildRouteTestRuntimeWithoutRouteCapability(t)

	err := announceRouteWithRuntime(rt, managed, "10.0.1.0/24")
	if err == nil {
		t.Fatalf("announceRoute without route capability succeeded, want error")
	}
	if !strings.Contains(err.Error(), "lacks write:route capability") {
		t.Fatalf("error = %v, want lacks write:route capability", err)
	}
}

func TestWithdrawAlreadyWithdrawnFails(t *testing.T) {
	rt, managed := buildRouteTestRuntime(t)
	prefix := "10.0.4.0/24"

	if err := announceRouteWithRuntime(rt, managed, prefix); err != nil {
		t.Fatalf("announce failed: %v", err)
	}
	if err := withdrawRouteWithRuntime(rt, managed, prefix); err != nil {
		t.Fatalf("withdraw failed: %v", err)
	}
	err := withdrawRouteWithRuntime(rt, managed, prefix)
	if err == nil {
		t.Fatalf("second withdraw succeeded, want error")
	}
	if !strings.Contains(err.Error(), "already withdrawn") {
		t.Fatalf("error = %v, want already withdrawn", err)
	}
}

func buildRouteTestRuntime(t *testing.T) (*Runtime, zone.ZonePath) {
	t.Helper()
	return buildRouteTestRuntimeWithCapability(t, true)
}

func buildRouteTestRuntimeWithoutRouteCapability(t *testing.T) (*Runtime, zone.ZonePath) {
	t.Helper()
	return buildRouteTestRuntimeWithCapability(t, false)
}

func buildRouteTestRuntimeWithCapability(t *testing.T, routeCap bool) (*Runtime, zone.ZonePath) {
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
	if routeCap {
		perms = append(perms, zone.PermWriteRoute)
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

