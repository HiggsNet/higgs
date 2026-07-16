package service

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/Catofes/higgs/pkg/core/zone"
	"github.com/Catofes/higgs/pkg/routing"
)

func TestParseSOCKS5RecordStrictSchema(t *testing.T) {
	record := &zone.Record{
		Zone:  "node-a.catofes.",
		Key:   "services/egress-cn",
		Type:  RecordTypeSOCKS5,
		Value: []byte(`{"type":"socks5","region":"cn-east","address":"fd42::20","port":1080}`),
	}
	parsed, err := ParseSOCKS5Record(record)
	if err != nil {
		t.Fatalf("ParseSOCKS5Record: %v", err)
	}
	if parsed.Type != TypeSOCKS5 || parsed.Region != "cn-east" || parsed.Address != "fd42::20" || parsed.Port != 1080 {
		t.Fatalf("parsed = %#v", parsed)
	}

	bad := *record
	bad.Value = []byte(`{"type":"socks5","region":"cn-east","address":"fd42::20","port":1080,"allow_zones":["catofes."]}`)
	if _, err := ParseSOCKS5Record(&bad); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("ParseSOCKS5Record local policy error = %v, want unknown field", err)
	}

	bad = *record
	bad.Key = "services/../egress"
	if _, err := ParseSOCKS5Record(&bad); err == nil || !strings.Contains(err.Error(), "service_record_key_mismatch") {
		t.Fatalf("ParseSOCKS5Record bad key error = %v", err)
	}
}

func TestSOCKS5RecordActiveCompatibility(t *testing.T) {
	record := &zone.Record{Zone: "node-a.catofes.", Key: "services/egress", Type: RecordTypeSOCKS5, Value: []byte(`{"type":"socks5","region":"cn","address":"fd42::20","port":3128}`)}
	parsed, err := ParseSOCKS5Record(record)
	if err != nil || !parsed.IsActive() {
		t.Fatalf("legacy record = %#v, error = %v", parsed, err)
	}
	active := false
	parsed.Active = &active
	data, err := json.Marshal(parsed)
	if err != nil {
		t.Fatal(err)
	}
	record.Value = data
	parsed, err = ParseSOCKS5Record(record)
	if err != nil || parsed.IsActive() {
		t.Fatalf("withdrawn record = %#v, error = %v", parsed, err)
	}
}

func TestAuthorizeSOCKS5RecordUsesValidIPAMAssignment(t *testing.T) {
	ns := zone.NewNetworkState()
	ns.Zones[zone.RootZone] = zone.NewZoneState(zone.RootZone, nil)
	ns.Zones["node-a.catofes."] = zone.NewZoneState("node-a.catofes.", nil)
	putJSONRecord(t, ns.Zones[zone.RootZone], routing.RecordKeyPrefixIPAMPools+"fd42::_16", routing.RecordTypeIPAMPool, routing.IPAMPoolRecord{
		Version: 1, Prefix: "fd42::/16", DelegatedTo: zone.RootZone, Active: true,
	})
	putJSONRecord(t, ns.Zones[zone.RootZone], routing.RecordKeyPrefixIPAMAssignments+"fd42:1::_64", routing.RecordTypeIPAMAssignment, routing.IPAMAssignmentRecord{
		Version: 1, Prefix: "fd42:1::/64", AssignedTo: "node-a.catofes.", Active: true,
	})
	authorized, err := routing.BuildAuthorizedRouteSet(ns, time.Unix(1, 0))
	if err != nil {
		t.Fatalf("BuildAuthorizedRouteSet: %v", err)
	}
	record := &zone.Record{
		Zone:  "node-a.catofes.",
		Key:   "services/egress",
		Type:  RecordTypeSOCKS5,
		Value: []byte(`{"type":"socks5","region":"cn-east","address":"fd42:1::20","port":1080}`),
	}
	assignment, err := AuthorizeSOCKS5Record(record, authorized)
	if err != nil {
		t.Fatalf("AuthorizeSOCKS5Record: %v", err)
	}
	if got := assignment.Prefix.String(); got != "fd42:1::/64" {
		t.Fatalf("assignment prefix = %s", got)
	}

	wrongOwner := *record
	wrongOwner.Zone = "node-b.catofes."
	if _, err := AuthorizeSOCKS5Record(&wrongOwner, authorized); err == nil || !strings.Contains(err.Error(), "service_address_unauthorized") {
		t.Fatalf("wrong-owner error = %v", err)
	}

	outside := *record
	outside.Value = []byte(`{"type":"socks5","region":"cn-east","address":"fd42:2::20","port":1080}`)
	if _, err := AuthorizeSOCKS5Record(&outside, authorized); err == nil || !strings.Contains(err.Error(), "service_address_unauthorized") {
		t.Fatalf("outside-prefix error = %v", err)
	}

	sharedOnly := &routing.AuthorizedRouteSet{AllAssignments: []*routing.AssignmentEntry{{
		Prefix: netip.MustParsePrefix("fd42:1::/64"), AssignedTo: record.Zone, Shared: true,
	}}}
	if _, err := AuthorizeSOCKS5Record(record, sharedOnly); err == nil || !strings.Contains(err.Error(), "non-shared") {
		t.Fatalf("shared assignment error = %v", err)
	}
}

func putJSONRecord(t *testing.T, state *zone.ZoneState, key, recordType string, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	state.Records[key] = &zone.Record{Zone: state.Path, Key: key, Type: recordType, Value: data}
}
