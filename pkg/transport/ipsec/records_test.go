package ipsec

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/Catofes/higgs/pkg/core/zone"
)

func TestParseIPsecRecordsAndBuildContactPoints(t *testing.T) {
	now := time.Unix(1717171717, 0)
	profileRecord := record(t, "node-a.catofes.", RecordKeyProfile, RecordTypeProfile, ProfileRecord{
		Version:                 1,
		Enabled:                 true,
		Provider:                ProviderStrongSwan,
		IKEIdentity:             "node-a.catofes.",
		TransportKeyFingerprint: "b2",
		Accept:                  AcceptInbound,
		AddressFamilies:         []string{FamilyIPv6, FamilyIPv4},
		PathModes:               []string{PathModeFamilyRedundant, PathModeExhaustive},
		UpdatedAt:               now.Unix(),
	})
	profile, err := ParseProfileRecord(profileRecord)
	if err != nil {
		t.Fatalf("ParseProfileRecord: %v", err)
	}
	if profile.IKEIdentity != "node-a.catofes." {
		t.Fatalf("IKEIdentity = %q", profile.IKEIdentity)
	}

	addressRecord := record(t, "node-a.catofes.", RecordKeyAddresses, RecordTypeAddresses, AddressRecord{
		Version: 1,
		Addresses: []AddressAdvertisement{
			{ID: "dns-main", Source: SourceManualDNS, Host: "node-a.example.com", Families: []string{FamilyIPv6, FamilyIPv4}, Priority: 90, TTLSeconds: 300},
			{ID: "manual-v6", Source: SourceManualAddress, Address: "2001:db8::10", Family: FamilyIPv6, Priority: 100, TTLSeconds: 3600},
			{ID: "old", Source: SourceReflector, Address: "203.0.113.10", Family: FamilyIPv4, Priority: 60, LastObserved: now.Add(-time.Hour).Unix(), TTLSeconds: 60},
		},
		UpdatedAt: now.Unix(),
	})
	addresses, err := ParseAddressRecord(addressRecord)
	if err != nil {
		t.Fatalf("ParseAddressRecord: %v", err)
	}
	candidates := AddressCandidates(addresses, now)
	if len(candidates) != 3 {
		t.Fatalf("AddressCandidates len = %d, want 3", len(candidates))
	}
	if candidates[0].ID != "manual-v6" {
		t.Fatalf("first candidate = %s, want manual-v6", candidates[0].ID)
	}

	portRecord := record(t, "node-a.catofes.", RecordKeyPorts, RecordTypePorts, PortRecord{
		Version: 1,
		Mode:    PortModeRange,
		Range:   &PortRange{From: 30000, To: 30999},
		Current: &PortSelection{
			Generation: 42,
			IKE:        PortBinding{Local: 30412, Advertised: 30412, Observed: 30412},
			NATT:       PortBinding{Local: 30413, Advertised: 30413, Observed: 30413},
			ValidUntil: now.Add(time.Hour).Unix(),
		},
		Previous: []PortSelection{{
			Generation: 41,
			IKE:        PortBinding{Advertised: 30100},
			NATT:       PortBinding{Advertised: 30101},
			ValidUntil: now.Add(10 * time.Minute).Unix(),
		}},
		UpdatedAt: now.Unix(),
	})
	ports, err := ParsePortRecord(portRecord)
	if err != nil {
		t.Fatalf("ParsePortRecord: %v", err)
	}
	points := ContactPoints(addresses, ports, now)
	if len(points) != 6 {
		t.Fatalf("ContactPoints len = %d, want 6", len(points))
	}
	selected := SelectContactPoints(points, PathModeFamilyRedundant)
	if len(selected) != 2 {
		t.Fatalf("family redundant len = %d, want 2", len(selected))
	}
	if selected[0].IKEPort != 30412 || !selected[0].Current {
		t.Fatalf("selected current port = %+v", selected[0])
	}
}

func TestTransportKeyAndLinkSpec(t *testing.T) {
	now := time.Unix(1717171717, 0)
	keyRecord := record(t, "node-a.catofes.", RecordKeyTransportKey, RecordTypeTransportKey, TransportKeyRecord{
		Version:     1,
		Kind:        TransportKeyRawPublicKey,
		Algorithm:   AlgorithmEd25519,
		PublicKey:   "base64",
		Fingerprint: "b2",
		NotBefore:   now.Unix(),
		NotAfter:    now.Add(time.Hour).Unix(),
		UpdatedAt:   now.Unix(),
	})
	key, err := ParseTransportKeyRecord(keyRecord)
	if err != nil {
		t.Fatalf("ParseTransportKeyRecord: %v", err)
	}
	records := &NodeRecords{
		Zone: "node-a.catofes.",
		Profile: &ProfileRecord{
			Version:                 1,
			Enabled:                 true,
			Provider:                ProviderStrongSwan,
			IKEIdentity:             "node-a.catofes.",
			TransportKeyFingerprint: "b2",
			Accept:                  AcceptInbound,
			AddressFamilies:         []string{FamilyIPv4},
			PathModes:               []string{PathModeFamilyRedundant},
		},
		TransportKey: key,
	}
	spec, err := NewTransportLinkSpec("node-b.catofes.", "node-a.catofes.", "ipsec-main", "", records, nil)
	if err != nil {
		t.Fatalf("NewTransportLinkSpec: %v", err)
	}
	if spec.Provider != ProviderStrongSwan || spec.AuthRef != "b2" {
		t.Fatalf("spec = %+v", spec)
	}
	if spec.XFRMIfID == 0 {
		t.Fatalf("XFRMIfID is zero")
	}
	if len(spec.InterfaceName) > 15 {
		t.Fatalf("interface name %q exceeds Linux limit", spec.InterfaceName)
	}
	again, err := NewTransportLinkSpec("node-b.catofes.", "node-a.catofes.", "ipsec-main", "", records, nil)
	if err != nil {
		t.Fatalf("NewTransportLinkSpec(second): %v", err)
	}
	if spec.TransportID != again.TransportID || spec.XFRMIfID != again.XFRMIfID || spec.InterfaceName != again.InterfaceName {
		t.Fatalf("stable derivation changed: %+v vs %+v", spec, again)
	}
}

func TestExtractNodeRecordsSkipsRevokedZone(t *testing.T) {
	ns := zone.NewNetworkState()
	ns.Zones["node-a.catofes."] = zone.NewZoneState("node-a.catofes.", nil)
	ns.Zones["catofes."] = zone.NewZoneState("catofes.", nil)
	ns.Zones["catofes."].Revocations["node-a.catofes."] = &zone.DelegationRevocation{
		ChildZone:  "node-a.catofes.",
		ParentZone: "catofes.",
		RevokedAt:  time.Now().Unix(),
	}
	if _, err := ExtractNodeRecords(ns, "node-a.catofes.", time.Now()); err == nil {
		t.Fatalf("ExtractNodeRecords should reject revoked peer")
	}
}

func TestShouldInitiateBidirectionalTieBreak(t *testing.T) {
	if !ShouldInitiate("node-a.catofes.", "node-b.catofes.", DirectionBidirectional, AcceptBidirectional) {
		t.Fatalf("node-a should initiate toward node-b")
	}
	if ShouldInitiate("node-b.catofes.", "node-a.catofes.", DirectionBidirectional, AcceptBidirectional) {
		t.Fatalf("node-b should not initiate toward node-a")
	}
	if ShouldInitiate("node-a.catofes.", "node-b.catofes.", DirectionOutbound, AcceptNone) {
		t.Fatalf("outbound should not initiate toward accept=none")
	}
}

func TestDryRunDriverRecordsApplyOrderInputs(t *testing.T) {
	driver := &DryRunDriver{}
	spec := TransportLinkSpec{TransportID: "ipsec-1", InterfaceName: "hgs1"}
	if err := driver.LoadConnection(context.Background(), spec); err != nil {
		t.Fatalf("LoadConnection: %v", err)
	}
	if err := driver.EnsureInterface(context.Background(), spec); err != nil {
		t.Fatalf("EnsureInterface: %v", err)
	}
	if err := driver.AssignAddress(context.Background(), "hgs1", "fd00::1/64"); err != nil {
		t.Fatalf("AssignAddress: %v", err)
	}
	if len(driver.Connections) != 1 || len(driver.Interfaces) != 1 || len(driver.Addresses) != 1 {
		t.Fatalf("driver = %+v", driver)
	}
}

func record(t *testing.T, owner zone.ZonePath, key, recordType string, value any) *zone.Record {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return &zone.Record{
		Zone:  owner,
		Key:   key,
		Type:  recordType,
		Value: data,
	}
}
