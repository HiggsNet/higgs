package main

import (
	"errors"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func TestShouldIgnorePartialReplan(t *testing.T) {
	reconcile := &ipsecReconcileState{
		DesiredLinks: 4,
		Desired:      []desiredLinkState{{InstanceID: "a"}, {InstanceID: "b"}, {InstanceID: "c"}, {InstanceID: "d"}},
	}
	if !shouldIgnorePartialReplan(reconcile, 1, nil) {
		t.Fatal("partial replan was not ignored")
	}
	if shouldIgnorePartialReplan(reconcile, 4, nil) {
		t.Fatal("complete replan was ignored")
	}
	if shouldIgnorePartialReplan(nil, 1, nil) {
		t.Fatal("replan without a last reconcile snapshot was ignored")
	}
	if !shouldIgnorePartialReplan(reconcile, 0, errors.New("planner failed")) {
		t.Fatal("planner error was not ignored")
	}
}

func TestPlannedInspectDesiredLinksResolvesManualDNS(t *testing.T) {
	state, _ := buildTestNetworkState(t)
	now := time.Unix(4000, 0)
	_, key := daemonTestTransportKey(t, now)
	peer := state.Network.Zones["node-b.catofes."]
	peer.Records[ipsec.RecordKeyProfile] = unsignedIPsecRecord(t, "node-b.catofes.", ipsec.RecordKeyProfile, ipsec.RecordTypeProfile, ipsec.ProfileRecord{
		Version:                 1,
		Enabled:                 true,
		Provider:                ipsec.ProviderStrongSwan,
		IKEIdentity:             "node-b.catofes.",
		TransportKeyFingerprint: key.Fingerprint,
		Role:                    ipsec.RoleIn,
		AddressFamilies:         []string{ipsec.FamilyIPv4},
		PathModes:               []string{ipsec.PathModeFamilyRedundant},
		UpdatedAt:               now.Unix(),
	})
	peer.Records[ipsec.RecordKeyAddresses] = unsignedIPsecRecord(t, "node-b.catofes.", ipsec.RecordKeyAddresses, ipsec.RecordTypeAddresses, ipsec.AddressRecord{
		Version: 1,
		Addresses: []ipsec.AddressAdvertisement{{
			ID:           "dns-v4",
			Source:       ipsec.SourceManualDNS,
			Host:         "127.0.0.1",
			Families:     []string{ipsec.FamilyIPv4},
			Reachability: ipsec.ReachabilityPublic,
		}},
		UpdatedAt: now.Unix(),
	})
	peer.Records[ipsec.RecordKeyPorts] = unsignedIPsecRecord(t, "node-b.catofes.", ipsec.RecordKeyPorts, ipsec.RecordTypePorts, ipsec.PortRecord{
		Version: 1,
		Mode:    ipsec.PortModeFixed,
		Current: &ipsec.PortSelection{
			Generation: 1,
			IKE:        ipsec.PortBinding{Advertised: ipsec.DefaultIKEPort},
			NATT:       ipsec.PortBinding{Advertised: ipsec.DefaultNATTPort},
		},
		UpdatedAt: now.Unix(),
	})
	peer.Records[ipsec.RecordKeyTransportKey] = unsignedIPsecRecord(t, "node-b.catofes.", ipsec.RecordKeyTransportKey, ipsec.RecordTypeTransportKey, *key)
	peer.Records[ipsec.OverlayIntentRecordKey("main")] = unsignedIPsecRecord(t, "node-b.catofes.", ipsec.OverlayIntentRecordKey("main"), ipsec.RecordTypeOverlayIntent, ipsec.OverlayIntentRecord{
		Version:       1,
		OverlayID:     "main",
		Provider:      ipsec.ProviderStrongSwan,
		PathKeys:      []string{"family:ipv4"},
		TunnelAddress: ipsec.TunnelAddressSpec{Mode: ipsec.TunnelAddressDerivedLinkLocal, Family: ipsec.FamilyIPv6},
		UpdatedAt:     now.Unix(),
	})
	rt := &Runtime{
		Config: defaultAppConfig(),
		Clock:  func() time.Time { return now },
	}
	rt.Config.IPsec.LinkGroups = []ipsec.LinkGroupSpec{{
		ID:                 "main",
		Provider:           ipsec.ProviderStrongSwan,
		DefaultPathMode:    ipsec.PathModeFamilyRedundant,
		AddressSourceOrder: []string{ipsec.SourceManualDNS},
		ConnectRules:       []string{"strongswan://node-b.catofes.?role=in"},
		TunnelAddressSpec:  ipsec.TunnelAddressSpec{Mode: ipsec.TunnelAddressDerivedLinkLocal, Family: ipsec.FamilyIPv6},
	}}

	planned, specs, err := plannedInspectDesiredLinks(rt, verifiedStateForTest(state), nil, linuxRuntimeStateFromLegacy(state))
	if err != nil {
		t.Fatalf("plannedInspectDesiredLinks: %v", err)
	}
	if len(planned) != 1 || len(specs) != 1 {
		t.Fatalf("planned=%+v specs=%d, want one manual-dns desired link", planned, len(specs))
	}
	if planned[0].Endpoint != "127.0.0.1" {
		t.Fatalf("endpoint = %q, want resolved localhost address", planned[0].Endpoint)
	}
	for _, spec := range specs {
		if len(spec.ContactPoints) != 1 {
			t.Fatalf("contact points = %+v, want one resolved DNS contact", spec.ContactPoints)
		}
		if spec.ContactPoints[0].Address != "127.0.0.1" || spec.ContactPoints[0].NATTPort != ipsec.DefaultNATTPort {
			t.Fatalf("contact point = %+v, want resolved localhost natt endpoint", spec.ContactPoints[0])
		}
	}
}
