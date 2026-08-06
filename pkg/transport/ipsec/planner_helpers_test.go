package ipsec

import (
	"github.com/Catofes/photon/pkg/core/zone"
	"testing"
	"time"
)

func setIPsecNATProfile(t *testing.T, ns *zone.NetworkState, peer zone.ZonePath, accept string, nat NATProfile, now time.Time) {
	t.Helper()
	zs := ns.Zones[peer]
	fingerprint := "fp-" + string(peer)
	zs.Records[RecordKeyProfile] = record(t, peer, RecordKeyProfile, RecordTypeProfile, ProfileRecord{
		Version:                 1,
		Enabled:                 true,
		Provider:                ProviderStrongSwan,
		IKEIdentity:             string(peer),
		TransportKeyFingerprint: fingerprint,
		Role:                    accept,
		AddressFamilies:         []string{FamilyIPv4, FamilyIPv6},
		PathModes:               []string{PathModeFamilyRedundant, PathModeExhaustive},
		NAT:                     nat,
		UpdatedAt:               now.Unix(),
	})
}

func addIPsecNode(t *testing.T, ns *zone.NetworkState, peer zone.ZonePath, accept string, addresses []AddressAdvertisement, now time.Time) {
	t.Helper()
	zs := zone.NewZoneState(peer, nil)
	fingerprint := "fp-" + string(peer)
	zs.Records[RecordKeyProfile] = record(t, peer, RecordKeyProfile, RecordTypeProfile, ProfileRecord{
		Version:                 1,
		Enabled:                 true,
		Provider:                ProviderStrongSwan,
		IKEIdentity:             string(peer),
		TransportKeyFingerprint: fingerprint,
		Role:                    accept,
		AddressFamilies:         []string{FamilyIPv4, FamilyIPv6},
		PathModes:               []string{PathModeFamilyRedundant, PathModeExhaustive},
		UpdatedAt:               now.Unix(),
	})
	zs.Records[RecordKeyAddresses] = record(t, peer, RecordKeyAddresses, RecordTypeAddresses, AddressRecord{
		Version:   1,
		Addresses: addresses,
		UpdatedAt: now.Unix(),
	})
	zs.Records[RecordKeyPorts] = record(t, peer, RecordKeyPorts, RecordTypePorts, PortRecord{
		Version: 1,
		Mode:    PortModeFixed,
		Current: &PortSelection{
			Generation: 1,
			IKE:        PortBinding{Advertised: DefaultIKEPort},
			NATT:       PortBinding{Advertised: DefaultNATTPort},
			ValidUntil: now.Add(time.Hour).Unix(),
		},
		UpdatedAt: now.Unix(),
	})
	zs.Records[RecordKeyTransportKey] = record(t, peer, RecordKeyTransportKey, RecordTypeTransportKey, TransportKeyRecord{
		Version:     1,
		Kind:        TransportKeyRawPublicKey,
		Algorithm:   AlgorithmEd25519,
		PublicKey:   "base64",
		Fingerprint: fingerprint,
		UpdatedAt:   now.Unix(),
	})
	zs.Records[OverlayIntentRecordKey("ipsec-main")] = record(t, peer, OverlayIntentRecordKey("ipsec-main"), RecordTypeOverlayIntent, OverlayIntentRecord{
		Version:       1,
		OverlayID:     "ipsec-main",
		Provider:      ProviderStrongSwan,
		PathKeys:      []string{"family:ipv4", "family:ipv6", DefaultPathKey},
		TunnelAddress: TunnelAddressSpec{Mode: TunnelAddressDerivedLinkLocal, Family: FamilyIPv6},
		UpdatedAt:     now.Unix(),
	})
	ns.Zones[peer] = zs
}

func setOverlayIntentTunnelAddress(t *testing.T, ns *zone.NetworkState, peer zone.ZonePath, tunnel TunnelAddressSpec, now time.Time) {
	t.Helper()
	zs := ns.Zones[peer]
	if zs == nil {
		t.Fatalf("zone %s not found", peer)
	}
	zs.Records[OverlayIntentRecordKey("ipsec-main")] = record(t, peer, OverlayIntentRecordKey("ipsec-main"), RecordTypeOverlayIntent, OverlayIntentRecord{
		Version:       1,
		OverlayID:     "ipsec-main",
		Provider:      ProviderStrongSwan,
		PathKeys:      []string{"family:ipv4", "family:ipv6", DefaultPathKey},
		TunnelAddress: tunnel,
		UpdatedAt:     now.Unix(),
	})
}

func hasSkip(skips []PlanSkip, peer zone.ZonePath, reason string) bool {
	for _, skip := range skips {
		if skip.Peer == peer && skip.Reason == reason {
			return true
		}
	}
	return false
}

func desiredSpecForPeer(t *testing.T, plan LinkPlan, peer zone.ZonePath) TransportLinkSpec {
	t.Helper()
	for _, spec := range plan.Desired {
		if spec.PeerZone == peer {
			return spec
		}
	}
	t.Fatalf("desired spec for peer %s not found: %+v", peer, plan.Desired)
	return TransportLinkSpec{}
}

func firstAction(result ReconcileResult, action string) *ReconcileAction {
	for i := range result.Actions {
		if result.Actions[i].Action == action {
			return &result.Actions[i]
		}
	}
	return nil
}
