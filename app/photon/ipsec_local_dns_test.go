package main

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

type localDNSResolver map[string][]net.IPAddr

func (r localDNSResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	return append([]net.IPAddr(nil), r[host]...), nil
}

func TestLocalAnnounceDNSForceUpdatesStaleInitiatorSA(t *testing.T) {
	spec := ipsec.TransportLinkSpec{
		LocalZone: "node-a.", PeerZone: "node-b.", OverlayID: "main",
		Provider: ipsec.ProviderStrongSwan, TransportID: "link-a",
		XFRMIfID: 42, InitiatorRole: ipsec.InitiatorRolePrimary,
	}
	instance := ipsec.NewLinkInstance(spec, ipsec.LinkStateUp, time.Unix(1000, 0))
	config := ipsecConfig{
		AnnounceDNS:               []string{"vpn.example.com"},
		AnnounceDNSReconnectAfter: 5 * time.Minute,
	}
	resolver := localDNSResolver{"vpn.example.com": {{IP: net.ParseIP("198.51.100.20")}}}
	sa := ipsec.SAState{
		Name: "link-a", XFRMIfID: 42, Established: true,
		Initiator: true, InitiatorKnown: true, LocalEndpoint: "198.51.100.10:4500",
		InboundPackets: 8, InboundIdleSecs: 301, InboundKnown: true,
	}

	updates, err := localAnnounceDNSForceUpdates(context.Background(), config, []ipsec.TransportLinkSpec{spec}, map[string]ipsec.LinkInstance{instance.ID: instance}, []ipsec.SAState{sa}, resolver)
	if err != nil {
		t.Fatalf("localAnnounceDNSForceUpdates: %v", err)
	}
	if updates[instance.ID] != "local announce DNS changed after inbound idle" {
		t.Fatalf("updates = %#v, want stale local DNS update", updates)
	}

	sa.InboundIdleSecs = 10
	updates, err = localAnnounceDNSForceUpdates(context.Background(), config, []ipsec.TransportLinkSpec{spec}, map[string]ipsec.LinkInstance{instance.ID: instance}, []ipsec.SAState{sa}, resolver)
	if err != nil || len(updates) != 0 {
		t.Fatalf("active SA updates = %#v, err = %v", updates, err)
	}

	sa.InboundIdleSecs = 301
	sa.LocalEndpoint = "198.51.100.20:4500"
	updates, err = localAnnounceDNSForceUpdates(context.Background(), config, []ipsec.TransportLinkSpec{spec}, map[string]ipsec.LinkInstance{instance.ID: instance}, []ipsec.SAState{sa}, resolver)
	if err != nil || len(updates) != 0 {
		t.Fatalf("current DNS address updates = %#v, err = %v", updates, err)
	}
}

func TestLocalAnnounceDNSForceUpdatesSkipsNATScopeMismatch(t *testing.T) {
	spec := ipsec.TransportLinkSpec{LocalZone: "node-a.", PeerZone: "node-b.", OverlayID: "main", Provider: ipsec.ProviderStrongSwan, TransportID: "link-a", InitiatorRole: ipsec.InitiatorRolePrimary}
	instance := ipsec.NewLinkInstance(spec, ipsec.LinkStateUp, time.Unix(1000, 0))
	sa := ipsec.SAState{Name: "link-a", Established: true, Initiator: true, InitiatorKnown: true, LocalEndpoint: "192.168.1.10:4500", ChildAgeSeconds: 600, InboundKnown: true}
	config := ipsecConfig{AnnounceDNS: []string{"vpn.example.com"}, AnnounceDNSReconnectAfter: 5 * time.Minute}
	resolver := localDNSResolver{"vpn.example.com": {{IP: net.ParseIP("198.51.100.20")}}}

	updates, err := localAnnounceDNSForceUpdates(context.Background(), config, []ipsec.TransportLinkSpec{spec}, map[string]ipsec.LinkInstance{instance.ID: instance}, []ipsec.SAState{sa}, resolver)
	if err != nil || len(updates) != 0 {
		t.Fatalf("NAT scope mismatch updates = %#v, err = %v", updates, err)
	}
}
