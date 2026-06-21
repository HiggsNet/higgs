package main

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/Catofes/higgs/pkg/core/gossip"
	"github.com/Catofes/higgs/pkg/core/zone"
	"github.com/Catofes/higgs/pkg/transport/ipsec"
)

func TestPublishIPsecRecordsSignsStableLocalCapability(t *testing.T) {
	state, config := buildTestNetworkState(t)
	state.ManagedZone = "node-b.catofes."
	config.PeerID = string(state.ManagedZone)
	now := time.Unix(5000, 0)
	appConfig := defaultAppConfig()
	appConfig.ListenAddr = "198.51.100.10:4500"
	appConfig.AdvertiseAddrs = []string{"198.51.100.10:4500"}
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{testIPsecLinkGroup()}
	rt := &Runtime{
		Config:    appConfig,
		StatePath: filepath.Join(t.TempDir(), "higgs.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	sr := newSyncRuntime(state, config, nil, rt)

	if err := sr.publishIPsecRecords(); err != nil {
		t.Fatalf("publishIPsecRecords: %v", err)
	}
	zs := state.Network.Zones[state.ManagedZone]
	for _, key := range []string{ipsec.RecordKeyProfile, ipsec.RecordKeyAddresses, ipsec.RecordKeyPorts, ipsec.RecordKeyTransportKey} {
		if zs.Records[key] == nil {
			t.Fatalf("%s record missing", key)
		}
		if zs.Records[key].Version != 1 {
			t.Fatalf("%s version = %d, want 1", key, zs.Records[key].Version)
		}
	}
	if state.IPsecTransportKey == nil || len(state.IPsecTransportKey.PrivateKey) == 0 {
		t.Fatalf("transport key state = %+v, want persisted private key", state.IPsecTransportKey)
	}
	profile, err := ipsec.ParseProfileRecord(zs.Records[ipsec.RecordKeyProfile])
	if err != nil {
		t.Fatalf("ParseProfileRecord: %v", err)
	}
	key, err := ipsec.ParseTransportKeyRecord(zs.Records[ipsec.RecordKeyTransportKey])
	if err != nil {
		t.Fatalf("ParseTransportKeyRecord: %v", err)
	}
	if profile.TransportKeyFingerprint != key.Fingerprint {
		t.Fatalf("profile fingerprint = %q, key fingerprint = %q", profile.TransportKeyFingerprint, key.Fingerprint)
	}
	addresses, err := ipsec.ParseAddressRecord(zs.Records[ipsec.RecordKeyAddresses])
	if err != nil {
		t.Fatalf("ParseAddressRecord: %v", err)
	}
	if len(addresses.Addresses) != 1 || addresses.Addresses[0].Address != "198.51.100.10" {
		t.Fatalf("addresses = %+v, want advertised IP", addresses.Addresses)
	}
	ports, err := ipsec.ParsePortRecord(zs.Records[ipsec.RecordKeyPorts])
	if err != nil {
		t.Fatalf("ParsePortRecord: %v", err)
	}
	if ports.Current == nil || ports.Current.NATT.Advertised != 4500 {
		t.Fatalf("ports = %+v, want natt 4500", ports)
	}

	latest, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if latest.IPsecTransportKey == nil || len(latest.IPsecTransportKey.PrivateKey) == 0 {
		t.Fatalf("loaded transport key state = %+v, want persisted private key", latest.IPsecTransportKey)
	}
	rt.Clock = func() time.Time { return now.Add(time.Hour) }
	sr.State = latest
	if err := sr.publishIPsecRecords(); err != nil {
		t.Fatalf("publishIPsecRecords(second): %v", err)
	}
	again := latest.Network.Zones[latest.ManagedZone].Records[ipsec.RecordKeyProfile]
	if again.Version != 1 {
		t.Fatalf("second profile version = %d, want unchanged 1", again.Version)
	}
}

func TestPublishIPsecRecordsRotatesPortGenerationByInterval(t *testing.T) {
	state, config := buildTestNetworkState(t)
	state.ManagedZone = "node-b.catofes."
	config.PeerID = string(state.ManagedZone)
	now := time.Unix(5000, 0)
	appConfig := defaultAppConfig()
	appConfig.ListenAddr = "198.51.100.10:4500"
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{testIPsecLinkGroup()}
	appConfig.IPsec.PortMode = ipsec.PortModeRange
	appConfig.IPsec.PortRange = ipsec.PortRange{From: 30000, To: 30099}
	appConfig.IPsec.PortRotateInterval = time.Hour
	rt := &Runtime{
		Config:    appConfig,
		StatePath: filepath.Join(t.TempDir(), "higgs.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	sr := newSyncRuntime(state, config, nil, rt)
	if err := sr.publishIPsecRecords(); err != nil {
		t.Fatalf("publishIPsecRecords: %v", err)
	}
	first, err := ipsec.ParsePortRecord(state.Network.Zones[state.ManagedZone].Records[ipsec.RecordKeyPorts])
	if err != nil {
		t.Fatalf("ParsePortRecord: %v", err)
	}
	if first.Current.Generation != 1 {
		t.Fatalf("first generation = %d, want 1", first.Current.Generation)
	}
	if state.IPsecPortRecord == nil || state.IPsecPortRecord.Generation != 1 {
		t.Fatalf("port state not persisted")
	}

	latest, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	rt.Clock = func() time.Time { return now.Add(30 * time.Minute) }
	sr.State = latest
	if err := sr.publishIPsecRecords(); err != nil {
		t.Fatalf("publishIPsecRecords(second): %v", err)
	}
	second, err := ipsec.ParsePortRecord(latest.Network.Zones[latest.ManagedZone].Records[ipsec.RecordKeyPorts])
	if err != nil {
		t.Fatalf("ParsePortRecord(second): %v", err)
	}
	if second.Current.Generation != 1 {
		t.Fatalf("generation advanced within interval = %d", second.Current.Generation)
	}

	rt.Clock = func() time.Time { return now.Add(2 * time.Hour) }
	if err := sr.publishIPsecRecords(); err != nil {
		t.Fatalf("publishIPsecRecords(third): %v", err)
	}
	third, err := ipsec.ParsePortRecord(latest.Network.Zones[latest.ManagedZone].Records[ipsec.RecordKeyPorts])
	if err != nil {
		t.Fatalf("ParsePortRecord(third): %v", err)
	}
	if third.Current.Generation != 2 {
		t.Fatalf("generation = %d, want 2", third.Current.Generation)
	}
	if len(third.Previous) == 0 || third.Previous[0].Generation != 1 {
		t.Fatalf("previous grace missing: %+v", third.Previous)
	}
}

func TestPublishIPsecRecordsSkipsWithoutLinkGroups(t *testing.T) {
	state, config := buildTestNetworkState(t)
	state.ManagedZone = "node-b.catofes."
	config.PeerID = string(state.ManagedZone)
	rt := &Runtime{
		Config:    defaultAppConfig(),
		StatePath: filepath.Join(t.TempDir(), "higgs.db"),
		Clock:     func() time.Time { return time.Unix(5100, 0) },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	sr := newSyncRuntime(state, config, nil, rt)

	if err := sr.publishIPsecRecords(); err != nil {
		t.Fatalf("publishIPsecRecords: %v", err)
	}
	zs := state.Network.Zones[state.ManagedZone]
	if zs == nil {
		t.Fatalf("zone %s missing", state.ManagedZone)
	}
	if zs.Records[ipsec.RecordKeyProfile] != nil {
		t.Fatalf("ipsec records unexpectedly published: %+v", zs.Records[ipsec.RecordKeyProfile])
	}
}

func TestLocalIPsecAddressRecordAnnounceAddrs(t *testing.T) {
	config := defaultAppConfig()
	config.IPsec.AnnounceAddrs = []string{"203.0.113.5:4500", "[2001:db8::5]:4500"}
	config.ListenAddr = "0.0.0.0:4500"

	record := localIPsecAddressRecord(config, nil, time.Now())
	if len(record.Addresses) != 2 {
		t.Fatalf("got %d addresses, want 2: %+v", len(record.Addresses), record.Addresses)
	}
	for i, addr := range record.Addresses {
		if addr.Source != ipsec.SourceManualAddress {
			t.Fatalf("address %d source = %q, want manual-address", i, addr.Source)
		}
	}
	if record.Addresses[0].Address != "203.0.113.5" {
		t.Fatalf("first address = %q, want 203.0.113.5", record.Addresses[0].Address)
	}
	if record.Addresses[1].Address != "2001:db8::5" {
		t.Fatalf("second address = %q, want 2001:db8::5", record.Addresses[1].Address)
	}
}

func TestLocalIPsecAddressRecordAnnounceDNS(t *testing.T) {
	config := defaultAppConfig()
	config.IPsec.AnnounceDNS = []string{"vpn.example.com"}
	config.ListenAddr = "0.0.0.0:4500"

	record := localIPsecAddressRecord(config, nil, time.Now())
	if len(record.Addresses) != 1 {
		t.Fatalf("got %d addresses, want 1: %+v", len(record.Addresses), record.Addresses)
	}
	ad := record.Addresses[0]
	if ad.Source != ipsec.SourceManualDNS {
		t.Fatalf("source = %q, want manual-dns", ad.Source)
	}
	if ad.Host != "vpn.example.com" {
		t.Fatalf("host = %q, want vpn.example.com", ad.Host)
	}
	if len(ad.Families) != 2 || ad.Families[0] != ipsec.FamilyIPv4 || ad.Families[1] != ipsec.FamilyIPv6 {
		t.Fatalf("families = %v, want [ipv4 ipv6]", ad.Families)
	}
}

func TestLocalIPsecAddressRecordFollowsGossipEndpoints(t *testing.T) {
	state, _ := buildTestNetworkState(t)
	state.ManagedZone = "node-b.catofes."
	now := time.Unix(5000, 0)

	er := gossip.EndpointRecord{
		Endpoints: []gossip.EndpointEntry{
			{Address: "203.0.113.10", Port: 33434, Source: "advertise", Scope: "advertise", Priority: 100, LastObserved: now.Unix()},
			{Address: "198.51.100.20", Port: 33434, Source: "reflector", Scope: "global", Priority: 50, LastObserved: now.Unix()},
			{Address: "10.0.0.5", Port: 33434, Source: "interface", Scope: "site", Priority: 10, LastObserved: now.Unix()},
			{Address: "203.0.113.50", Port: 33434, Source: "interface", Scope: "global", Priority: 20, LastObserved: now.Unix()},
		},
		TTL:       int64(time.Hour / time.Second),
		UpdatedAt: now.Unix(),
	}
	data, _ := json.Marshal(er)
	state.Network.Zones[state.ManagedZone].Records[gossip.EndpointRecordKeyUDP] = &zone.Record{
		Zone:      state.ManagedZone,
		Key:       gossip.EndpointRecordKeyUDP,
		Type:      "sync.endpoint",
		Value:     data,
		Timestamp: now.Unix(),
	}

	config := defaultAppConfig()
	config.ListenAddr = "0.0.0.0:33434"
	// PublishFromEndpoints defaults to true.

	record := localIPsecAddressRecord(config, state, now)
	if len(record.Addresses) != 4 {
		t.Fatalf("got %d addresses, want 4: %+v", len(record.Addresses), record.Addresses)
	}

	byID := make(map[string]ipsec.AddressAdvertisement)
	for _, ad := range record.Addresses {
		byID[ad.ID] = ad
	}

	if ad, ok := byID["endpoint-1"]; !ok || ad.Source != ipsec.SourceManualAddress || ad.Address != "203.0.113.10" {
		t.Fatalf("advertise endpoint mapping unexpected: %+v", byID["endpoint-1"])
	}
	if ad, ok := byID["endpoint-2"]; !ok || ad.Source != ipsec.SourceReflector || ad.Address != "198.51.100.20" {
		t.Fatalf("reflector endpoint mapping unexpected: %+v", byID["endpoint-2"])
	}
	if ad, ok := byID["endpoint-3"]; !ok || ad.Source != ipsec.SourceLocal || ad.Address != "10.0.0.5" || ad.Reachability != ipsec.ReachabilityPrivate {
		t.Fatalf("private interface mapping unexpected: %+v", byID["endpoint-3"])
	}
	if ad, ok := byID["endpoint-4"]; !ok || ad.Source != ipsec.SourceDiscovery || ad.Address != "203.0.113.50" || ad.Reachability != ipsec.ReachabilityPublic {
		t.Fatalf("public interface mapping unexpected: %+v", byID["endpoint-4"])
	}
}

func TestLocalIPsecAddressRecordDedupsManualAndEndpoint(t *testing.T) {
	state, _ := buildTestNetworkState(t)
	state.ManagedZone = "node-b.catofes."
	now := time.Unix(5000, 0)

	config := defaultAppConfig()
	config.AdvertiseAddrs = []string{"203.0.113.10:33434"}
	config.IPsec.AnnounceAddrs = []string{"203.0.113.10:4500"}
	config.ListenAddr = "0.0.0.0:33434"

	er := gossip.EndpointRecord{
		Endpoints: []gossip.EndpointEntry{
			{Address: "203.0.113.10", Port: 33434, Source: "advertise", Scope: "advertise", Priority: 100, LastObserved: now.Unix()},
			{Address: "198.51.100.20", Port: 33434, Source: "reflector", Scope: "global", Priority: 50, LastObserved: now.Unix()},
		},
		TTL:       int64(time.Hour / time.Second),
		UpdatedAt: now.Unix(),
	}
	data, _ := json.Marshal(er)
	state.Network.Zones[state.ManagedZone].Records[gossip.EndpointRecordKeyUDP] = &zone.Record{
		Zone:      state.ManagedZone,
		Key:       gossip.EndpointRecordKeyUDP,
		Type:      "sync.endpoint",
		Value:     data,
		Timestamp: now.Unix(),
	}

	record := localIPsecAddressRecord(config, state, now)
	if len(record.Addresses) != 2 {
		t.Fatalf("got %d addresses, want 2: %+v", len(record.Addresses), record.Addresses)
	}
	if record.Addresses[0].Address != "203.0.113.10" || record.Addresses[0].Source != ipsec.SourceManualAddress {
		t.Fatalf("first address unexpected: %+v", record.Addresses[0])
	}
	if record.Addresses[1].Address != "198.51.100.20" || record.Addresses[1].Source != ipsec.SourceReflector {
		t.Fatalf("second address unexpected: %+v", record.Addresses[1])
	}
}

func TestLocalIPsecAddressRecordPublishFromEndpointsDisabled(t *testing.T) {
	state, _ := buildTestNetworkState(t)
	state.ManagedZone = "node-b.catofes."
	now := time.Unix(5000, 0)

	er := gossip.EndpointRecord{
		Endpoints: []gossip.EndpointEntry{
			{Address: "203.0.113.10", Port: 33434, Source: "reflector", Scope: "global", Priority: 50, LastObserved: now.Unix()},
		},
		TTL:       int64(time.Hour / time.Second),
		UpdatedAt: now.Unix(),
	}
	data, _ := json.Marshal(er)
	state.Network.Zones[state.ManagedZone].Records[gossip.EndpointRecordKeyUDP] = &zone.Record{
		Zone:      state.ManagedZone,
		Key:       gossip.EndpointRecordKeyUDP,
		Type:      "sync.endpoint",
		Value:     data,
		Timestamp: now.Unix(),
	}

	config := defaultAppConfig()
	config.IPsec.PublishFromEndpoints = false
	config.ListenAddr = "198.51.100.10:33434"

	record := localIPsecAddressRecord(config, state, now)
	if len(record.Addresses) != 1 || record.Addresses[0].Address != "198.51.100.10" {
		t.Fatalf("expected only listen fallback, got: %+v", record.Addresses)
	}
}
