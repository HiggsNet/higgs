package main

import (
	"path/filepath"
	"testing"
	"time"

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
