package main

import (
	"github.com/Catofes/higgs/pkg/core/gossip"
	"github.com/Catofes/higgs/pkg/core/zone"
	higgscrypto "github.com/Catofes/higgs/pkg/crypto"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestReflectorEndpointPublishSmoke(t *testing.T) {
	state, config := buildTestNetworkState(t)
	state.ManagedZone = "node-b.catofes."
	config.PeerID = "node-b.catofes."
	config.ListenAddr = "127.0.0.1:33434"
	config.EndpointTTL = time.Hour
	config.EndpointGrace = 10 * time.Minute

	reflectorIP := "198.51.100.10"
	oldCollect := collectSyncLocalEndpoints
	collectSyncLocalEndpoints = func(port uint16, advertiseAddrs, reflectors []string, timeout time.Duration, filterPrivateIPv4 bool) ([]gossip.LocalEndpoint, error) {
		return []gossip.LocalEndpoint{{
			IP:       net.ParseIP(reflectorIP),
			Port:     port,
			Scope:    "global",
			Priority: 50,
			Source:   gossip.SourceReflector,
		}}, nil
	}
	defer func() { collectSyncLocalEndpoints = oldCollect }()
	config.Reflectors = []string{"https://reflector.example"}

	dir := t.TempDir()
	rt := &Runtime{
		Config:    defaultAppConfig(),
		StatePath: filepath.Join(dir, "higgs.db"),
		Clock:     func() time.Time { return time.Unix(1000, 0) },
	}
	sr := newSyncRuntime(config, nil, rt)

	if err := sr.publishEndpointRecord(state); err != nil {
		t.Fatalf("publishEndpointRecord(first): %v", err)
	}
	first := endpointRecordFromState(t, state, "node-b.catofes.")
	if len(first.Endpoints) == 0 || first.Endpoints[0].Address != "198.51.100.10" {
		t.Fatalf("first endpoint record = %#v, want reflector ip", first)
	}
	if first.Endpoints[0].Source != "reflector" {
		t.Fatalf("first endpoint source = %q, want reflector", first.Endpoints[0].Source)
	}

	reflectorIP = "198.51.100.20"
	rt.Clock = func() time.Time { return time.Unix(1060, 0) }
	if err := sr.publishEndpointRecord(state); err != nil {
		t.Fatalf("publishEndpointRecord(second): %v", err)
	}
	second := endpointRecordFromState(t, state, "node-b.catofes.")
	if len(second.Endpoints) < 2 {
		t.Fatalf("second endpoints = %#v, want new endpoint plus grace fallback", second.Endpoints)
	}
	if second.Endpoints[0].Address != "198.51.100.20" {
		t.Fatalf("new endpoint = %s, want 198.51.100.20", second.Endpoints[0].Address)
	}
	if second.Endpoints[1].Address != "198.51.100.10" || !strings.Contains(second.Endpoints[1].Source, "grace") {
		t.Fatalf("grace endpoint = %#v, want old reflector endpoint retained", second.Endpoints[1])
	}
}

func TestEndpointPublishRefreshesStableEndpointsAfterInterval(t *testing.T) {
	state, config := buildTestNetworkState(t)
	state.ManagedZone = "node-b.catofes."
	config.PeerID = "node-b.catofes."
	config.ListenAddr = "127.0.0.1:33434"
	config.EndpointTTL = time.Hour
	config.EndpointRefresh = 30 * time.Minute
	config.EndpointGrace = 10 * time.Minute

	oldCollect := collectSyncLocalEndpoints
	collectSyncLocalEndpoints = func(port uint16, advertiseAddrs, reflectors []string, timeout time.Duration, filterPrivateIPv4 bool) ([]gossip.LocalEndpoint, error) {
		return []gossip.LocalEndpoint{{
			IP:       net.ParseIP("198.51.100.10"),
			Port:     port,
			Scope:    "global",
			Priority: 50,
			Source:   gossip.SourceReflector,
		}}, nil
	}
	defer func() { collectSyncLocalEndpoints = oldCollect }()
	config.Reflectors = []string{"https://reflector.example"}

	dir := t.TempDir()
	rt := &Runtime{
		Config:    defaultAppConfig(),
		StatePath: filepath.Join(dir, "higgs.db"),
		Clock:     func() time.Time { return time.Unix(1000, 0) },
	}
	sr := newSyncRuntime(config, nil, rt)

	if err := sr.publishEndpointRecord(state); err != nil {
		t.Fatalf("publishEndpointRecord(first): %v", err)
	}
	first := state.Network.Zones["node-b.catofes."].Records[gossip.EndpointRecordKeyUDP]
	if first == nil {
		t.Fatal("first endpoint record missing")
	}
	if first.Version != 1 {
		t.Fatalf("first version = %d, want 1", first.Version)
	}

	rt.Clock = func() time.Time { return time.Unix(1300, 0) }
	if err := sr.publishEndpointRecord(state); err != nil {
		t.Fatalf("publishEndpointRecord(second): %v", err)
	}
	second := state.Network.Zones["node-b.catofes."].Records[gossip.EndpointRecordKeyUDP]
	if second.Version != first.Version {
		t.Fatalf("second version = %d, want %d (unchanged)", second.Version, first.Version)
	}

	rt.Clock = func() time.Time { return time.Unix(2800, 0) }
	if err := sr.publishEndpointRecord(state); err != nil {
		t.Fatalf("publishEndpointRecord(third): %v", err)
	}
	third := state.Network.Zones["node-b.catofes."].Records[gossip.EndpointRecordKeyUDP]
	if third.Version != first.Version+1 {
		t.Fatalf("third version = %d, want %d (lease refreshed)", third.Version, first.Version+1)
	}
	refreshed := endpointRecordFromState(t, state, "node-b.catofes.")
	if refreshed.UpdatedAt != 2800 {
		t.Fatalf("refreshed updated_at = %d, want 2800", refreshed.UpdatedAt)
	}
}

func TestEndpointPublishDisabledClearsExistingEndpoint(t *testing.T) {
	state, config := buildTestNetworkState(t)
	state.ManagedZone = "node-b.catofes."
	config.PeerID = "node-b.catofes."
	config.DisableEndpointPublish = true
	dir := t.TempDir()
	rt := &Runtime{
		Config:    defaultAppConfig(),
		StatePath: filepath.Join(dir, "higgs.db"),
		Clock:     func() time.Time { return time.Unix(1000, 0) },
	}
	now := time.Unix(900, 0)
	endpoints := []gossip.LocalEndpoint{
		{IP: net.ParseIP("10.16.255.8"), Port: 33435, Scope: "global", Priority: 100, Source: gossip.SourceInterface},
	}
	record := &zone.Record{
		Zone:      "node-b.catofes.",
		Key:       gossip.EndpointRecordKeyUDP,
		Type:      "sync.endpoint",
		Value:     endpointRecordBytes(endpoints, now),
		Version:   1,
		Timestamp: now.Unix(),
	}
	if err := higgscrypto.SignRecord(record, state.ZonePrivateKey); err != nil {
		t.Fatalf("SignRecord(endpoint): %v", err)
	}
	if err := state.Network.PutAt(record, now); err != nil {
		t.Fatalf("PutAt(endpoint): %v", err)
	}
	sr := newSyncRuntime(config, nil, rt)

	if err := sr.publishEndpointRecord(state); err != nil {
		t.Fatalf("publishEndpointRecord(clear): %v", err)
	}
	clearedRecord := state.Network.Zones["node-b.catofes."].Records[gossip.EndpointRecordKeyUDP]
	if clearedRecord.Version != 2 {
		t.Fatalf("cleared endpoint version = %d, want 2", clearedRecord.Version)
	}
	cleared := endpointRecordFromState(t, state, "node-b.catofes.")
	if len(cleared.Endpoints) != 0 {
		t.Fatalf("cleared endpoints = %#v, want empty", cleared.Endpoints)
	}
	if history := state.Network.Zones["node-b.catofes."].RecordHistory[gossip.EndpointRecordKeyUDP]; len(history) != 1 {
		t.Fatalf("endpoint history len = %d, want previous record retained", len(history))
	}

	if err := sr.publishEndpointRecord(state); err != nil {
		t.Fatalf("publishEndpointRecord(clear again): %v", err)
	}
	if got := state.Network.Zones["node-b.catofes."].Records[gossip.EndpointRecordKeyUDP].Version; got != 2 {
		t.Fatalf("endpoint version after second clear = %d, want 2", got)
	}
}

func TestEndpointPublishSkipsRootAdminState(t *testing.T) {
	dir := t.TempDir()
	rt := &Runtime{
		Config:    defaultAppConfig(),
		StatePath: filepath.Join(dir, "root.db"),
		Clock:     func() time.Time { return time.Unix(1000, 0) },
	}
	if _, err := initRootStateInRuntime(rt); err != nil {
		t.Fatalf("initRootStateInRuntime: %v", err)
	}
	state, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState(root): %v", err)
	}
	config := &syncConfigFile{PeerID: "node-admin", ListenAddr: "127.0.0.1:33540"}
	sr := newSyncRuntime(config, nil, rt)

	if err := sr.publishEndpointRecord(state); err != nil {
		t.Fatalf("publishEndpointRecord(root): %v", err)
	}
	if record := state.Network.Zones[zone.RootZone].Records[gossip.EndpointRecordKeyUDP]; record != nil {
		t.Fatalf("root admin unexpectedly published endpoint record")
	}
}
