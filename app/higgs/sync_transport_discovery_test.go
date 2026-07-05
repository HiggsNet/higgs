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

func TestOpenSyncTransportAddsVerifiedZones(t *testing.T) {
	state, config := buildTestNetworkState(t)

	transport, err := openSyncTransport(config, state)
	if err != nil {
		skipRestrictedSocket(t, err)
		t.Fatalf("openSyncTransport: %v", err)
	}
	defer transport.Close()

	found := false
	for _, id := range transport.KnownPeerIDs() {
		if id == "node-b.catofes." {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("KnownPeerIDs() does not contain node-b.catofes.")
	}

	if transport.PeerAddr("node-b.catofes.") != nil {
		t.Fatalf("PeerAddr(node-b.catofes.) should be nil when no endpoint record exists")
	}
}

func TestAddVerifiedZonePeersAddsDelegatedChildWithoutZoneState(t *testing.T) {
	state, config := buildTestNetworkState(t)
	delete(state.Network.Zones, zone.ZonePath("node-b.catofes."))
	transport := &gossip.Transport{}
	sr := newSyncRuntime(state, config, transport, &Runtime{Clock: func() time.Time { return time.Unix(123, 0) }})

	sr.addVerifiedZonePeers()

	found := false
	for _, id := range transport.KnownPeerIDs() {
		if id == "node-b.catofes." {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("KnownPeerIDs() does not contain delegated node-b.catofes.")
	}
}

func TestHandlePingWithDifferentCatalogSummaryRequestsPeerCatalog(t *testing.T) {
	state, _ := buildTestNetworkState(t)
	config := &syncConfigFile{
		PeerID:          "node-b.catofes.",
		ListenAddr:      "127.0.0.1:0",
		MaxMessageBytes: gossip.DefaultDatagramBudget,
	}
	now := time.Unix(2000, 0)
	rt := &Runtime{
		StatePath: filepath.Join(t.TempDir(), "higgs.db"),
		Clock:     func() time.Time { return now },
	}

	transportA, err := gossip.Listen(gossip.Config{
		PeerID:          "node-a.catofes.",
		ListenAddr:      "127.0.0.1:0",
		MaxMessageBytes: gossip.DefaultDatagramBudget,
	})
	if err != nil {
		skipRestrictedSocket(t, err)
		t.Fatalf("Listen(A): %v", err)
	}
	defer transportA.Close()

	transportB, err := gossip.Listen(gossip.Config{
		PeerID:          config.PeerID,
		ListenAddr:      config.ListenAddr,
		MaxMessageBytes: gossip.DefaultDatagramBudget,
		KnownPeers: map[string]*net.UDPAddr{
			"node-a.catofes.": transportA.LocalAddr(),
		},
	})
	if err != nil {
		skipRestrictedSocket(t, err)
		t.Fatalf("Listen(B): %v", err)
	}
	defer transportB.Close()
	transportA.AddPeer(config.PeerID, transportB.LocalAddr())

	localSummary, err := gossip.CatalogSummaryFor(state.Network, gossip.DefaultDatagramBudget)
	if err != nil {
		t.Fatalf("CatalogSummaryFor: %v", err)
	}
	remoteSummary := &gossip.CatalogSummary{
		CatalogRoot: append([]byte(nil), localSummary.CatalogRoot...),
		ZoneCount:   localSummary.ZoneCount,
	}
	remoteSummary.CatalogRoot[0] ^= 0xff

	service := newDaemonService(rt, state, config, defaultDaemonInterval)
	service.Sync.Transport = transportB
	state.Lock()
	err = service.respondPing("node-a.catofes.", &gossip.Ping{Summary: remoteSummary})
	state.Unlock()
	if err != nil {
		t.Fatalf("respondPing: %v", err)
	}

	deadline := time.Now().Add(time.Second)
	var sawFetch bool
	for time.Now().Before(deadline) {
		packet, err := receiveWithDeadline(transportA, time.Now().Add(100*time.Millisecond))
		if err != nil {
			if isReceiveTimeout(err) {
				continue
			}
			t.Fatalf("receive A: %v", err)
		}
		if packet.Message.Type == gossip.MessageFetchCatalogPage {
			sawFetch = true
			break
		}
	}
	if !sawFetch {
		t.Fatalf("B did not request A catalog after different ping summary")
	}
}

func TestSyncRuntimeTransportConfigUsesInjectedDeps(t *testing.T) {
	state, config := buildTestNetworkState(t)
	knownAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 10001}
	replay := gossip.NewReplayWindow(time.Minute)
	quotas := gossip.NewPeerQuotas(gossip.QuotaConfig{ByteRate: 1, ByteBurst: 1, ObjectRate: 1, ObjectBurst: 1})
	var logged bool
	logger := func(gossip.Event) { logged = true }
	now := time.Unix(1234, 0)
	rt := &Runtime{Clock: func() time.Time { return now }}

	syncRuntime := newSyncRuntime(state, config, nil, rt)
	syncRuntime.TransportDeps = &SyncTransportDeps{
		KnownPeers: map[string]*net.UDPAddr{"node-b.catofes.": knownAddr},
		Replay:     replay,
		Quotas:     quotas,
		Log:        logger,
	}

	transportConfig := syncRuntime.transportConfig(syncRuntime.syncTransportDeps())
	if transportConfig.KnownPeers["node-b.catofes."] != knownAddr {
		t.Fatalf("KnownPeers did not use injected map")
	}
	if transportConfig.Replay != replay {
		t.Fatalf("Replay did not use injected replay window")
	}
	if transportConfig.Quotas != quotas {
		t.Fatalf("Quotas did not use injected quotas")
	}
	transportConfig.Log(gossip.Event{})
	if !logged {
		t.Fatalf("Log did not use injected logger")
	}
	if got := transportConfig.Clock(); !got.Equal(now) {
		t.Fatalf("Clock = %s, want %s", got, now)
	}
}

func TestDefaultSyncTransportDeps(t *testing.T) {
	config := &syncConfigFile{
		PeerID:          "node-a.catofes.",
		ListenAddr:      "127.0.0.1:0",
		MaxMessageBytes: 4096,
		Bootstrap: []syncConfigPeer{{
			ID:   "node-b.catofes.",
			Addr: "127.0.0.1:10001",
		}},
	}

	deps := defaultSyncTransportDeps(config)
	if deps.Replay == nil {
		t.Fatalf("Replay is nil")
	}
	if deps.Quotas == nil {
		t.Fatalf("Quotas is nil")
	}
	if addr := deps.KnownPeers["node-b.catofes."]; addr == nil || addr.String() != "127.0.0.1:10001" {
		t.Fatalf("KnownPeers[node-b] = %v, want 127.0.0.1:10001", addr)
	}
}

func TestUpdateDiscoveredPeersAddsAddrsForEndpoints(t *testing.T) {
	state, config := buildTestNetworkState(t)

	transport, err := openSyncTransport(config, state)
	if err != nil {
		skipRestrictedSocket(t, err)
		t.Fatalf("openSyncTransport: %v", err)
	}
	defer transport.Close()

	// node-b has no endpoint record yet
	if transport.PeerAddr("node-b.catofes.") != nil {
		t.Fatalf("PeerAddr(node-b.catofes.) should be nil before update")
	}

	// Add endpoint record for node-b
	endpoints := []gossip.LocalEndpoint{
		{IP: net.ParseIP("127.0.0.1"), Port: 9999, Scope: "global", Priority: 100, Source: gossip.SourceAdvertise},
	}
	value := gossip.EndpointRecordBytes(endpoints, time.Now())
	record := &zone.Record{
		Zone:      "node-b.catofes.",
		Key:       gossip.EndpointRecordKeyUDP,
		Type:      "sync.endpoint",
		Value:     value,
		Version:   1,
		Timestamp: time.Now().Unix(),
	}
	if err := higgscrypto.SignRecord(record, state.ZonePrivateKey); err != nil {
		t.Fatalf("SignRecord: %v", err)
	}
	if err := state.Network.Put(record); err != nil {
		t.Fatalf("Put: %v", err)
	}

	updateDiscoveredPeers(state, transport, config)

	addr := transport.PeerAddr("node-b.catofes.")
	if addr == nil {
		t.Fatalf("PeerAddr(node-b.catofes.) should not be nil after update")
	}
	if addr.IP.String() != "127.0.0.1" || addr.Port != 9999 {
		t.Fatalf("PeerAddr = %s, want 127.0.0.1:9999", addr.String())
	}
}

func TestUpdateDiscoveredPeersRanksPrivateEndpointsAfterPublic(t *testing.T) {
	state, config := buildTestNetworkState(t)
	prepareStatePersistence(t)
	transport := &gossip.Transport{}
	now := time.Now()
	endpoints := []gossip.LocalEndpoint{
		{IP: net.ParseIP("10.16.255.8"), Port: 33435, Scope: "global", Priority: 200, Source: gossip.SourceInterface},
		{IP: net.ParseIP("203.0.113.10"), Port: 33434, Scope: "global", Priority: 10, Source: gossip.SourceReflector},
	}
	record := &zone.Record{
		Zone:      "node-b.catofes.",
		Key:       gossip.EndpointRecordKeyUDP,
		Type:      "sync.endpoint",
		Value:     gossip.EndpointRecordBytes(endpoints, now),
		Version:   1,
		Timestamp: now.Unix(),
	}
	if err := higgscrypto.SignRecord(record, state.ZonePrivateKey); err != nil {
		t.Fatalf("SignRecord: %v", err)
	}
	if err := state.Network.PutAt(record, now); err != nil {
		t.Fatalf("PutAt: %v", err)
	}

	updateDiscoveredPeers(state, transport, config)

	addr := transport.PeerAddr("node-b.catofes.")
	if addr == nil || addr.String() != "203.0.113.10:33434" {
		t.Fatalf("PeerAddr = %v, want 203.0.113.10:33434", addr)
	}
	if got := state.SyncPeers["node-b.catofes."].DiscoveredAddr; got != "203.0.113.10:33434" {
		t.Fatalf("DiscoveredAddr = %q, want 203.0.113.10:33434", got)
	}
}

func TestUpdateDiscoveredPeersUpdatesEndpointAddrWithoutUDP(t *testing.T) {
	state, config := buildTestNetworkState(t)
	config.EndpointGrace = time.Nanosecond
	prepareStatePersistence(t)
	transport := &gossip.Transport{}

	now := time.Now()
	putSignedEndpointRecord(t, state, "127.0.0.1", 9999, now, 1)
	updateDiscoveredPeers(state, transport, config)
	if addr := transport.PeerAddr("node-b.catofes."); addr == nil || addr.String() != "127.0.0.1:9999" {
		t.Fatalf("PeerAddr after first update = %v, want 127.0.0.1:9999", addr)
	}

	putSignedEndpointRecord(t, state, "127.0.0.1", 10000, now.Add(time.Second), 2)
	updateDiscoveredPeers(state, transport, config)
	if addr := transport.PeerAddr("node-b.catofes."); addr == nil || addr.String() != "127.0.0.1:10000" {
		t.Fatalf("PeerAddr after endpoint change = %v, want 127.0.0.1:10000", addr)
	}
}

func TestUpdateDiscoveredPeersRevokesExpiredEndpointWithoutUDP(t *testing.T) {
	state, config := buildTestNetworkState(t)
	config.EndpointGrace = time.Nanosecond
	prepareStatePersistence(t)
	transport := &gossip.Transport{}

	putSignedEndpointRecord(t, state, "127.0.0.1", 9999, time.Unix(1, 0), 1)
	state.SyncPeers = map[string]syncPeerState{
		"node-b.catofes.": {
			LastSyncUnix:     time.Unix(1, 0).Unix(),
			DiscoveredAddr:   "127.0.0.1:9999",
			DiscoveredAtUnix: time.Unix(1, 0).Unix(),
		},
	}
	transport.SetPeerAddrs("node-b.catofes.", []*net.UDPAddr{{IP: net.ParseIP("127.0.0.1"), Port: 9999}})

	updateDiscoveredPeers(state, transport, config)
	if addr := transport.PeerAddr("node-b.catofes."); addr != nil {
		t.Fatalf("PeerAddr after expired endpoint = %v, want nil", addr)
	}
	if got := state.SyncPeers["node-b.catofes."].DiscoveredAddr; got != "" {
		t.Fatalf("DiscoveredAddr = %q, want cleared", got)
	}
}

func TestAppendRecentSuccessfulDiscoveredAddr(t *testing.T) {
	now := time.Unix(1000, 0)
	addrs := []*net.UDPAddr{{IP: net.ParseIP("127.0.0.1"), Port: 1000}}
	peerState := syncPeerState{
		LastSyncUnix:     now.Add(-time.Minute).Unix(),
		DiscoveredAddr:   "127.0.0.1:2000",
		DiscoveredAtUnix: now.Add(-2 * time.Minute).Unix(),
	}

	addrs = appendRecentSuccessfulDiscoveredAddr(addrs, peerState, 10*time.Minute, now)

	if len(addrs) != 2 {
		t.Fatalf("addrs = %d, want 2", len(addrs))
	}
	if addrs[1].String() != "127.0.0.1:2000" {
		t.Fatalf("fallback addr = %s, want 127.0.0.1:2000", addrs[1])
	}
}

func TestAppendRecentSuccessfulDiscoveredAddrExpires(t *testing.T) {
	now := time.Unix(1000, 0)
	peerState := syncPeerState{
		LastSyncUnix:   now.Add(-20 * time.Minute).Unix(),
		DiscoveredAddr: "127.0.0.1:2000",
	}

	addrs := appendRecentSuccessfulDiscoveredAddr(nil, peerState, 10*time.Minute, now)
	if len(addrs) != 0 {
		t.Fatalf("addrs = %#v, want expired fallback to be dropped", addrs)
	}
}

func TestBuildPeerAddrsPutsAdvertiseBeforeBootstrap(t *testing.T) {
	now := time.Now()
	bootstrap := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 33434}
	entries := []gossip.EndpointEntry{
		{Address: "203.0.113.10", Port: 33434, Source: "reflector", Priority: 50},
		{Address: "10.0.0.5", Port: 33434, Source: "interface", Priority: 10},
		{Address: "198.51.100.2", Port: 33434, Source: "advertise", Priority: 100},
	}

	addrs := buildPeerAddrs("peer-a", entries, bootstrap, syncPeerState{}, time.Minute, nil, now)
	if len(addrs) != 4 {
		t.Fatalf("addrs = %d, want 4", len(addrs))
	}
	if addrs[0].String() != "198.51.100.2:33434" {
		t.Fatalf("first addr = %v, want advertise 198.51.100.2:33434", addrs[0])
	}
	if addrs[1].String() != bootstrap.String() {
		t.Fatalf("second addr = %v, want bootstrap %v", addrs[1], bootstrap)
	}
}

func TestBuildPeerAddrsRespectsSourceOrder(t *testing.T) {
	now := time.Now()
	bootstrap := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 33434}
	entries := []gossip.EndpointEntry{
		{Address: "203.0.113.10", Port: 33434, Source: "reflector"},
		{Address: "198.51.100.2", Port: 33434, Source: "advertise"},
	}

	addrs := buildPeerAddrs("peer-a", entries, bootstrap, syncPeerState{}, time.Minute, []string{"bootstrap", "advertise", "reflector"}, now)
	if len(addrs) != 3 {
		t.Fatalf("addrs = %d, want 3", len(addrs))
	}
	if addrs[0].String() != bootstrap.String() {
		t.Fatalf("first addr = %v, want bootstrap", addrs[0])
	}
	if addrs[1].String() != "198.51.100.2:33434" {
		t.Fatalf("second addr = %v, want advertise 198.51.100.2:33434", addrs[1])
	}
}

func TestFilterEndpointDiscoveryInputsLoopbackOnly(t *testing.T) {
	config := &syncConfigFile{
		ListenAddr:        ":33434",
		AdvertiseAddrs:    []string{"127.0.0.1:33434", "203.0.113.10:33434"},
		Reflectors:        []string{"auto"},
		EndpointDiscovery: "loopback_only",
	}
	advertise, reflectors := filterEndpointDiscoveryInputs(config, 33434)
	if len(reflectors) != 0 {
		t.Fatalf("reflectors = %v, want empty", reflectors)
	}
	foundPublic := false
	for _, addr := range advertise {
		if strings.Contains(addr, "203.0.113.10") {
			foundPublic = true
		}
	}
	if foundPublic {
		t.Fatalf("public advertise addr should be filtered in loopback_only: %v", advertise)
	}
	if len(advertise) == 0 {
		t.Fatalf("expected at least one loopback advertise addr")
	}
}

func TestFilterEndpointDiscoveryInputsAdvertiseOnly(t *testing.T) {
	config := &syncConfigFile{
		ListenAddr:        "127.0.0.1:33434",
		AdvertiseAddrs:    []string{"203.0.113.10:33434"},
		Reflectors:        []string{"auto"},
		EndpointDiscovery: "advertise_only",
	}
	advertise, reflectors := filterEndpointDiscoveryInputs(config, 33434)
	if len(reflectors) != 0 {
		t.Fatalf("reflectors = %v, want empty", reflectors)
	}
	if len(advertise) != 1 || advertise[0] != "203.0.113.10:33434" {
		t.Fatalf("advertise = %v, want [203.0.113.10:33434]", advertise)
	}
}

func TestFilterEndpointDiscoveryInputsAutoLoopbackBootstrap(t *testing.T) {
	config := &syncConfigFile{
		ListenAddr: ":33434",
		Bootstrap: []syncConfigPeer{
			{ID: "peer-a", Addr: "127.0.0.1:33435"},
		},
		AdvertiseAddrs: []string{"203.0.113.10:33434"},
		Reflectors:     []string{"auto"},
	}
	advertise, reflectors := filterEndpointDiscoveryInputs(config, 33434)
	if len(reflectors) != 0 {
		t.Fatalf("auto loopback-only should suppress reflectors")
	}
	foundPublic := false
	for _, addr := range advertise {
		if strings.Contains(addr, "203.0.113.10") {
			foundPublic = true
		}
	}
	if foundPublic {
		t.Fatalf("auto loopback-only should filter public advertise addrs: %v", advertise)
	}
}

func TestFilterEndpointDiscoveryInputsAutoPublicBootstrap(t *testing.T) {
	config := &syncConfigFile{
		ListenAddr: ":33434",
		Bootstrap: []syncConfigPeer{
			{ID: "peer-a", Addr: "203.0.113.10:33435"},
		},
		AdvertiseAddrs: []string{"203.0.113.10:33434"},
		Reflectors:     []string{"auto"},
	}
	advertise, reflectors := filterEndpointDiscoveryInputs(config, 33434)
	if len(reflectors) == 0 {
		t.Fatalf("auto with public bootstrap should keep reflectors")
	}
	if len(advertise) != 1 || advertise[0] != "203.0.113.10:33434" {
		t.Fatalf("advertise = %v, want [203.0.113.10:33434]", advertise)
	}
}
