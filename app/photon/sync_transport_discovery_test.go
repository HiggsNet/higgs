package main

import (
	"context"
	"net"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
)

func TestStartupDiscoveryAddsVerifiedZones(t *testing.T) {
	state, config := buildTestNetworkState(t)

	transport, err := newSyncRuntime(config, nil, nil).openTransport()
	if err != nil {
		skipRestrictedSocket(t, err)
		t.Fatalf("openSyncTransport: %v", err)
	}
	defer transport.Close()
	updateDiscoveredPeersForTest(t, state, config, transport)

	found := slices.Contains(transport.KnownPeerIDs(), "node-b.catofes.")
	if !found {
		t.Fatalf("KnownPeerIDs() does not contain node-b.catofes.")
	}

	if transport.PeerAddr("node-b.catofes.") != nil {
		t.Fatalf("PeerAddr(node-b.catofes.) should be nil when no endpoint record exists")
	}
}

func updateDiscoveredPeersForTest(t *testing.T, state *stateFile, config *syncConfigFile, transport *gossip.Transport) {
	t.Helper()
	now := time.Now()
	rt := &Runtime{StatePath: filepath.Join(t.TempDir(), "state.db"), Clock: func() time.Time { return now }}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	service := newTestDaemonService(rt, state, config, time.Second)
	service.Sync.Transport = transport
	service.updateDiscoveredPeers()
	committed, _ := service.StateStore.Snapshot()
	state.Network = committed.Network
	state.SyncPeers = committed.SyncPeers
}

func TestStartupDiscoveryAddsDelegatedChildWithoutZoneState(t *testing.T) {
	state, config := buildTestNetworkState(t)
	delete(state.Network.Zones, zone.ZonePath("node-b.catofes."))
	transport := &gossip.Transport{}
	updateDiscoveredPeersForTest(t, state, config, transport)

	found := slices.Contains(transport.KnownPeerIDs(), "node-b.catofes.")
	if !found {
		t.Fatalf("KnownPeerIDs() does not contain delegated node-b.catofes.")
	}
}

func TestSyncIngressRouteExpiresWithoutBecomingDurable(t *testing.T) {
	now := time.Unix(1000, 0)
	service := &DaemonService{}
	addr := &net.UDPAddr{IP: net.ParseIP("198.51.100.20"), Port: 42000}
	service.rememberSyncIngressRoute("node-b.catofes.", addr, now)

	got := service.syncIngressRouteAddr("node-b.catofes.", now.Add(syncIngressRouteTTL-time.Second))
	if got == nil || got.String() != addr.String() {
		t.Fatalf("active ingress route = %v, want %v", got, addr)
	}
	if got := service.syncIngressRouteAddr("node-b.catofes.", now.Add(syncIngressRouteTTL)); got != nil {
		t.Fatalf("expired ingress route = %v, want nil", got)
	}
}

func TestPingResponderRepliesToInboundSourceBeforePeerZoneIsVerified(t *testing.T) {
	state, config := buildTestNetworkState(t)
	delete(state.Network.Zones, zone.ZonePath("node-b.catofes."))
	now := time.Unix(123, 0)
	rt := &Runtime{
		StatePath: filepath.Join(t.TempDir(), "photon.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}

	transportA, err := listenTestGossipTransport("127.0.0.1:0", gossip.Config{
		PeerID: config.PeerID,
		KnownPeers: map[string]*net.UDPAddr{
			"node-b.catofes.": {IP: net.ParseIP("192.0.2.10"), Port: 33434},
		},
		Clock: func() time.Time { return now },
	})
	if err != nil {
		skipRestrictedSocket(t, err)
		t.Fatalf("Listen(A): %v", err)
	}
	defer transportA.Close()

	transportB, err := listenTestGossipTransport("127.0.0.1:0", gossip.Config{
		PeerID:     "node-b.catofes.",
		KnownPeers: map[string]*net.UDPAddr{config.PeerID: transportA.LocalAddr()},
		Clock:      func() time.Time { return now },
	})
	if err != nil {
		skipRestrictedSocket(t, err)
		t.Fatalf("Listen(B): %v", err)
	}
	defer transportB.Close()

	if err := transportB.Send(config.PeerID, &gossip.Message{Type: gossip.MessagePing, Ping: &gossip.Ping{}}); err != nil {
		t.Fatalf("Send(B -> A): %v", err)
	}
	if err := transportA.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline(A): %v", err)
	}
	packet, err := transportA.Receive()
	if err != nil {
		t.Fatalf("Receive(A): %v", err)
	}

	service := newTestDaemonService(rt, state, config, defaultDaemonInterval)
	service.Sync.Transport = transportA
	if err := service.handlePacketEventSyncSession(packet, context.Background()); err != nil {
		t.Fatalf("handlePacketEventSyncSession: %v", err)
	}

	if err := transportB.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline(B): %v", err)
	}
	reply, err := transportB.Receive()
	if err != nil {
		t.Fatalf("Receive(B): %v", err)
	}
	if reply.Message.Type != gossip.MessagePong {
		t.Fatalf("reply type = %s, want pong", reply.Message.Type)
	}

	session := NewSyncSession("node-b.catofes.")
	service.hostRuntime.Gossip.SetSession(session.PeerID, session)
	service.executeSyncActions(context.Background(), session, []SyncAction{gossip.SendChunkFallbackAction{
		PeerID: session.PeerID,
		Zone:   "catofes.",
	}})
	if err := transportB.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline(B fallback): %v", err)
	}
	pull, err := transportB.Receive()
	if err != nil {
		t.Fatalf("Receive(B fallback): %v", err)
	}
	if pull.Message.Type != gossip.MessageFetchZone || pull.Message.FetchZone == nil || !pull.Message.FetchZone.ChunkFallback {
		t.Fatalf("active pull = %#v, want chunk-fallback fetch_zone", pull.Message)
	}
	if got := transportA.LastSendAddr("node-b.catofes."); got == nil || got.String() != packet.Addr.String() {
		t.Fatalf("A last sent addr = %v, want inbound source %q", got, packet.Addr)
	}

	session.State = SyncSessionCompleted
	service.completeSyncSessionAfterPeerState(session, false)
	if got := service.syncIngressRouteAddr(session.PeerID, now); got != nil {
		t.Fatalf("session ingress route remained after completion: %v", got)
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
		StatePath: filepath.Join(t.TempDir(), "photon.db"),
		Clock:     func() time.Time { return now },
	}

	transportA, err := listenTestGossipTransport("127.0.0.1:0", gossip.Config{
		PeerID:          "node-a.catofes.",
		MaxMessageBytes: gossip.DefaultDatagramBudget,
	})
	if err != nil {
		skipRestrictedSocket(t, err)
		t.Fatalf("Listen(A): %v", err)
	}
	defer transportA.Close()

	transportB, err := listenTestGossipTransport(config.ListenAddr, gossip.Config{
		PeerID:          config.PeerID,
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

	localSummary := corestate.CatalogSummaryFor(state.Network)
	remoteSummary := &corestate.CatalogSummary{
		CatalogRoot: append([]byte(nil), localSummary.CatalogRoot...),
		ZoneCount:   localSummary.ZoneCount,
	}
	remoteSummary.CatalogRoot[0] ^= 0xff

	service := newTestDaemonService(rt, state, config, defaultDaemonInterval)
	service.Sync.Transport = transportB
	message := &gossip.Message{
		Type:   gossip.MessagePing,
		PeerID: "node-a.catofes.",
		Ping:   &gossip.Ping{Summary: remoteSummary},
	}
	controller := &daemonGossipActionController{
		daemon: service,
		now:    service.Sync.now(),
		limits: syncLimits(config),
	}
	state.Lock()
	err = service.hostRuntime.ExecuteGossipInbound(
		context.Background(),
		service.hostRuntime.Gossip.PlanInbound(&gossip.Packet{Message: message}),
		controller,
	)
	state.Unlock()
	if err != nil {
		t.Fatalf("ExecuteGossipInbound: %v", err)
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
	_, config := buildTestNetworkState(t)
	knownAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 10001}
	replay := gossip.NewReplayWindow(time.Minute)
	quotas := gossip.NewPeerQuotas(gossip.QuotaConfig{ByteRate: 1, ByteBurst: 1, ObjectRate: 1, ObjectBurst: 1})
	var logged bool
	logger := func(gossip.Event) { logged = true }
	now := time.Unix(1234, 0)
	rt := &Runtime{Clock: func() time.Time { return now }}

	syncRuntime := newSyncRuntime(config, nil, rt)
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

	transport, err := newSyncRuntime(config, nil, nil).openTransport()
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
	value := endpointRecordBytes(endpoints, time.Now())
	record := &zone.Record{
		Zone:      "node-b.catofes.",
		Key:       gossip.EndpointRecordKeyUDP,
		Type:      "sync.endpoint",
		Value:     value,
		Version:   1,
		Timestamp: time.Now().Unix(),
	}
	if err := photoncrypto.SignRecord(record, state.ZonePrivateKey); err != nil {
		t.Fatalf("SignRecord: %v", err)
	}
	if err := state.Network.Put(record); err != nil {
		t.Fatalf("Put: %v", err)
	}

	updateDiscoveredPeersForTest(t, state, config, transport)

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
		Value:     endpointRecordBytes(endpoints, now),
		Version:   1,
		Timestamp: now.Unix(),
	}
	if err := photoncrypto.SignRecord(record, state.ZonePrivateKey); err != nil {
		t.Fatalf("SignRecord: %v", err)
	}
	if err := state.Network.PutAt(record, now); err != nil {
		t.Fatalf("PutAt: %v", err)
	}

	updateDiscoveredPeersForTest(t, state, config, transport)

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
	updateDiscoveredPeersForTest(t, state, config, transport)
	if addr := transport.PeerAddr("node-b.catofes."); addr == nil || addr.String() != "127.0.0.1:9999" {
		t.Fatalf("PeerAddr after first update = %v, want 127.0.0.1:9999", addr)
	}

	putSignedEndpointRecord(t, state, "127.0.0.1", 10000, now.Add(time.Second), 2)
	updateDiscoveredPeersForTest(t, state, config, transport)
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

	updateDiscoveredPeersForTest(t, state, config, transport)
	if addr := transport.PeerAddr("node-b.catofes."); addr != nil {
		t.Fatalf("PeerAddr after expired endpoint = %v, want nil", addr)
	}
	if got := state.SyncPeers["node-b.catofes."].DiscoveredAddr; got != "" {
		t.Fatalf("DiscoveredAddr = %q, want cleared", got)
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
