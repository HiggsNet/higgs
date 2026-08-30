package main

import (
	"crypto/ed25519"
	"net"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corehost "github.com/HiggsNet/photon/pkg/core/host"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
)

func newTestObserverServer() *observerServer {
	state := newTestStateFile()
	store := newTestDaemonStateStore(state)
	d := &DaemonService{
		StateStore: store,
		Sync: &SyncRuntime{
			Config: &syncConfigFile{PeerID: "test-node", ListenAddr: "127.0.0.1:33434"},
			App:    &Runtime{Config: &appConfig{}},
		},
	}
	d.hostRuntime = corehost.NewRuntime(corehost.NewClock(nil), corehost.DefaultEventBuffer, store.common, corehost.GossipRuntimeConfig{})
	cfg := defaultObserverConfig()
	cfg.Enabled = true
	return newObserverServer(d, cfg)
}

func updateTestObserverState(srv *observerServer, fn func(*stateFile)) {
	if srv == nil || srv.daemon == nil || srv.daemon.StateStore == nil || fn == nil {
		return
	}
	state, _ := snapshotTestDaemonState(srv.daemon.StateStore)
	fn(state)
	replaceTestDaemonState(srv.daemon.StateStore, state)
}

func newTestStateFile() *stateFile {
	return &stateFile{
		Network:   nil,
		SyncPeers: make(map[string]syncPeerState),
	}
}

func addObserverEndpointZone(t *testing.T, ns *zone.NetworkState, path zone.ZonePath, ip string, port uint16, now time.Time) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(%s): %v", path, err)
	}
	authority := &zone.ZoneAuthority{Zone: path, Epoch: 1, Threshold: 1, Keys: []zone.AuthorizedKey{{Key: pub}}}
	zs := zone.NewZoneState(path, authority)
	value := endpointRecordBytes([]gossip.LocalEndpoint{{
		IP:       net.ParseIP(ip),
		Port:     port,
		Scope:    "loopback",
		Priority: 100,
		Source:   gossip.SourceAdvertise,
	}}, now)
	record := &zone.Record{
		Zone:      path,
		Key:       gossip.EndpointRecordKeyUDP,
		Type:      "sync.endpoint",
		Value:     value,
		Version:   1,
		Timestamp: now.Unix(),
	}
	if err := photoncrypto.SignRecord(record, priv); err != nil {
		t.Fatalf("SignRecord(%s): %v", path, err)
	}
	zs.Records[gossip.EndpointRecordKeyUDP] = record
	ns.Zones[path] = zs
}
