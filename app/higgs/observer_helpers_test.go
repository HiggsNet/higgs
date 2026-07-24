package main

import (
	"crypto/ed25519"
	"net"
	"testing"
	"time"

	"github.com/Catofes/higgs/internal/observability"
	"github.com/Catofes/higgs/pkg/core/gossip"
	"github.com/Catofes/higgs/pkg/core/zone"
	higgscrypto "github.com/Catofes/higgs/pkg/crypto"
)

func newTestObserverServer() *observerServer {
	peerObservability := observability.NewPeerObservabilityStore(32, time.Hour)
	d := &DaemonService{
		PeerObservability: peerObservability,
		Sync: &SyncRuntime{
			State:         newTestStateFile(),
			Config:        &syncConfigFile{PeerID: "test-node", ListenAddr: "127.0.0.1:33434"},
			App:           &Runtime{Config: &appConfig{}},
			Observability: peerObservability,
		},
	}
	cfg := defaultObserverConfig()
	cfg.Enabled = true
	return newObserverServer(d, cfg)
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
	value := gossip.EndpointRecordBytes([]gossip.LocalEndpoint{{
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
	if err := higgscrypto.SignRecord(record, priv); err != nil {
		t.Fatalf("SignRecord(%s): %v", path, err)
	}
	zs.Records[gossip.EndpointRecordKeyUDP] = record
	ns.Zones[path] = zs
}
