package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"
)

func TestParseConfigYAML(t *testing.T) {
	pub := make(ed25519.PublicKey, ed25519.PublicKeySize)
	for i := range pub {
		pub[i] = byte(i)
	}
	config := defaultAppConfig()
	input := `
data_dir: /tmp/higgs-a
peer_id: node-a
listen_port: 33434
max_message_bytes: 32768
max_sync_zones: 8
max_sync_records: 512
bootstrap:
  - id: node-b
    addr: 127.0.0.1:33435
trusted_root_public_key: ` + hex.EncodeToString(pub) + `
`
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	normalizeAppConfig(config)
	if config.StatePath != "/tmp/higgs-a/higgs.db" {
		t.Fatalf("StatePath = %q, want /tmp/higgs-a/higgs.db", config.StatePath)
	}
	if config.PeerID != "node-a" || config.ListenAddr != ":33434" {
		t.Fatalf("peer/listen = %q/%q", config.PeerID, config.ListenAddr)
	}
	if len(config.Bootstrap) != 1 || config.Bootstrap[0].ID != "node-b" || config.Bootstrap[0].Addr != "127.0.0.1:33435" {
		t.Fatalf("Bootstrap = %#v", config.Bootstrap)
	}
	if !equalPublicKey(config.TrustedRootPublicKey, pub) {
		t.Fatalf("TrustedRootPublicKey mismatch")
	}
	if config.MaxMessageBytes != 32768 || config.MaxSyncZones != 8 || config.MaxSyncRecords != 512 {
		t.Fatalf("sync limits = %d/%d/%d", config.MaxMessageBytes, config.MaxSyncZones, config.MaxSyncRecords)
	}
}
