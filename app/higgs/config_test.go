package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Catofes/higgs/pkg/core/gossip"
	"github.com/Catofes/higgs/pkg/transport/ipsec"
)

func TestParseConfigYAML(t *testing.T) {
	pub := make(ed25519.PublicKey, ed25519.PublicKeySize)
	for i := range pub {
		pub[i] = byte(i)
	}
	config := defaultAppConfig()
	input := `
data_dir: /tmp/higgs-a
trusted_root_public_key: ` + hex.EncodeToString(pub) + `
gossip:
  peer_id: node-a
  listen_port: 33434
  max_datagram_bytes: 32768
  max_sync_zones: 8
  max_sync_records: 512
  endpoint_grace: 2m
  reflector_timeout: 1500ms
  publish_endpoints: false
  bootstrap:
    - id: node-b
      addr: 127.0.0.1:33435
`
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	normalizeAppConfig(config)
	if config.StatePath != "/tmp/higgs-a/higgs.db" {
		t.Fatalf("StatePath = %q, want /tmp/higgs-a/higgs.db", config.StatePath)
	}
	if config.PeerID != "node-a" || config.ListenAddr != "0.0.0.0:33434" {
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
	if config.EndpointGrace.String() != "2m0s" {
		t.Fatalf("EndpointGrace = %s, want 2m0s", config.EndpointGrace)
	}
	if config.ReflectorTimeout.String() != "1.5s" {
		t.Fatalf("ReflectorTimeout = %s, want 1.5s", config.ReflectorTimeout)
	}
	if config.PublishEndpoints {
		t.Fatalf("PublishEndpoints = true, want false")
	}
	if config.IPsec.DefaultNetNS.Name != ipsec.DefaultNetNSName || !config.IPsec.DefaultNetNS.Create {
		t.Fatalf("IPsec.DefaultNetNS = %+v", config.IPsec.DefaultNetNS)
	}
	if config.Overlay.DefaultNetNS.Name != ipsec.DefaultNetNSName || !config.Overlay.DefaultNetNS.Create {
		t.Fatalf("Overlay.DefaultNetNS = %+v", config.Overlay.DefaultNetNS)
	}
}

func TestParseConfigExampleYAML(t *testing.T) {
	data, err := os.ReadFile("../../config.example.yaml")
	if err != nil {
		t.Fatalf("read config.example.yaml: %v", err)
	}
	config := defaultAppConfig()
	if err := parseConfigYAML(string(data), config); err != nil {
		t.Fatalf("parse config.example.yaml: %v", err)
	}
	if config.PeerID == "" {
		t.Fatal("config.example.yaml should set peer_id")
	}
	if len(config.IPsec.LinkGroups) != 0 {
		t.Fatal("config.example.yaml should not enable overlay link groups by default")
	}
	if len(config.Routing.Instances) == 0 {
		t.Fatal("config.example.yaml should include a routing instance example")
	}
}

func TestLoadAppConfigRejectsMissingExplicitConfig(t *testing.T) {
	missingPath := filepath.Join(t.TempDir(), "missing.yaml")
	t.Setenv("HIGGS_CONFIG", missingPath)

	config, err := loadAppConfig()
	if err == nil {
		t.Fatalf("loadAppConfig returned nil error and config %#v for missing explicit config", config)
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("loadAppConfig error = %v, want not-exist error", err)
	}
	if !strings.Contains(err.Error(), missingPath) {
		t.Fatalf("loadAppConfig error = %q, want path %q", err.Error(), missingPath)
	}
}

func TestConfigDefaultsForListenAndPrivateIPv4Filter(t *testing.T) {
	config := defaultAppConfig()
	normalizeAppConfig(config)
	if config.ListenAddr != "0.0.0.0:33434" {
		t.Fatalf("ListenAddr = %q, want 0.0.0.0:33434", config.ListenAddr)
	}
	if !config.FilterPrivateIPv4 {
		t.Fatal("FilterPrivateIPv4 = false, want true")
	}
	if config.IPsec.Driver != ipsecDriverStrongSwan {
		t.Fatalf("IPsec.Driver = %q, want strongswan", config.IPsec.Driver)
	}
}

func TestParseConfigYAMLCanDisablePrivateIPv4Filter(t *testing.T) {
	config := defaultAppConfig()
	if err := parseConfigYAML("gossip:\n  filter_private_ipv4: false\n", config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	if config.FilterPrivateIPv4 {
		t.Fatal("FilterPrivateIPv4 = true, want false")
	}
}

func TestParseConfigYAMLOverlayDefaultNetNS(t *testing.T) {
	config := defaultAppConfig()
	input := `
overlay:
  default_netns:
    kind: name
    name: h2
    create: true
`
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	normalizeAppConfig(config)
	if config.Overlay.DefaultNetNS.Kind != ipsec.NetNSName || config.Overlay.DefaultNetNS.Name != "h2" || !config.Overlay.DefaultNetNS.Create {
		t.Fatalf("Overlay.DefaultNetNS = %+v", config.Overlay.DefaultNetNS)
	}
	if config.IPsec.DefaultNetNS.Kind != ipsec.NetNSName || config.IPsec.DefaultNetNS.Name != "h2" || !config.IPsec.DefaultNetNS.Create {
		t.Fatalf("IPsec.DefaultNetNS = %+v", config.IPsec.DefaultNetNS)
	}
}

func TestParseConfigYAMLLegacyIPsecDefaultNetNS(t *testing.T) {
	config := defaultAppConfig()
	input := `
ipsec:
  default_netns:
    kind: name
    name: legacy-h2
    create: true
`
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	normalizeAppConfig(config)
	if config.Overlay.DefaultNetNS.Name != "legacy-h2" || config.IPsec.DefaultNetNS.Name != "legacy-h2" {
		t.Fatalf("default netns = overlay:%+v ipsec:%+v", config.Overlay.DefaultNetNS, config.IPsec.DefaultNetNS)
	}
}

func TestParseConfigYAMLIPsecDriver(t *testing.T) {
	config := defaultAppConfig()
	input := `
ipsec:
  driver: strongswan
  vici_socket: /tmp/charon.vici
`
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	normalizeAppConfig(config)
	if config.IPsec.Driver != ipsecDriverStrongSwan || config.IPsec.VICISocket != "/tmp/charon.vici" {
		t.Fatalf("IPsec driver config = %+v", config.IPsec)
	}
}

func TestParseConfigYAMLRejectsInvalidIPsecDriver(t *testing.T) {
	config := defaultAppConfig()
	input := `
ipsec:
  driver: magic
`
	if err := parseConfigYAML(input, config); err == nil {
		t.Fatalf("parseConfigYAML should reject invalid ipsec.driver")
	}
}

func TestParseConfigYAMLIPsecAnnouncements(t *testing.T) {
	config := defaultAppConfig()
	input := `ipsec:
  announce_addrs:
    - 203.0.113.10:4500
    - "[2001:db8::10]:4500"
  announce_dns:
    - vpn.example.com
    - vpn6.example.com
  publish_from_endpoints: false
`
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	normalizeAppConfig(config)
	if len(config.IPsec.AnnounceAddrs) != 2 || config.IPsec.AnnounceAddrs[0] != "203.0.113.10:4500" || config.IPsec.AnnounceAddrs[1] != "[2001:db8::10]:4500" {
		t.Fatalf("AnnounceAddrs = %v", config.IPsec.AnnounceAddrs)
	}
	if len(config.IPsec.AnnounceDNS) != 2 || config.IPsec.AnnounceDNS[0] != "vpn.example.com" || config.IPsec.AnnounceDNS[1] != "vpn6.example.com" {
		t.Fatalf("AnnounceDNS = %v", config.IPsec.AnnounceDNS)
	}
	if config.IPsec.PublishFromEndpoints {
		t.Fatalf("PublishFromEndpoints = true, want false")
	}
}

func TestParseConfigYAMLIPsecPublishFromEndpointsDefaultsToTrue(t *testing.T) {
	config := defaultAppConfig()
	if err := parseConfigYAML("", config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	normalizeAppConfig(config)
	if !config.IPsec.PublishFromEndpoints {
		t.Fatalf("PublishFromEndpoints = false, want true")
	}
}

func TestParseConfigYAMLOverlayDefaultNetNSOverridesLegacyIPsecDefault(t *testing.T) {
	config := defaultAppConfig()
	input := `
ipsec:
  default_netns:
    kind: name
    name: legacy-h2
    create: true
overlay:
  default_netns:
    kind: name
    name: overlay-h2
    create: true
`
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	normalizeAppConfig(config)
	if config.Overlay.DefaultNetNS.Name != "overlay-h2" || config.IPsec.DefaultNetNS.Name != "overlay-h2" {
		t.Fatalf("default netns = overlay:%+v ipsec:%+v", config.Overlay.DefaultNetNS, config.IPsec.DefaultNetNS)
	}
}

func TestParseConfigYAMLOverlays(t *testing.T) {
	config := defaultAppConfig()
	input := `
netns:
  default:
    kind: name
    name: h2
    create: true
overlays:
  - name: ipsec-main
    provider: strongswan
    netns: default
    default_path_mode: family-redundant
    address_source_order: manual-dns, discovery
    max_peers: 64
    max_links_per_peer: 2
    tunnel_address_pool: fd00:1234::/64
    reconcile:
      interval: 30s
      rotate_retention: 1h
      backoff:
        initial: 1s
        max: 1m
    connect:
      - "strongswan://*.catofes.?accept=inbound&family=dual"
    deny:
      - "strongswan://*.lab.catofes."
`
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	normalizeAppConfig(config)
	if len(config.IPsec.LinkGroups) != 1 {
		t.Fatalf("LinkGroups len = %d, want 1", len(config.IPsec.LinkGroups))
	}
	group := config.IPsec.LinkGroups[0]
	if group.ID != "ipsec-main" || group.Name != "ipsec-main" || group.Provider != ipsec.ProviderStrongSwan {
		t.Fatalf("group identity = %+v", group)
	}
	if group.NetNS.Kind != ipsec.NetNSName || group.NetNS.Name != "h2" || !group.NetNS.Create {
		t.Fatalf("group netns = %+v", group.NetNS)
	}
	if group.TunnelAddressPool.String() != "fd00:1234::/64" {
		t.Fatalf("tunnel pool = %s", group.TunnelAddressPool)
	}
	if group.Reconcile.IntervalSeconds != 30 || group.Reconcile.RotateRetentionSeconds != 3600 || group.Reconcile.Backoff.InitialSeconds != 1 || group.Reconcile.Backoff.MaxSeconds != 60 {
		t.Fatalf("reconcile = %+v", group.Reconcile)
	}
	if got := strings.Join(group.AddressSourceOrder, ","); got != "manual-dns,discovery" {
		t.Fatalf("AddressSourceOrder = %q", got)
	}
	if len(group.ConnectRules) != 1 || len(group.DenyRules) != 1 {
		t.Fatalf("rules = connect:%v deny:%v", group.ConnectRules, group.DenyRules)
	}
	if config.IPsec.Accept != ipsec.AcceptBidirectional {
		t.Fatalf("IPsec.Accept = %q, want default bidirectional", config.IPsec.Accept)
	}
}

func TestParseConfigYAMLIPsecAccept(t *testing.T) {
	config := defaultAppConfig()
	input := `
ipsec:
  accept: bidirectional
`
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	normalizeAppConfig(config)
	if config.IPsec.Accept != ipsec.AcceptBidirectional {
		t.Fatalf("IPsec.Accept = %q, want bidirectional", config.IPsec.Accept)
	}
}

func TestParseConfigYAMLIPsecAcceptInvalid(t *testing.T) {
	config := defaultAppConfig()
	input := `
ipsec:
  accept: both
`
	if err := parseConfigYAML(input, config); err == nil {
		t.Fatalf("expected error for invalid ipsec.accept")
	}
}

func TestParseConfigYAMLOverlayDirectionDeprecated(t *testing.T) {
	config := defaultAppConfig()
	input := `
overlays:
  - name: ipsec-main
    direction: outbound
`
	if err := parseConfigYAML(input, config); err == nil {
		t.Fatalf("expected error for deprecated overlays[].direction")
	}
}

func TestParseConfigYAMLOverlayUsesDefaultNetNSReference(t *testing.T) {
	config := defaultAppConfig()
	input := `
netns:
  default:
    kind: name
    name: h2
    create: true
overlays:
  - name: ipsec-main
    provider: strongswan
`
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	normalizeAppConfig(config)
	group := config.IPsec.LinkGroups[0]
	if group.NetNS.Kind != ipsec.NetNSName || group.NetNS.Name != "h2" || !group.NetNS.Create {
		t.Fatalf("group netns = %+v, want netns.default h2", group.NetNS)
	}
}

func TestParseConfigYAMLOverlayAcceptsLegacyInlineNetNS(t *testing.T) {
	config := defaultAppConfig()
	input := `
overlays:
  - name: ipsec-main
    provider: strongswan
    netns:
      kind: name
      name: legacy-h2
      create: true
`
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	normalizeAppConfig(config)
	group := config.IPsec.LinkGroups[0]
	if group.NetNS.Kind != ipsec.NetNSName || group.NetNS.Name != "legacy-h2" || !group.NetNS.Create {
		t.Fatalf("group netns = %+v, want inline legacy-h2", group.NetNS)
	}
}

func TestParseConfigYAMLOverlayRejectsUnknownNetNSReference(t *testing.T) {
	config := defaultAppConfig()
	input := `
netns:
  default:
    kind: name
    name: h2
    create: true
overlays:
  - name: ipsec-main
    provider: strongswan
    netns: missing
`
	err := parseConfigYAML(input, config)
	if err == nil {
		t.Fatal("expected unknown overlay netns reference error")
	}
	if !strings.Contains(err.Error(), `unknown netns "missing"`) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseConfigYAMLRejectsInvalidOverlay(t *testing.T) {
	config := defaultAppConfig()
	input := `
overlays:
  - name: broken
    provider: strongswan
    tunnel_address_pool: not-a-prefix
`
	if err := parseConfigYAML(input, config); err == nil {
		t.Fatalf("parseConfigYAML should reject invalid overlay tunnel pool")
	}
}

func TestParseConfigYAMLRejectsInvalidOverlayRule(t *testing.T) {
	config := defaultAppConfig()
	input := `
overlays:
  - name: ipsec-main
    provider: strongswan
    connect:
      - "strongswan://*.catofes.?source=magic"
`
	if err := parseConfigYAML(input, config); err == nil {
		t.Fatalf("parseConfigYAML should reject invalid overlay rule")
	}
}

func TestParseConfigYAMLRejectsInvalidOverlayDefaultNetNS(t *testing.T) {
	config := defaultAppConfig()
	input := `
overlay:
  default_netns:
    kind: host
    create: true
`
	if err := parseConfigYAML(input, config); err == nil {
		t.Fatalf("parseConfigYAML should reject overlay host netns create")
	}
}

func TestParseConfigYAMLLists(t *testing.T) {
	config := defaultAppConfig()
	input := `
gossip:
  advertise_addrs:
    - 127.0.0.1:33434
    - 10.0.0.2:33434
  reflectors:
    - 198.51.100.10:33434
    - 198.51.100.11:33434
  bootstrap:
    - id: node-b
      addr: 127.0.0.1:33435
`
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	if got := strings.Join(config.AdvertiseAddrs, ","); got != "127.0.0.1:33434,10.0.0.2:33434" {
		t.Fatalf("AdvertiseAddrs = %q", got)
	}
	if got := strings.Join(config.Reflectors, ","); got != "198.51.100.10:33434,198.51.100.11:33434" {
		t.Fatalf("Reflectors = %q", got)
	}
	if len(config.Bootstrap) != 1 || config.Bootstrap[0].ID != "node-b" {
		t.Fatalf("Bootstrap = %#v", config.Bootstrap)
	}
}

func TestParseConfigYAMLGossipSection(t *testing.T) {
	config := defaultAppConfig()
	input := `
gossip:
  init:
    managed_zone: node-a.catofes.
    key_path: /var/lib/higgs/identity.key.json
  peer_id: node-a.catofes.
  listen_addr: 0.0.0.0:33434
  max_datagram_bytes: 1200
  max_sync_zones: 16
  max_sync_records: 1024
  advertise_addrs:
    - 203.0.113.10:33434
  endpoint_discovery: all
  publish_endpoints: false
  reflectors: auto
  reflector_interval: 5m
  reflector_timeout: 3s
  endpoint_ttl: 1h
  endpoint_grace: 10m
  endpoint_source_order:
    - bootstrap
    - advertise
  filter_private_ipv4: false
  bootstrap:
    - id: node-b.catofes.
      addr: 203.0.113.20:33434
`
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	normalizeAppConfig(config)
	if config.ManagedZone.String() != "node-a.catofes." {
		t.Fatalf("ManagedZone = %q", config.ManagedZone)
	}
	if config.Identity.KeyPath != "/var/lib/higgs/identity.key.json" {
		t.Fatalf("Identity.KeyPath = %q", config.Identity.KeyPath)
	}
	if config.PeerID != "node-a.catofes." || config.ListenAddr != "0.0.0.0:33434" {
		t.Fatalf("peer/listen = %q/%q", config.PeerID, config.ListenAddr)
	}
	if len(config.Bootstrap) != 1 || config.Bootstrap[0].ID != "node-b.catofes." || config.Bootstrap[0].Addr != "203.0.113.20:33434" {
		t.Fatalf("Bootstrap = %#v", config.Bootstrap)
	}
	if config.MaxMessageBytes != 1200 || config.MaxSyncZones != 16 || config.MaxSyncRecords != 1024 {
		t.Fatalf("sync limits = %d/%d/%d", config.MaxMessageBytes, config.MaxSyncZones, config.MaxSyncRecords)
	}
	if got := strings.Join(config.AdvertiseAddrs, ","); got != "203.0.113.10:33434" {
		t.Fatalf("AdvertiseAddrs = %q", got)
	}
	if len(config.Reflectors) != len(gossip.DefaultPublicIPReflectors()) {
		t.Fatalf("Reflectors = %d, want auto preset", len(config.Reflectors))
	}
	if config.ReflectorInterval != 5*time.Minute || config.ReflectorTimeout != 3*time.Second {
		t.Fatalf("reflector timers = %s/%s", config.ReflectorInterval, config.ReflectorTimeout)
	}
	if config.EndpointTTL != time.Hour || config.EndpointGrace != 10*time.Minute {
		t.Fatalf("endpoint timers = %s/%s", config.EndpointTTL, config.EndpointGrace)
	}
	if config.EndpointDiscovery != "all" || config.PublishEndpoints || config.FilterPrivateIPv4 {
		t.Fatalf("endpoint flags = discovery:%q publish:%t filter:%t", config.EndpointDiscovery, config.PublishEndpoints, config.FilterPrivateIPv4)
	}
	if got := strings.Join(config.EndpointSourceOrder, ","); got != "bootstrap,advertise" {
		t.Fatalf("EndpointSourceOrder = %q", got)
	}
}

func TestParseConfigYAMLKeepsCommaSeparatedAdvertiseAddrs(t *testing.T) {
	config := defaultAppConfig()
	input := `gossip:
  advertise_addrs: 127.0.0.1:33434, 10.0.0.2:33434`
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	if got := strings.Join(config.AdvertiseAddrs, ","); got != "127.0.0.1:33434,10.0.0.2:33434" {
		t.Fatalf("AdvertiseAddrs = %q", got)
	}
}

func TestParseConfigYAMLExpandsAutoReflectors(t *testing.T) {
	config := defaultAppConfig()
	input := `gossip:
  reflectors: auto, https://custom.example/ip`
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	if len(config.Reflectors) != len(gossip.DefaultPublicIPReflectors())+1 {
		t.Fatalf("Reflectors = %d, want custom plus defaults", len(config.Reflectors))
	}
	if config.Reflectors[len(config.Reflectors)-1] != "https://custom.example/ip" {
		t.Fatalf("last reflector = %q, want custom", config.Reflectors[len(config.Reflectors)-1])
	}
}

func TestParseConfigYAMLRejectsUnknownFields(t *testing.T) {
	config := defaultAppConfig()
	if err := parseConfigYAML("unknown: true\n", config); err == nil {
		t.Fatalf("parseConfigYAML should reject unknown config fields")
	}
}

func TestParseConfigYAMLRejectsLegacyTopLevelGossipFields(t *testing.T) {
	for _, input := range []string{
		"managed_zone: node-a.catofes.\n",
		"identity:\n  key_path: keys/node-a.json\n",
		"peer_id: node-a\n",
		"listen_addr: 127.0.0.1:0\n",
		"bootstrap:\n  - id: node-b\n    addr: 127.0.0.1:33435\n",
		"max_datagram_bytes: 1200\n",
		"advertise_addrs:\n  - 203.0.113.10:33434\n",
		"endpoint_discovery: all\n",
		"publish_endpoints: false\n",
		"filter_private_ipv4: false\n",
	} {
		config := defaultAppConfig()
		if err := parseConfigYAML(input, config); err == nil {
			t.Fatalf("parseConfigYAML(%q) should reject legacy top-level gossip field", input)
		}
	}
}

func TestParseConfigYAMLRejectsExplicitZeroLimits(t *testing.T) {
	for _, input := range []string{
		"gossip:\n  listen_port: 0\n",
		"gossip:\n  max_datagram_bytes: 0\n",
		"gossip:\n  max_sync_zones: 0\n",
		"gossip:\n  max_sync_records: 0\n",
	} {
		config := defaultAppConfig()
		if err := parseConfigYAML(input, config); err == nil {
			t.Fatalf("parseConfigYAML(%q) should reject explicit zero", input)
		}
	}
}

func TestRuntimeCachesConfigForStateIO(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	dataDir := filepath.Join(dir, "data")
	statePath := filepath.Join(dataDir, "higgs.db")

	state, _ := buildTestNetworkState(t)
	rootKey, err := rootPublicKey(state.Network)
	if err != nil {
		t.Fatalf("rootPublicKey: %v", err)
	}
	writeRuntimeConfig(t, configPath, dataDir, rootKey, nil)
	t.Setenv("HIGGS_CONFIG", configPath)

	rt, err := NewRuntime()
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	if err := saveStateAt(statePath, state); err != nil {
		t.Fatalf("saveStateAt: %v", err)
	}

	wrongRoot := make(ed25519.PublicKey, ed25519.PublicKeySize)
	for i := range wrongRoot {
		wrongRoot[i] = byte(255 - i)
	}
	writeRuntimeConfig(t, configPath, dataDir, wrongRoot, nil)

	if _, err := rt.LoadState(); err != nil {
		t.Fatalf("cached runtime LoadState should keep original trusted root: %v", err)
	}
	if _, err := loadState(); err == nil {
		t.Fatalf("loadState should observe updated config and reject mismatched root")
	}
}

func TestRuntimeStatePathOverride(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	configDataDir := filepath.Join(dir, "config-data")
	overridePath := filepath.Join(dir, "override", "state.db")
	writeRuntimeConfig(t, configPath, configDataDir, nil, nil)
	t.Setenv("HIGGS_CONFIG", configPath)
	t.Setenv("HIGGS_STATE", overridePath)

	rt, err := NewRuntime()
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	if rt.StatePath != overridePath {
		t.Fatalf("StatePath = %q, want override %q", rt.StatePath, overridePath)
	}
}

func TestRuntimeSyncConfigDerivesLimitsAndDefaults(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	writeRuntimeConfig(t, configPath, filepath.Join(dir, "data"), nil, map[string]string{
		"max_datagram_bytes": "4096",
		"max_sync_zones":     "8",
		"max_sync_records":   "64",
		"log.level":          "debug",
		"log.mode":           "stderr+file",
		"log.file":           filepath.Join(dir, "higgs.log"),
	})
	t.Setenv("HIGGS_CONFIG", configPath)

	rt, err := NewRuntime()
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	state, _ := buildTestNetworkState(t)
	config, err := rt.SyncConfig(state)
	if err != nil {
		t.Fatalf("SyncConfig: %v", err)
	}
	if config.PeerID != string(state.ManagedZone) {
		t.Fatalf("PeerID = %q, want managed zone default %q", config.PeerID, state.ManagedZone)
	}
	limits := syncLimits(config)
	if limits.MaxBytes != 4096 || limits.MaxZones != 8 || limits.MaxRecords != 64 {
		t.Fatalf("limits = %#v, want 4096/8/64", limits)
	}
	if !debugLogEnabled(config) {
		t.Fatalf("config log.level=debug should enable debug logs")
	}
	if config.LogMode != "stderr+file" || config.LogFile != filepath.Join(dir, "higgs.log") {
		t.Fatalf("log output config = mode %q file %q, want stderr+file/%s", config.LogMode, config.LogFile, filepath.Join(dir, "higgs.log"))
	}
	t.Setenv("HIGGS_LOG_LEVEL", "info")
	if debugLogEnabled(config) {
		t.Fatalf("HIGGS_LOG_LEVEL should override config log.level")
	}
	t.Setenv("HIGGS_LOG_LEVEL", "debug")
	config.LogLevel = "info"
	if !debugLogEnabled(config) {
		t.Fatalf("HIGGS_LOG_LEVEL=debug should enable debug logs")
	}
}

func TestVerifyConfiguredRootTrustAt(t *testing.T) {
	state, _ := buildTestNetworkState(t)
	rootKey, err := rootPublicKey(state.Network)
	if err != nil {
		t.Fatalf("rootPublicKey: %v", err)
	}
	if err := verifyConfiguredRootTrustAt(state.Network, rootKey); err != nil {
		t.Fatalf("verifyConfiguredRootTrustAt(valid): %v", err)
	}

	wrongRoot := make(ed25519.PublicKey, ed25519.PublicKeySize)
	for i := range wrongRoot {
		wrongRoot[i] = byte(i + 1)
	}
	if err := verifyConfiguredRootTrustAt(state.Network, wrongRoot); err == nil {
		t.Fatalf("verifyConfiguredRootTrustAt should reject mismatched root")
	}
	if err := verifyConfiguredRootTrustAt(state.Network, nil); err != nil {
		t.Fatalf("verifyConfiguredRootTrustAt(nil): %v", err)
	}
}

func TestParseConfigYAMLTunnelAddressBlock(t *testing.T) {
	config := defaultAppConfig()
	input := `
overlays:
  - name: ipsec-main
    provider: strongswan
    tunnel_address:
      mode: derived-link-local
      family: ipv6
`
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	normalizeAppConfig(config)
	if len(config.IPsec.LinkGroups) != 1 {
		t.Fatalf("LinkGroups len = %d, want 1", len(config.IPsec.LinkGroups))
	}
	group := config.IPsec.LinkGroups[0]
	if group.TunnelAddressSpec.Mode != ipsec.TunnelAddressDerivedLinkLocal || group.TunnelAddressSpec.Family != ipsec.FamilyIPv6 {
		t.Fatalf("tunnel address spec = %+v", group.TunnelAddressSpec)
	}
}

func TestParseConfigYAMLDerivedPool(t *testing.T) {
	config := defaultAppConfig()
	input := `
overlays:
  - name: ipsec-main
    provider: strongswan
    tunnel_address:
      mode: derived-pool
      family: ipv4
      pool: 10.44.0.0/24
`
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	normalizeAppConfig(config)
	group := config.IPsec.LinkGroups[0]
	if group.TunnelAddressSpec.Mode != ipsec.TunnelAddressDerivedPool || group.TunnelAddressSpec.Family != ipsec.FamilyIPv4 {
		t.Fatalf("tunnel address spec = %+v", group.TunnelAddressSpec)
	}
	if group.TunnelAddressSpec.Pool.String() != "10.44.0.0/24" {
		t.Fatalf("pool = %s", group.TunnelAddressSpec.Pool)
	}
}

func TestParseConfigYAMLLegacyTunnelAddressPoolStillWorks(t *testing.T) {
	config := defaultAppConfig()
	input := `
overlays:
  - name: ipsec-main
    provider: strongswan
    tunnel_address_pool: fd00:1234::/64
`
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	normalizeAppConfig(config)
	group := config.IPsec.LinkGroups[0]
	if group.TunnelAddressPool.String() != "fd00:1234::/64" {
		t.Fatalf("legacy pool = %s", group.TunnelAddressPool)
	}
	normalized := group.Normalized()
	if normalized.TunnelAddressSpec.Mode != ipsec.TunnelAddressSequentialPool {
		t.Fatalf("legacy did not map to sequential-pool: %+v", normalized.TunnelAddressSpec)
	}
	if normalized.TunnelAddressSpec.Pool != netip.MustParsePrefix("fd00:1234::/64") {
		t.Fatalf("sequential pool = %s", normalized.TunnelAddressSpec.Pool)
	}
}

func TestParseConfigYAMLRejectsMixedTunnelAddressConfig(t *testing.T) {
	config := defaultAppConfig()
	input := `
overlays:
  - name: ipsec-main
    provider: strongswan
    tunnel_address_pool: fd00:1234::/64
    tunnel_address:
      mode: derived-link-local
`
	if err := parseConfigYAML(input, config); err == nil {
		t.Fatalf("parseConfigYAML should reject mixed tunnel address config")
	}
}

func TestParseConfigYAMLRejectsInvalidTunnelAddressMode(t *testing.T) {
	config := defaultAppConfig()
	input := `
overlays:
  - name: ipsec-main
    provider: strongswan
    tunnel_address:
      mode: magic
`
	if err := parseConfigYAML(input, config); err == nil {
		t.Fatalf("parseConfigYAML should reject invalid tunnel_address.mode")
	}
}

func TestParseConfigYAMLRejectsInvalidTunnelAddressFamily(t *testing.T) {
	config := defaultAppConfig()
	input := `
overlays:
  - name: ipsec-main
    provider: strongswan
    tunnel_address:
      family: ipx
`
	if err := parseConfigYAML(input, config); err == nil {
		t.Fatalf("parseConfigYAML should reject invalid tunnel_address.family")
	}
}

func TestParseConfigYAMLRejectsMismatchedTunnelAddressPoolFamily(t *testing.T) {
	config := defaultAppConfig()
	input := `
overlays:
  - name: ipsec-main
    provider: strongswan
    tunnel_address:
      mode: derived-pool
      family: ipv4
      pool: fd00:1234::/64
`
	if err := parseConfigYAML(input, config); err == nil {
		t.Fatalf("parseConfigYAML should reject mismatched family/pool")
	}
}

func TestParseConfigYAMLIPsecPortRotation(t *testing.T) {
	config := defaultAppConfig()
	input := `
ipsec:
  port_mode: range
  port_range:
    from: 30000
    to: 30099
  port_rotate_interval: 24h
  port_previous_grace: 2h
`
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	normalizeAppConfig(config)
	if config.IPsec.PortMode != ipsec.PortModeRange {
		t.Fatalf("PortMode = %q, want range", config.IPsec.PortMode)
	}
	if config.IPsec.PortRange.From != 30000 || config.IPsec.PortRange.To != 30099 {
		t.Fatalf("PortRange = %+v", config.IPsec.PortRange)
	}
	if config.IPsec.PortRotateInterval != 24*time.Hour {
		t.Fatalf("PortRotateInterval = %s", config.IPsec.PortRotateInterval)
	}
	if config.IPsec.PortPreviousGrace != 2*time.Hour {
		t.Fatalf("PortPreviousGrace = %s", config.IPsec.PortPreviousGrace)
	}
}

func TestDefaultIPsecPortPreviousGraceIsLongerThanRotateRetention(t *testing.T) {
	config := defaultAppConfig()
	if config.IPsec.PortPreviousGrace != 2*time.Hour {
		t.Fatalf("default PortPreviousGrace = %s, want 2h", config.IPsec.PortPreviousGrace)
	}
}

func TestParseConfigYAMLRejectsPortGraceShorterThanRotateRetention(t *testing.T) {
	config := defaultAppConfig()
	input := `
ipsec:
  port_previous_grace: 10m
overlays:
  - name: ipsec-main
    reconcile:
      rotate_retention: 1h
`
	err := parseConfigYAML(input, config)
	if err == nil {
		t.Fatalf("parseConfigYAML unexpectedly succeeded")
	}
	if !strings.Contains(err.Error(), "ipsec.port_previous_grace") {
		t.Fatalf("error = %v", err)
	}
}

func TestParseConfigYAMLRejectsInvalidPortMode(t *testing.T) {
	config := defaultAppConfig()
	input := `
ipsec:
  port_mode: dynamic
`
	if err := parseConfigYAML(input, config); err == nil {
		t.Fatalf("parseConfigYAML should reject invalid port_mode")
	}
}

func TestParseConfigYAMLRejectsInvalidPortRange(t *testing.T) {
	config := defaultAppConfig()
	input := `
ipsec:
  port_mode: range
  port_range:
    from: 40000
    to: 30000
`
	if err := parseConfigYAML(input, config); err == nil {
		t.Fatalf("parseConfigYAML should reject invalid port_range")
	}
}

func writeRuntimeConfig(t *testing.T, path string, dataDir string, rootKey ed25519.PublicKey, extra map[string]string) {
	t.Helper()
	var lines []string
	lines = append(lines, "data_dir: "+dataDir)
	lines = append(lines, "gossip:")
	lines = append(lines, "  listen_addr: 127.0.0.1:0")
	if len(rootKey) > 0 {
		lines = append(lines, "trusted_root_public_key: "+hex.EncodeToString(rootKey))
	}
	for _, key := range []string{"max_datagram_bytes", "max_sync_zones", "max_sync_records"} {
		if value := extra[key]; value != "" {
			lines = append(lines, "  "+key+": "+value)
		}
	}
	if value := extra["log.level"]; value != "" || extra["log.mode"] != "" {
		lines = append(lines, "log:")
		if mode := extra["log.mode"]; mode != "" {
			lines = append(lines, "  mode: "+mode)
			if file := extra["log.file"]; file != "" {
				lines = append(lines, "  file: "+file)
			}
		}
		if value != "" {
			lines = append(lines, "  level: "+value)
		}
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(config): %v", err)
	}
}

func TestParseConfigYAMLRoutingInstances(t *testing.T) {
	config := defaultAppConfig()
	input := `
overlay:
  default_netns:
    kind: name
    name: h2
    create: true
netns:
  default:
    kind: name
    name: h2
    create: true
routing:
  instances:
    - id: main
      netns: h2
      provider: bird
      mode: external
      control_socket: /run/higgs/bird-main.ctl
      pid_file: /run/higgs/bird-main.pid
      config_file: /etc/higgs/bird-main.conf
      table: "254"
      metric_base: 150
      metric_staged: 250
      metric_draining: 550
      ecmp: false
      ecmp_limit: 8
      interface_pattern: hgs*
`
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	normalizeAppConfig(config)
	if len(config.Routing.Instances) != 1 {
		t.Fatalf("Routing.Instances len = %d, want 1", len(config.Routing.Instances))
	}
	inst := config.Routing.Instances[0]
	if inst.ID != "main" {
		t.Fatalf("inst.ID = %q, want main", inst.ID)
	}
	if inst.NetNS != "h2" {
		t.Fatalf("inst.NetNS = %q, want h2", inst.NetNS)
	}
	if !inst.Enabled {
		t.Fatalf("inst.Enabled = false, want true")
	}
	if inst.Protocol != "bird" {
		t.Fatalf("inst.Protocol = %q, want bird", inst.Protocol)
	}
	if inst.Mode != ipsec.RoutingModeExternal {
		t.Fatalf("inst.Mode = %q, want external", inst.Mode)
	}
	if inst.ControlSocket != "/run/higgs/bird-main.ctl" {
		t.Fatalf("inst.ControlSocket = %q", inst.ControlSocket)
	}
	if inst.PIDFile != "/run/higgs/bird-main.pid" {
		t.Fatalf("inst.PIDFile = %q", inst.PIDFile)
	}
	if inst.ConfigFile != "/etc/higgs/bird-main.conf" {
		t.Fatalf("inst.ConfigFile = %q", inst.ConfigFile)
	}
	if inst.TableID != "254" {
		t.Fatalf("inst.TableID = %q, want 254", inst.TableID)
	}
	if inst.MetricBase != 150 {
		t.Fatalf("inst.MetricBase = %d, want 150", inst.MetricBase)
	}
	if inst.MetricStaged != 250 {
		t.Fatalf("inst.MetricStaged = %d, want 250", inst.MetricStaged)
	}
	if inst.MetricDraining != 550 {
		t.Fatalf("inst.MetricDraining = %d, want 550", inst.MetricDraining)
	}
	if inst.ECMP {
		t.Fatalf("inst.ECMP = true, want false")
	}
	if inst.ECMPLimit != 8 {
		t.Fatalf("inst.ECMPLimit = %d, want 8", inst.ECMPLimit)
	}
	if inst.InterfacePat != "hgs*" {
		t.Fatalf("inst.InterfacePat = %q, want hgs*", inst.InterfacePat)
	}
}

func TestParseConfigYAMLRoutingInstancesAcceptsLegacyProtocolAlias(t *testing.T) {
	config := defaultAppConfig()
	input := `
netns:
  default:
    kind: name
    name: h2
    create: true
routing:
  instances:
    - id: main
      netns: h2
      protocol: bird
`
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	normalizeAppConfig(config)
	if got := config.Routing.Instances[0].Protocol; got != "bird" {
		t.Fatalf("Protocol = %q, want bird", got)
	}
}

func TestParseConfigYAMLRoutingInstancesRejectsProviderProtocolConflict(t *testing.T) {
	config := defaultAppConfig()
	input := `
netns:
  default:
    kind: name
    name: h2
    create: true
routing:
  instances:
    - id: main
      netns: h2
      provider: bird
      protocol: babeld
`
	if err := parseConfigYAML(input, config); err == nil {
		t.Fatal("parseConfigYAML should reject conflicting routing provider/protocol")
	}
}

func TestParseConfigYAMLRoutingInstancesDefaults(t *testing.T) {
	config := defaultAppConfig()
	input := `
netns:
  default:
    kind: name
    name: h2
    create: true
routing:
  instances:
    - id: main
      netns: h2
`
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	normalizeAppConfig(config)
	if len(config.Routing.Instances) != 1 {
		t.Fatalf("Routing.Instances len = %d, want 1", len(config.Routing.Instances))
	}
	inst := config.Routing.Instances[0]
	if inst.Mode != ipsec.RoutingModeManaged {
		t.Fatalf("inst.Mode = %q, want managed", inst.Mode)
	}
	if inst.Protocol != "bird" {
		t.Fatalf("inst.Protocol = %q, want bird", inst.Protocol)
	}
	if inst.TableID != "main" {
		t.Fatalf("inst.TableID = %q, want main", inst.TableID)
	}
	if inst.MetricBase != 100 {
		t.Fatalf("inst.MetricBase = %d, want 100", inst.MetricBase)
	}
	if inst.MetricStaged != 200 {
		t.Fatalf("inst.MetricStaged = %d, want 200", inst.MetricStaged)
	}
	if inst.MetricDraining != 500 {
		t.Fatalf("inst.MetricDraining = %d, want 500", inst.MetricDraining)
	}
	if !inst.ECMP {
		t.Fatalf("inst.ECMP = false, want true")
	}
	if inst.ECMPLimit != 16 {
		t.Fatalf("inst.ECMPLimit = %d, want 16", inst.ECMPLimit)
	}
	if inst.InterfacePat != "hgs*" {
		t.Fatalf("inst.InterfacePat = %q, want hgs*", inst.InterfacePat)
	}
}

func TestParseConfigYAMLRoutingInstanceDisabled(t *testing.T) {
	config := defaultAppConfig()
	input := `
netns:
  default:
    kind: name
    name: h2
    create: true
routing:
  instances:
    - id: main
      netns: h2
      disabled: true
`
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	normalizeAppConfig(config)
	if len(config.Routing.Instances) != 1 {
		t.Fatalf("Routing.Instances len = %d, want 1", len(config.Routing.Instances))
	}
	if config.Routing.Instances[0].Enabled {
		t.Fatalf("routing instance should be disabled")
	}
}

func TestParseConfigYAMLRejectsConflictingEnabledDisabled(t *testing.T) {
	config := defaultAppConfig()
	input := `
netns:
  default:
    kind: name
    name: h2
    create: true
routing:
  instances:
    - id: main
      netns: h2
      enabled: true
      disabled: true
`
	if err := parseConfigYAML(input, config); err == nil {
		t.Fatal("parseConfigYAML should reject conflicting enabled/disabled")
	}
}

func TestParseConfigYAMLEndpointDiscovery(t *testing.T) {
	config := defaultAppConfig()
	input := `
gossip:
  endpoint_discovery: loopback_only
  endpoint_source_order:
    - bootstrap
    - advertise
`
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	normalizeAppConfig(config)
	if config.EndpointDiscovery != "loopback_only" {
		t.Fatalf("EndpointDiscovery = %q, want loopback_only", config.EndpointDiscovery)
	}
	if len(config.EndpointSourceOrder) != 2 || config.EndpointSourceOrder[0] != "bootstrap" || config.EndpointSourceOrder[1] != "advertise" {
		t.Fatalf("EndpointSourceOrder = %v, want [bootstrap advertise]", config.EndpointSourceOrder)
	}
}

func TestParseConfigYAMLInvalidEndpointSourceOrderIgnored(t *testing.T) {
	config := defaultAppConfig()
	input := `
gossip:
  endpoint_source_order:
    - bootstrap
    - unknown
    - advertise
    - bootstrap
`
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	normalizeAppConfig(config)
	if len(config.EndpointSourceOrder) != 2 || config.EndpointSourceOrder[0] != "bootstrap" || config.EndpointSourceOrder[1] != "advertise" {
		t.Fatalf("EndpointSourceOrder = %v, want [bootstrap advertise]", config.EndpointSourceOrder)
	}
}
