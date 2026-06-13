package main

import (
	"crypto/ed25519"
	"encoding/hex"
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
peer_id: node-a
listen_port: 33434
max_message_bytes: 32768
max_sync_zones: 8
max_sync_records: 512
endpoint_grace: 2m
reflector_timeout: 1500ms
publish_endpoints: false
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
overlay:
  default_netns:
    kind: name
    name: h2
    create: true
overlays:
  - name: ipsec-main
    provider: strongswan
    default_path_mode: family-redundant
    direction: outbound
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

func TestParseConfigYAMLKeepsCommaSeparatedAdvertiseAddrs(t *testing.T) {
	config := defaultAppConfig()
	input := `advertise_addrs: 127.0.0.1:33434, 10.0.0.2:33434`
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	if got := strings.Join(config.AdvertiseAddrs, ","); got != "127.0.0.1:33434,10.0.0.2:33434" {
		t.Fatalf("AdvertiseAddrs = %q", got)
	}
}

func TestParseConfigYAMLExpandsAutoReflectors(t *testing.T) {
	config := defaultAppConfig()
	input := `reflectors: auto, https://custom.example/ip`
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

func TestParseConfigYAMLRejectsExplicitZeroLimits(t *testing.T) {
	for _, input := range []string{
		"listen_port: 0\n",
		"max_message_bytes: 0\n",
		"max_sync_zones: 0\n",
		"max_sync_records: 0\n",
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
		"max_message_bytes": "4096",
		"max_sync_zones":    "8",
		"max_sync_records":  "64",
		"log_level":         "debug",
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
		t.Fatalf("config log_level=debug should enable debug logs")
	}
	t.Setenv("HIGGS_LOG_LEVEL", "info")
	if debugLogEnabled(config) {
		t.Fatalf("HIGGS_LOG_LEVEL should override config log_level")
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
	lines = append(lines, "listen_addr: 127.0.0.1:0")
	if len(rootKey) > 0 {
		lines = append(lines, "trusted_root_public_key: "+hex.EncodeToString(rootKey))
	}
	for _, key := range []string{"max_message_bytes", "max_sync_zones", "max_sync_records", "log_level"} {
		if value := extra[key]; value != "" {
			lines = append(lines, key+": "+value)
		}
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(config): %v", err)
	}
}

func TestParseConfigYAMLOverlayRouting(t *testing.T) {
	config := defaultAppConfig()
	input := `
overlay:
  default_netns:
    kind: name
    name: h2
    create: true
overlays:
  - name: ipsec-main
    provider: strongswan
    routing:
      enabled: true
      protocol: bird
      mode: external
      control_socket: /run/higgs/bird-ipsec-main.ctl
      pid_file: /run/higgs/bird-ipsec-main.pid
      config_file: /etc/higgs/bird-ipsec-main.conf
      router_id: 16909060
      table: 254
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
	if len(config.IPsec.LinkGroups) != 1 {
		t.Fatalf("LinkGroups len = %d, want 1", len(config.IPsec.LinkGroups))
	}
	group := config.IPsec.LinkGroups[0]
	if !group.Routing.Enabled {
		t.Fatalf("Routing.Enabled = false, want true")
	}
	if group.Routing.Protocol != "bird" {
		t.Fatalf("Routing.Protocol = %q, want bird", group.Routing.Protocol)
	}
	if group.Routing.Mode != ipsec.RoutingModeExternal {
		t.Fatalf("Routing.Mode = %q, want external", group.Routing.Mode)
	}
	if group.Routing.ControlSocket != "/run/higgs/bird-ipsec-main.ctl" {
		t.Fatalf("Routing.ControlSocket = %q", group.Routing.ControlSocket)
	}
	if group.Routing.PIDFile != "/run/higgs/bird-ipsec-main.pid" {
		t.Fatalf("Routing.PIDFile = %q", group.Routing.PIDFile)
	}
	if group.Routing.ConfigFile != "/etc/higgs/bird-ipsec-main.conf" {
		t.Fatalf("Routing.ConfigFile = %q", group.Routing.ConfigFile)
	}
	if group.Routing.RouterID != 16909060 {
		t.Fatalf("Routing.RouterID = %d, want 16909060", group.Routing.RouterID)
	}
	if group.Routing.TableID != "254" {
		t.Fatalf("Routing.TableID = %q, want 254", group.Routing.TableID)
	}
	if group.Routing.MetricBase != 150 {
		t.Fatalf("Routing.MetricBase = %d, want 150", group.Routing.MetricBase)
	}
	if group.Routing.MetricStaged != 250 {
		t.Fatalf("Routing.MetricStaged = %d, want 250", group.Routing.MetricStaged)
	}
	if group.Routing.MetricDraining != 550 {
		t.Fatalf("Routing.MetricDraining = %d, want 550", group.Routing.MetricDraining)
	}
	if group.Routing.ECMP {
		t.Fatalf("Routing.ECMP = true, want false")
	}
	if group.Routing.ECMPLimit != 8 {
		t.Fatalf("Routing.ECMPLimit = %d, want 8", group.Routing.ECMPLimit)
	}
	if group.Routing.InterfacePattern != "hgs*" {
		t.Fatalf("Routing.InterfacePattern = %q, want hgs*", group.Routing.InterfacePattern)
	}
	// NetNS should be inherited from the link group default.
	if group.Routing.NetNS.Kind != ipsec.NetNSName || group.Routing.NetNS.Name != "h2" {
		t.Fatalf("Routing.NetNS = %+v, want h2 name netns", group.Routing.NetNS)
	}
}

func TestParseConfigYAMLOverlayRoutingDefaults(t *testing.T) {
	config := defaultAppConfig()
	input := `
overlay:
  default_netns:
    kind: name
    name: h2
    create: true
overlays:
  - name: ipsec-main
    provider: strongswan
    routing:
      enabled: true
`
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	normalizeAppConfig(config)
	group := config.IPsec.LinkGroups[0]
	if group.Routing.Mode != ipsec.RoutingModeManaged {
		t.Fatalf("Routing.Mode = %q, want managed", group.Routing.Mode)
	}
	if group.Routing.Protocol != "bird" {
		t.Fatalf("Routing.Protocol = %q, want bird", group.Routing.Protocol)
	}
	if group.Routing.TableID != "main" {
		t.Fatalf("Routing.TableID = %q, want main", group.Routing.TableID)
	}
	if group.Routing.MetricBase != 100 {
		t.Fatalf("Routing.MetricBase = %d, want 100", group.Routing.MetricBase)
	}
	if group.Routing.MetricStaged != 200 {
		t.Fatalf("Routing.MetricStaged = %d, want 200", group.Routing.MetricStaged)
	}
	if group.Routing.MetricDraining != 500 {
		t.Fatalf("Routing.MetricDraining = %d, want 500", group.Routing.MetricDraining)
	}
	if !group.Routing.ECMP {
		t.Fatalf("Routing.ECMP = false, want true")
	}
	if group.Routing.ECMPLimit != 16 {
		t.Fatalf("Routing.ECMPLimit = %d, want 16", group.Routing.ECMPLimit)
	}
	if group.Routing.InterfacePattern != "hgs*" {
		t.Fatalf("Routing.InterfacePattern = %q, want hgs*", group.Routing.InterfacePattern)
	}
}
