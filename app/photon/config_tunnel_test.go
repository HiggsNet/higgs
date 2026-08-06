package main

import (
	"github.com/Catofes/photon/pkg/transport/ipsec"
	"net/netip"
	"testing"
)

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
