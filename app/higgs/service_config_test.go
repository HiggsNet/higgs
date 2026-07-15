package main

import (
	"strings"
	"testing"
)

func TestParseServiceConfig(t *testing.T) {
	config := defaultAppConfig()
	input := `
netns:
  default:
    kind: name
    name: h2
    create: true
services:
  - id: egress-cn
    type: socks5
    region: cn-east
    netns: default
    address: fd42:1::20
    port: 1080
    allow_zones:
      - clients.catofes.
    compose:
      output_dir: /etc/higgs/services/egress-cn
      project_name: higgs-egress-cn
      image: ghcr.io/example/socks5:stable
      container_name: higgs-egress-cn
`
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	if len(config.Services) != 1 {
		t.Fatalf("services = %#v", config.Services)
	}
	service := config.Services[0]
	if service.ID != "egress-cn" || service.Type != "socks5" || service.Region != "cn-east" || service.NetNS != "default" {
		t.Fatalf("service identity = %#v", service)
	}
	if service.Address.String() != "fd42:1::20" || service.Port != 1080 {
		t.Fatalf("service endpoint = %s:%d", service.Address, service.Port)
	}
	if len(service.AllowZones) != 1 || service.AllowZones[0] != "clients.catofes." {
		t.Fatalf("allow zones = %#v", service.AllowZones)
	}
	if service.Compose.ProjectName != "higgs-egress-cn" || service.Compose.Image == "" {
		t.Fatalf("compose = %#v", service.Compose)
	}
}

func TestParseServiceConfigRejectsInvalidInputs(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{"duplicate id", "services:\n  - {id: egress, type: socks5, region: cn, address: 'fd42::1', port: 1080}\n  - {id: egress, type: socks5, region: us, address: 'fd42::2', port: 1080}\n", "duplicate service id"},
		{"unknown type", "services:\n  - {id: egress, type: http, region: cn, address: 'fd42::1', port: 1080}\n", `type must be "socks5"`},
		{"unknown netns", "services:\n  - {id: egress, type: socks5, region: cn, netns: missing, address: 'fd42::1', port: 1080}\n", `unknown netns "missing"`},
		{"missing region", "services:\n  - {id: egress, type: socks5, address: 'fd42::1', port: 1080}\n", "region is required"},
		{"zero port", "services:\n  - {id: egress, type: socks5, region: cn, address: 'fd42::1'}\n", "service port"},
		{"invalid allow zone", "services:\n  - {id: egress, type: socks5, region: cn, address: 'fd42::1', port: 1080, allow_zones: [invalid]}\n", "invalid allow_zones"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			config := defaultAppConfig()
			err := parseConfigYAML(tc.yaml, config)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want substring %q", err, tc.want)
			}
		})
	}
}
