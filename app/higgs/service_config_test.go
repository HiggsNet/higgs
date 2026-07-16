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
routing:
  instances:
    - id: main
      upstream: {}
services:
  compose:
    output_dir: /var/lib/higgs/services/networks
  networks:
    main:
      ipv4: "local;172.30.0.0/24;172.30.0.128/28;172.30.0.1"
      ipv6: "auto;::/112;::100/120;::1"
  instances:
    - id: egress-cn
      type: socks5
      region: cn-east
      network: main
      address: ::20
      port: 1080
      allow_zones:
        - clients.catofes.
        - '*.partners.catofes.'
        - '*.'
      compose:
        output_dir: /etc/higgs/services/egress-cn
        project_name: higgs-egress-cn
        image: ghcr.io/example/socks5:stable
        container_name: higgs-egress-cn
`
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	if len(config.Services.Networks) != 1 || len(config.Services.Instances) != 1 {
		t.Fatalf("services = %#v", config.Services)
	}
	network := config.Services.Networks[0]
	if network.ID != "main" || network.Name != "higgs-main" || network.Driver != "bridge" || network.RoutingInstance != "main" {
		t.Fatalf("network = %#v", network)
	}
	if network.IPv4 == nil || network.IPv4.Source != serviceNetworkSourceLocal || network.IPv6 == nil || network.IPv6.Source != serviceNetworkSourceAuto || !network.IPv6.Subnet.Relative {
		t.Fatalf("network ipv6 = %#v", network.IPv6)
	}
	if config.Services.Compose.OutputDir != "/var/lib/higgs/services/networks" || config.Services.Compose.ProjectName != "higgs-networks" {
		t.Fatalf("network compose = %#v", config.Services.Compose)
	}
	service := config.Services.Instances[0]
	if service.ID != "egress-cn" || service.Type != "socks5" || service.Region != "cn-east" || service.Network != "main" {
		t.Fatalf("service identity = %#v", service)
	}
	if service.Address.Raw != "::20" || !service.Address.Relative || service.Port != 1080 {
		t.Fatalf("service endpoint = %#v:%d", service.Address, service.Port)
	}
	if len(service.AllowZones) != 3 || service.AllowZones[0].String() != "clients.catofes." || service.AllowZones[1].String() != "*.partners.catofes." || service.AllowZones[2].String() != "*." {
		t.Fatalf("allow zones = %#v", service.AllowZones)
	}
	if service.Compose.ProjectName != "higgs-egress-cn" || service.Compose.Image == "" {
		t.Fatalf("compose = %#v", service.Compose)
	}
}

func TestParseServiceConfigRejectsInvalidInputs(t *testing.T) {
	routing := "routing:\n  instances:\n    - id: main\n      upstream: {}\n"
	network := "services:\n  networks:\n    - id: svcnet\n      name: higgs-services\n      routing_instance: main\n      ipv6: {subnet: 'fd42:1::/112', gateway: 'fd42:1::1'}\n"
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{"unknown routing instance", "services:\n  networks:\n    - id: svcnet\n      name: higgs-services\n      routing_instance: missing\n      ipv6: {subnet: 'fd42:1::/112', gateway: 'fd42:1::1'}\n", `unknown routing_instance "missing"`},
		{"routing without upstream", "routing:\n  instances:\n    - id: main\nservices:\n  networks:\n    - id: svcnet\n      name: higgs-services\n      routing_instance: main\n      ipv6: {subnet: 'fd42:1::/112', gateway: 'fd42:1::1'}\n", "must be enabled with static upstream"},
		{"range outside subnet", routing + "services:\n  networks:\n    svcnet:\n      routing_instance: main\n      ipv6: 'local;fd42:1::/112;fd42:2::/120;fd42:1::1'\n", "dynamic range"},
		{"bad descriptor", routing + "services:\n  networks:\n    svcnet:\n      routing_instance: main\n      ipv6: 'auto;::/112;::1'\n", "descriptor must contain"},
		{"unknown source", routing + "services:\n  networks:\n    svcnet:\n      routing_instance: main\n      ipv6: 'allocation:socks-cn;::/112;::100/120;::1'\n", "unsupported source"},
		{"duplicate id", routing + network + "  instances:\n    - {id: egress, type: socks5, region: cn, network: svcnet, address: 'fd42:1::20', port: 1080}\n    - {id: egress, type: socks5, region: us, network: svcnet, address: 'fd42:1::21', port: 1080}\n", "duplicate service id"},
		{"unknown type", routing + network + "  instances:\n    - {id: egress, type: http, region: cn, network: svcnet, address: 'fd42:1::20', port: 1080}\n", `type must be "socks5"`},
		{"unknown network", routing + network + "  instances:\n    - {id: egress, type: socks5, region: cn, network: missing, address: 'fd42:1::20', port: 1080}\n", `unknown network "missing"`},
		{"missing region", routing + network + "  instances:\n    - {id: egress, type: socks5, network: svcnet, address: 'fd42:1::20', port: 1080}\n", "region is required"},
		{"zero port", routing + network + "  instances:\n    - {id: egress, type: socks5, region: cn, network: svcnet, address: 'fd42:1::20'}\n", "service port"},
		{"invalid allow zone", routing + network + "  instances:\n    - {id: egress, type: socks5, region: cn, network: svcnet, address: 'fd42:1::20', port: 1080, allow_zones: [invalid]}\n", "invalid allow_zones"},
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

func TestParseServiceConfigLegacyNetworkSequence(t *testing.T) {
	config := defaultAppConfig()
	input := `
routing:
  instances:
    - id: main
      upstream: {}
services:
  networks:
    - id: svcnet
      name: old-name
      routing_instance: main
      ipv6:
        subnet: fd42:1::/112
        ip_range: fd42:1::100/120
        gateway: fd42:1::1
      compose:
        output_dir: /legacy/networks
        project_name: old-project
`
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	network := config.Services.Networks[0]
	if network.Name != "old-name" || network.IPv6 == nil || network.IPv6.Source != serviceNetworkSourceLegacy {
		t.Fatalf("legacy network = %#v", network)
	}
	if config.Services.Compose.OutputDir != "/legacy/networks" || config.Services.Compose.ProjectName != "old-project" {
		t.Fatalf("legacy compose = %#v", config.Services.Compose)
	}
}
