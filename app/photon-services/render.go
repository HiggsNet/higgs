package main

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type composeFile struct {
	Name     string                    `yaml:"name"`
	Services map[string]composeService `yaml:"services,omitempty"`
	Networks map[string]composeNetwork `yaml:"networks"`
}

type composeNetwork struct {
	Name       string              `yaml:"name"`
	External   bool                `yaml:"external,omitempty"`
	Driver     string              `yaml:"driver,omitempty"`
	DriverOpts map[string]string   `yaml:"driver_opts,omitempty"`
	EnableIPv6 bool                `yaml:"enable_ipv6,omitempty"`
	IPAM       *composeNetworkIPAM `yaml:"ipam,omitempty"`
}

type composeNetworkIPAM struct {
	Driver string                     `yaml:"driver"`
	Config []composeNetworkIPAMConfig `yaml:"config"`
}

type composeNetworkIPAMConfig struct {
	Subnet  string `yaml:"subnet"`
	IPRange string `yaml:"ip_range"`
	Gateway string `yaml:"gateway"`
}

type composeService struct {
	Image    string                              `yaml:"image"`
	Restart  string                              `yaml:"restart,omitempty"`
	Scale    *int                                `yaml:"scale,omitempty"`
	Networks map[string]composeServiceAttachment `yaml:"networks"`
	Command  []string                            `yaml:"command,omitempty"`
	Volumes  []string                            `yaml:"volumes,omitempty"`
}

type composeServiceAttachment struct {
	IPv4Address string `yaml:"ipv4_address,omitempty"`
	IPv6Address string `yaml:"ipv6_address,omitempty"`
}

type gostConfig struct {
	Services  []gostService  `yaml:"services"`
	Resolvers []gostResolver `yaml:"resolvers"`
}

type gostService struct {
	Name     string         `yaml:"name"`
	Addr     string         `yaml:"addr"`
	Resolver string         `yaml:"resolver"`
	Handler  gostPluginType `yaml:"handler"`
	Listener gostPluginType `yaml:"listener"`
}

type gostPluginType struct {
	Type     string         `yaml:"type"`
	Auth     *gostAuth      `yaml:"auth,omitempty"`
	Metadata map[string]any `yaml:"metadata,omitempty"`
}

type gostAuth struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type gostResolver struct {
	Name        string           `yaml:"name"`
	Nameservers []gostNameserver `yaml:"nameservers"`
}

type gostNameserver struct {
	Addr   string `yaml:"addr"`
	Prefer string `yaml:"prefer,omitempty"`
	Only   string `yaml:"only,omitempty"`
}

func renderArtifacts(manifest resolvedManifest) error {
	if err := renderNetworkCompose(manifest); err != nil {
		return err
	}
	if manifest.SOCKS5.configured() {
		if err := renderSOCKS5Compose(manifest, manifest.SOCKS5); err != nil {
			return err
		}
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(filepath.Join(manifest.OutputDir, "resolved.json"), append(data, '\n'), 0o644)
}

func renderNetworkCompose(manifest resolvedManifest) error {
	scaleZero := 0
	// Compose rejects projects without a selected service before creating their
	// networks. A scale-zero owner keeps the networks under an independent
	// Compose lifecycle without leaving a placeholder container running.
	file := composeFile{
		Name:     "photon-networks",
		Networks: map[string]composeNetwork{},
		Services: map[string]composeService{
			"owner": {
				Image:    manifest.Images.Gost,
				Scale:    &scaleZero,
				Networks: map[string]composeServiceAttachment{},
			},
		},
	}
	for _, id := range sortedKeys(manifest.Networks) {
		network := manifest.Networks[id]
		serviceAddress := publishedServiceAddress(manifest.SOCKS5, id)
		configs := make([]composeNetworkIPAMConfig, 0, 2)
		if network.IPv4 != nil {
			configs = append(configs, composeNetworkIPAMConfig{Subnet: network.IPv4.Subnet, IPRange: network.IPv4.IPRange, Gateway: network.IPv4.Gateway})
		}
		if network.IPv6 != nil {
			configs = append(configs, composeNetworkIPAMConfig{Subnet: network.IPv6.Subnet, IPRange: network.IPv6.IPRange, Gateway: network.IPv6.Gateway})
		}
		file.Networks[id] = composeNetwork{
			Name: network.Name, Driver: "bridge", EnableIPv6: network.IPv6 != nil,
			DriverOpts: composeBridgeDriverOpts(network.TrustedHostInterfaces, serviceAddress),
			IPAM:       &composeNetworkIPAM{Driver: "default", Config: configs},
		}
		file.Services["owner"].Networks[id] = composeServiceAttachment{}
	}
	return writeYAML(filepath.Join(manifest.OutputDir, "networks", "docker-compose.yml"), file)
}

func publishedServiceAddress(service resolvedSOCKS5, network string) string {
	for _, endpoint := range service.Endpoints {
		if endpoint.Network == network {
			return endpoint.Address
		}
	}
	return ""
}

func renderSOCKS5Compose(manifest resolvedManifest, service resolvedSOCKS5) error {
	networks := map[string]composeNetwork{}
	socksNetworks := map[string]composeServiceAttachment{}
	h2Networks := map[string]composeServiceAttachment{}
	for _, id := range sortedKeys(service.Networks) {
		network := manifest.Networks[id]
		roles := service.Networks[id]
		networks[id] = composeNetwork{Name: network.Name, External: true}
		socksNetworks[id] = attachmentForAddress(roles.SOCKS)
		h2Networks[id] = attachmentForAddress(roles.H2)
	}
	file := composeFile{
		Name:     "photon-socks5",
		Networks: networks,
		Services: map[string]composeService{
			"socks": {
				Image: manifest.Images.Gost, Restart: "unless-stopped", Networks: socksNetworks,
				Command: []string{"-C", "/etc/gost/gost.yaml"},
				Volumes: []string{"./config/socks.yaml:/etc/gost/gost.yaml:ro"},
			},
			"h2": {
				Image: manifest.Images.Gost, Restart: "unless-stopped", Networks: h2Networks,
				Command: []string{"-C", "/etc/gost/gost.yaml"},
				Volumes: []string{"./config/h2.yaml:/etc/gost/gost.yaml:ro"},
			},
		},
	}
	dir := filepath.Join(manifest.OutputDir, "socks5")
	if err := writeYAML(filepath.Join(dir, "docker-compose.yml"), file); err != nil {
		return err
	}
	if err := renderGOSTConfig(filepath.Join(dir, "config", "socks.yaml"), "socks", "socks5", service.Port, service.Resolver, nil); err != nil {
		return err
	}
	if err := renderGOSTConfig(filepath.Join(dir, "config", "h2.yaml"), "h2", "http", service.Port, service.Resolver, &service.HTTPAuth); err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(dir, "config", "smartdns.conf")); err != nil && !os.IsNotExist(err) {
		return err
	}
	data, err := json.MarshalIndent(renderedSOCKS5Lock{resolvedSOCKS5: service, ManagedZone: manifest.ManagedZone}, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(filepath.Join(dir, "resolved.json"), append(data, '\n'), 0o644)
}

func renderGOSTConfig(path, name, handler string, port uint16, resolver resolverConfig, auth *proxyAuthConfig) error {
	nameservers := make([]gostNameserver, 0, len(resolver.Servers))
	for _, server := range resolver.Servers {
		nameserver := gostNameserver{Addr: server}
		switch resolver.Mode {
		case "ipv4_first":
			nameserver.Prefer = "ipv4"
		case "ipv6_first":
			nameserver.Prefer = "ipv6"
		case "ipv4_only":
			nameserver.Only = "ipv4"
		case "ipv6_only":
			nameserver.Only = "ipv6"
		}
		nameservers = append(nameservers, nameserver)
	}
	handlerConfig := gostPluginType{Type: handler}
	if handler == "socks5" {
		handlerConfig.Metadata = map[string]any{"udp": true, "udpBufferSize": 65535}
	}
	if auth != nil {
		handlerConfig.Auth = &gostAuth{Username: auth.Username, Password: auth.Password}
	}
	config := gostConfig{
		Services: []gostService{{
			Name: name, Addr: fmt.Sprintf("[::]:%d", port), Resolver: "service-resolver",
			Handler: handlerConfig, Listener: gostPluginType{Type: "tcp"},
		}},
		Resolvers: []gostResolver{{Name: "service-resolver", Nameservers: nameservers}},
	}
	return writeYAMLMode(path, config, 0o600)
}

func composeBridgeDriverOpts(interfaces []string, serviceAddress string) map[string]string {
	options := map[string]string{}
	if len(interfaces) > 0 {
		options["com.docker.network.bridge.trusted_host_interfaces"] = strings.Join(interfaces, ":")
	}
	if address, err := netip.ParseAddr(serviceAddress); err == nil {
		family := "ipv6"
		if address.Is4() {
			family = "ipv4"
		}
		options["com.docker.network.bridge.gateway_mode_"+family] = "nat-unprotected"
	}
	if len(options) == 0 {
		return nil
	}
	return options
}

func attachmentForAddress(address string) composeServiceAttachment {
	if len(address) != 0 && address[0] != '[' && !containsColon(address) {
		return composeServiceAttachment{IPv4Address: address}
	}
	return composeServiceAttachment{IPv6Address: address}
}

func containsColon(value string) bool {
	for i := range value {
		if value[i] == ':' {
			return true
		}
	}
	return false
}

func writeYAML(path string, value any) error {
	return writeYAMLMode(path, value, 0o644)
}

func writeYAMLMode(path string, value any, mode os.FileMode) error {
	data, err := yaml.Marshal(value)
	if err != nil {
		return err
	}
	return atomicWrite(path, data, mode)
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".photon-services-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
