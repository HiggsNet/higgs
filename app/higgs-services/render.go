package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

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
	Image     string                              `yaml:"image"`
	Restart   string                              `yaml:"restart"`
	Networks  map[string]composeServiceAttachment `yaml:"networks"`
	Command   []string                            `yaml:"command,omitempty"`
	Volumes   []string                            `yaml:"volumes,omitempty"`
	DependsOn []string                            `yaml:"depends_on,omitempty"`
}

type composeServiceAttachment struct {
	IPv4Address string `yaml:"ipv4_address,omitempty"`
	IPv6Address string `yaml:"ipv6_address,omitempty"`
}

func renderArtifacts(manifest resolvedManifest) error {
	if err := renderNetworkCompose(manifest); err != nil {
		return err
	}
	if err := renderSOCKS5Compose(manifest, manifest.SOCKS5); err != nil {
		return err
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(filepath.Join(manifest.OutputDir, "resolved.json"), append(data, '\n'), 0o644)
}

func renderNetworkCompose(manifest resolvedManifest) error {
	file := composeFile{Name: "higgs-networks", Networks: map[string]composeNetwork{}}
	for _, id := range sortedKeys(manifest.Networks) {
		network := manifest.Networks[id]
		configs := make([]composeNetworkIPAMConfig, 0, 2)
		if network.IPv4 != nil {
			configs = append(configs, composeNetworkIPAMConfig{Subnet: network.IPv4.Subnet, IPRange: network.IPv4.IPRange, Gateway: network.IPv4.Gateway})
		}
		if network.IPv6 != nil {
			configs = append(configs, composeNetworkIPAMConfig{Subnet: network.IPv6.Subnet, IPRange: network.IPv6.IPRange, Gateway: network.IPv6.Gateway})
		}
		file.Networks[id] = composeNetwork{
			Name: network.Name, Driver: "bridge", EnableIPv6: network.IPv6 != nil,
			IPAM: &composeNetworkIPAM{Driver: "default", Config: configs},
		}
	}
	return writeYAML(filepath.Join(manifest.OutputDir, "networks", "docker-compose.yml"), file)
}

func renderSOCKS5Compose(manifest resolvedManifest, service resolvedSOCKS5) error {
	networks := map[string]composeNetwork{}
	socksNetworks := map[string]composeServiceAttachment{}
	dnsNetworks := map[string]composeServiceAttachment{}
	h2Networks := map[string]composeServiceAttachment{}
	for _, id := range sortedKeys(service.Networks) {
		network := manifest.Networks[id]
		roles := service.Networks[id]
		networks[id] = composeNetwork{Name: network.Name, External: true}
		socksNetworks[id] = attachmentForAddress(roles.SOCKS)
		dnsNetworks[id] = attachmentForAddress(roles.DNS)
		h2Networks[id] = attachmentForAddress(roles.H2)
	}
	file := composeFile{
		Name:     "higgs-socks5",
		Networks: networks,
		Services: map[string]composeService{
			"socks": {
				Image: manifest.Images.Gost, Restart: "unless-stopped", Networks: socksNetworks,
				Command: []string{"-L", fmt.Sprintf("socks5://[::]:%d?dns=dns:53", service.Port)}, DependsOn: []string{"dns"},
			},
			"dns": {
				Image: manifest.Images.SmartDNS, Restart: "unless-stopped", Networks: dnsNetworks,
				Volumes: []string{"./config/smartdns.conf:/etc/smartdns/smartdns.conf:ro"},
			},
			"h2": {
				Image: manifest.Images.Gost, Restart: "unless-stopped", Networks: h2Networks,
				Command: []string{"-L", fmt.Sprintf("http://[::]:%d?dns=dns:53", service.Port)}, DependsOn: []string{"dns"},
			},
		},
	}
	dir := filepath.Join(manifest.OutputDir, "socks5")
	if err := writeYAML(filepath.Join(dir, "docker-compose.yml"), file); err != nil {
		return err
	}
	if err := atomicWrite(filepath.Join(dir, "config", "smartdns.conf"), []byte("bind [::]:53\ncache-size 4096\nserver 8.8.8.8\nserver 1.1.1.1\ndualstack-ip-selection yes\n"), 0o644); err != nil {
		return err
	}
	data, err := json.MarshalIndent(renderedSOCKS5Lock{resolvedSOCKS5: service, ManagedZone: manifest.ManagedZone}, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(filepath.Join(dir, "resolved.json"), append(data, '\n'), 0o644)
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
	data, err := yaml.Marshal(value)
	if err != nil {
		return err
	}
	return atomicWrite(path, data, 0o644)
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".higgs-services-*")
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
