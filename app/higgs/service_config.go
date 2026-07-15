package main

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/Catofes/higgs/pkg/core/zone"
	higgsservice "github.com/Catofes/higgs/pkg/service"
)

// serviceConfig is local desired state. AllowZones and Compose never enter a
// signed service record.
type serviceConfig struct {
	ID         string
	Type       string
	Region     string
	NetNS      string
	Address    netip.Addr
	Port       uint16
	AllowZones []zone.ZonePath
	Compose    serviceComposeConfig
}

type serviceComposeConfig struct {
	OutputDir     string
	ProjectName   string
	Image         string
	ContainerName string
}

type serviceConfigYAML struct {
	ID         string                   `yaml:"id"`
	Type       string                   `yaml:"type"`
	Region     string                   `yaml:"region"`
	NetNS      string                   `yaml:"netns"`
	Address    string                   `yaml:"address"`
	Port       uint16                   `yaml:"port"`
	AllowZones configStringList         `yaml:"allow_zones"`
	Compose    serviceComposeConfigYAML `yaml:"compose"`
}

type serviceComposeConfigYAML struct {
	OutputDir     string `yaml:"output_dir"`
	ProjectName   string `yaml:"project_name"`
	Image         string `yaml:"image"`
	ContainerName string `yaml:"container_name"`
}

func parseServiceConfigs(values []serviceConfigYAML, netnsCfg netnsConfig) ([]serviceConfig, error) {
	services := make([]serviceConfig, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for i, value := range values {
		parsed, err := parseServiceConfig(value, netnsCfg)
		if err != nil {
			return nil, fmt.Errorf("services[%d]: %w", i, err)
		}
		if _, exists := seen[parsed.ID]; exists {
			return nil, fmt.Errorf("services[%d]: duplicate service id %q", i, parsed.ID)
		}
		seen[parsed.ID] = struct{}{}
		services = append(services, parsed)
	}
	return services, nil
}

func parseServiceConfig(value serviceConfigYAML, netnsCfg netnsConfig) (serviceConfig, error) {
	id, err := higgsservice.NormalizeID(value.ID)
	if err != nil {
		return serviceConfig{}, err
	}
	serviceType := strings.ToLower(strings.TrimSpace(value.Type))
	if serviceType != higgsservice.TypeSOCKS5 {
		return serviceConfig{}, fmt.Errorf("type must be %q", higgsservice.TypeSOCKS5)
	}
	region := strings.TrimSpace(value.Region)
	if region == "" {
		return serviceConfig{}, fmt.Errorf("region is required")
	}
	netnsName := strings.TrimSpace(value.NetNS)
	if netnsName == "" {
		netnsName = netnsCfg.Default
		if netnsName == "" {
			netnsName = "default"
		}
	}
	if _, ok := netnsCfg.Names[netnsName]; !ok {
		return serviceConfig{}, fmt.Errorf("unknown netns %q", netnsName)
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(value.Address))
	if err != nil {
		return serviceConfig{}, fmt.Errorf("invalid address %q: %w", value.Address, err)
	}
	public := higgsservice.SOCKS5Record{Type: serviceType, Region: region, Address: addr.String(), Port: value.Port}
	if err := public.Validate(); err != nil {
		return serviceConfig{}, err
	}
	allowZones := make([]zone.ZonePath, 0, len(value.AllowZones))
	seenZones := make(map[zone.ZonePath]struct{}, len(value.AllowZones))
	for _, raw := range value.AllowZones {
		path := zone.ZonePath(strings.TrimSpace(raw))
		if !path.Valid() {
			return serviceConfig{}, fmt.Errorf("invalid allow_zones entry %q", raw)
		}
		if _, exists := seenZones[path]; exists {
			continue
		}
		seenZones[path] = struct{}{}
		allowZones = append(allowZones, path)
	}
	return serviceConfig{
		ID:         id,
		Type:       serviceType,
		Region:     region,
		NetNS:      netnsName,
		Address:    addr,
		Port:       value.Port,
		AllowZones: allowZones,
		Compose: serviceComposeConfig{
			OutputDir:     strings.TrimSpace(value.Compose.OutputDir),
			ProjectName:   strings.TrimSpace(value.Compose.ProjectName),
			Image:         strings.TrimSpace(value.Compose.Image),
			ContainerName: strings.TrimSpace(value.Compose.ContainerName),
		},
	}, nil
}
