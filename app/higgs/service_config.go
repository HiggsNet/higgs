package main

import (
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"

	higgsservice "github.com/Catofes/higgs/pkg/service"
	"github.com/Catofes/higgs/pkg/transport/ipsec"
	"gopkg.in/yaml.v3"
)

const (
	serviceNetworkSourceLocal      = "local"
	serviceNetworkSourceAuto       = "auto"
	serviceNetworkSourceAssignment = "assignment"
	serviceNetworkSourceShared     = "shared"
	serviceNetworkSourceLegacy     = "legacy"
)

// servicesConfig separates the single host-side Docker network artifact from
// service containers. Network address plans are resolved against live IPAM
// assignments by `higgs service validate`, rather than frozen at config load.
type servicesConfig struct {
	Compose   serviceNetworkComposeConfig
	Networks  []serviceNetworkConfig
	Instances []serviceInstanceConfig
}

type serviceNetworkConfig struct {
	ID              string
	Name            string
	Driver          string
	RoutingInstance string
	IPv4            *serviceNetworkAddressPlan
	IPv6            *serviceNetworkAddressPlan
}

type serviceNetworkAddressPlan struct {
	Raw        string
	Family     int
	Source     string
	Assignment netip.Prefix
	Subnet     servicePrefixExpr
	IPRange    servicePrefixExpr
	Gateway    serviceAddrExpr
}

type servicePrefixExpr struct {
	Prefix   netip.Prefix
	Relative bool
}

type serviceAddrExpr struct {
	Addr     netip.Addr
	Relative bool
}

type serviceAddressSpec struct {
	Raw      string
	Addr     netip.Addr
	Relative bool
}

type serviceNetworkIPAMConfig struct {
	Subnet  netip.Prefix
	IPRange netip.Prefix
	Gateway netip.Addr
}

type serviceNetworkComposeConfig struct {
	OutputDir   string
	ProjectName string
}

// serviceInstanceConfig is local desired state. AllowZones, Network and
// Compose never enter a signed service record.
type serviceInstanceConfig struct {
	ID         string
	Type       string
	Region     string
	Network    string
	Address    serviceAddressSpec
	Port       uint16
	AllowZones []higgsservice.ZoneSelector
	Compose    serviceComposeConfig
}

type serviceComposeConfig struct {
	OutputDir     string
	ProjectName   string
	Image         string
	ContainerName string
}

type servicesConfigYAML struct {
	Compose   serviceNetworkComposeConfigYAML `yaml:"compose"`
	Networks  serviceNetworksYAML             `yaml:"networks"`
	Instances []serviceInstanceConfigYAML     `yaml:"instances"`
}

// serviceNetworksYAML accepts the preferred map form and the Phase 8.1 legacy
// sequence form. Keeping the conversion here leaves the internal model simple.
type serviceNetworksYAML struct {
	Items []serviceNetworkConfigYAML
}

type serviceNetworkConfigYAML struct {
	ID              string
	Name            string
	Driver          string
	RoutingInstance string
	IPv4            string
	IPv6            string
	LegacyIPv6      *serviceNetworkIPAMConfigYAML
	LegacyCompose   serviceNetworkComposeConfigYAML
}

type serviceNetworkMapValueYAML struct {
	RoutingInstance string `yaml:"routing_instance"`
	IPv4            string `yaml:"ipv4"`
	IPv6            string `yaml:"ipv6"`
}

type legacyServiceNetworkConfigYAML struct {
	ID              string                          `yaml:"id"`
	Name            string                          `yaml:"name"`
	Driver          string                          `yaml:"driver"`
	RoutingInstance string                          `yaml:"routing_instance"`
	IPv6            serviceNetworkIPAMConfigYAML    `yaml:"ipv6"`
	Compose         serviceNetworkComposeConfigYAML `yaml:"compose"`
}

func (value *serviceNetworksYAML) UnmarshalYAML(node *yaml.Node) error {
	if node == nil || node.Kind == 0 {
		return nil
	}
	switch node.Kind {
	case yaml.MappingNode:
		value.Items = make([]serviceNetworkConfigYAML, 0, len(node.Content)/2)
		for i := 0; i < len(node.Content); i += 2 {
			id := strings.TrimSpace(node.Content[i].Value)
			body := node.Content[i+1]
			item := serviceNetworkConfigYAML{ID: id}
			if body.Kind == yaml.ScalarNode {
				if err := body.Decode(&item.IPv6); err != nil {
					return fmt.Errorf("network %q: %w", id, err)
				}
			} else {
				var decoded serviceNetworkMapValueYAML
				if err := body.Decode(&decoded); err != nil {
					return fmt.Errorf("network %q: %w", id, err)
				}
				item.RoutingInstance = decoded.RoutingInstance
				item.IPv4 = decoded.IPv4
				item.IPv6 = decoded.IPv6
			}
			value.Items = append(value.Items, item)
		}
		return nil
	case yaml.SequenceNode:
		var legacy []legacyServiceNetworkConfigYAML
		if err := node.Decode(&legacy); err != nil {
			return err
		}
		value.Items = make([]serviceNetworkConfigYAML, 0, len(legacy))
		for i := range legacy {
			item := legacy[i]
			value.Items = append(value.Items, serviceNetworkConfigYAML{
				ID: item.ID, Name: item.Name, Driver: item.Driver,
				RoutingInstance: item.RoutingInstance, LegacyIPv6: &item.IPv6,
				LegacyCompose: item.Compose,
			})
		}
		return nil
	default:
		return fmt.Errorf("must be a mapping or sequence")
	}
}

type serviceNetworkIPAMConfigYAML struct {
	Subnet  string `yaml:"subnet"`
	IPRange string `yaml:"ip_range"`
	Gateway string `yaml:"gateway"`
}

type serviceNetworkComposeConfigYAML struct {
	OutputDir   string `yaml:"output_dir"`
	ProjectName string `yaml:"project_name"`
}

type serviceInstanceConfigYAML struct {
	ID         string                   `yaml:"id"`
	Type       string                   `yaml:"type"`
	Region     string                   `yaml:"region"`
	Network    string                   `yaml:"network"`
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

func parseServicesConfig(value *servicesConfigYAML, routingCfg routingConfig, dataDir string) (servicesConfig, error) {
	if value == nil {
		return servicesConfig{}, nil
	}
	result := servicesConfig{
		Compose: serviceNetworkComposeConfig{
			OutputDir:   filepath.Join(dataDir, "services", "networks"),
			ProjectName: "higgs-networks",
		},
		Networks:  make([]serviceNetworkConfig, 0, len(value.Networks.Items)),
		Instances: make([]serviceInstanceConfig, 0, len(value.Instances)),
	}
	if output := strings.TrimSpace(value.Compose.OutputDir); output != "" {
		result.Compose.OutputDir = output
	}
	if project := strings.TrimSpace(value.Compose.ProjectName); project != "" {
		result.Compose.ProjectName = project
	}
	networks := make(map[string]serviceNetworkConfig, len(value.Networks.Items))
	networkNames := make(map[string]struct{}, len(value.Networks.Items))
	var legacyCompose *serviceNetworkComposeConfig
	for i, raw := range value.Networks.Items {
		parsed, err := parseServiceNetworkConfig(raw, routingCfg)
		if err != nil {
			return servicesConfig{}, fmt.Errorf("services.networks[%d]: %w", i, err)
		}
		if _, exists := networks[parsed.ID]; exists {
			return servicesConfig{}, fmt.Errorf("services.networks[%d]: duplicate network id %q", i, parsed.ID)
		}
		if _, exists := networkNames[parsed.Name]; exists {
			return servicesConfig{}, fmt.Errorf("services.networks[%d]: duplicate Docker network name %q", i, parsed.Name)
		}
		if raw.LegacyCompose.OutputDir != "" || raw.LegacyCompose.ProjectName != "" {
			legacy := serviceNetworkComposeConfig{OutputDir: strings.TrimSpace(raw.LegacyCompose.OutputDir), ProjectName: strings.TrimSpace(raw.LegacyCompose.ProjectName)}
			if legacyCompose != nil && *legacyCompose != legacy {
				return servicesConfig{}, fmt.Errorf("services.networks[%d]: legacy per-network compose settings conflict; move the shared settings to services.compose", i)
			}
			legacyCompose = &legacy
			if value.Compose.OutputDir != "" && legacy.OutputDir != "" && result.Compose.OutputDir != legacy.OutputDir {
				return servicesConfig{}, fmt.Errorf("services.networks[%d]: legacy compose.output_dir conflicts with services.compose.output_dir", i)
			}
			if value.Compose.ProjectName != "" && legacy.ProjectName != "" && result.Compose.ProjectName != legacy.ProjectName {
				return servicesConfig{}, fmt.Errorf("services.networks[%d]: legacy compose.project_name conflicts with services.compose.project_name", i)
			}
			if value.Compose.OutputDir == "" && legacy.OutputDir != "" {
				result.Compose.OutputDir = legacy.OutputDir
			}
			if value.Compose.ProjectName == "" && legacy.ProjectName != "" {
				result.Compose.ProjectName = legacy.ProjectName
			}
		}
		networks[parsed.ID] = parsed
		networkNames[parsed.Name] = struct{}{}
		result.Networks = append(result.Networks, parsed)
	}
	seenInstances := make(map[string]struct{}, len(value.Instances))
	for i, raw := range value.Instances {
		parsed, err := parseServiceInstanceConfig(raw, networks)
		if err != nil {
			return servicesConfig{}, fmt.Errorf("services.instances[%d]: %w", i, err)
		}
		if _, exists := seenInstances[parsed.ID]; exists {
			return servicesConfig{}, fmt.Errorf("services.instances[%d]: duplicate service id %q", i, parsed.ID)
		}
		seenInstances[parsed.ID] = struct{}{}
		result.Instances = append(result.Instances, parsed)
	}
	return result, nil
}

func parseServiceNetworkConfig(value serviceNetworkConfigYAML, routingCfg routingConfig) (serviceNetworkConfig, error) {
	id, err := higgsservice.NormalizeID(value.ID)
	if err != nil {
		return serviceNetworkConfig{}, err
	}
	name := strings.TrimSpace(value.Name)
	if name == "" {
		name = "higgs-" + id
	}
	driver := strings.ToLower(strings.TrimSpace(value.Driver))
	if driver == "" {
		driver = "bridge"
	}
	if driver != "bridge" {
		return serviceNetworkConfig{}, fmt.Errorf("driver must be %q", "bridge")
	}
	routingInstance := strings.TrimSpace(value.RoutingInstance)
	if routingInstance == "" {
		routingInstance = id
	}
	instance, ok := findRoutingInstance(routingCfg, routingInstance)
	if !ok {
		return serviceNetworkConfig{}, fmt.Errorf("unknown routing_instance %q", routingInstance)
	}
	if !instance.Enabled || instance.Upstream == nil || !instance.Upstream.Enabled || instance.Upstream.Mode != upstreamModeStatic {
		return serviceNetworkConfig{}, fmt.Errorf("routing_instance %q must be enabled with static upstream", routingInstance)
	}
	if instance.Upstream.ExternalNetns != "" && instance.Upstream.ExternalNetns != ipsec.NetNSHost {
		return serviceNetworkConfig{}, fmt.Errorf("routing_instance %q upstream external.netns must be host", routingInstance)
	}
	parsed := serviceNetworkConfig{ID: id, Name: name, Driver: driver, RoutingInstance: routingInstance}
	if strings.TrimSpace(value.IPv4) != "" {
		plan, err := parseServiceNetworkDescriptor(value.IPv4, 4)
		if err != nil {
			return serviceNetworkConfig{}, fmt.Errorf("ipv4: %w", err)
		}
		parsed.IPv4 = &plan
	}
	if strings.TrimSpace(value.IPv6) != "" {
		plan, err := parseServiceNetworkDescriptor(value.IPv6, 6)
		if err != nil {
			return serviceNetworkConfig{}, fmt.Errorf("ipv6: %w", err)
		}
		parsed.IPv6 = &plan
	}
	if value.LegacyIPv6 != nil {
		plan, err := parseLegacyServiceNetworkIPv6(*value.LegacyIPv6)
		if err != nil {
			return serviceNetworkConfig{}, fmt.Errorf("ipv6: %w", err)
		}
		parsed.IPv6 = &plan
	}
	if parsed.IPv4 == nil && parsed.IPv6 == nil {
		return serviceNetworkConfig{}, fmt.Errorf("at least one of ipv4 or ipv6 is required")
	}
	return parsed, nil
}

func parseServiceNetworkDescriptor(raw string, family int) (serviceNetworkAddressPlan, error) {
	parts := strings.Split(raw, ";")
	if len(parts) != 4 {
		return serviceNetworkAddressPlan{}, fmt.Errorf("descriptor must contain source;subnet;dynamic-range;gateway")
	}
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
		if parts[i] == "" {
			return serviceNetworkAddressPlan{}, fmt.Errorf("descriptor field %d is empty", i+1)
		}
	}
	plan := serviceNetworkAddressPlan{Raw: strings.TrimSpace(raw), Family: family}
	switch {
	case parts[0] == serviceNetworkSourceLocal:
		plan.Source = serviceNetworkSourceLocal
	case parts[0] == serviceNetworkSourceAuto:
		plan.Source = serviceNetworkSourceAuto
	case strings.HasPrefix(parts[0], serviceNetworkSourceAssignment+":"):
		plan.Source = serviceNetworkSourceAssignment
		assignment, err := parseServicePrefix(strings.TrimPrefix(parts[0], serviceNetworkSourceAssignment+":"), family, "assignment")
		if err != nil {
			return serviceNetworkAddressPlan{}, err
		}
		plan.Assignment = assignment
	case strings.HasPrefix(parts[0], serviceNetworkSourceShared+":"):
		plan.Source = serviceNetworkSourceShared
		assignment, err := parseServicePrefix(strings.TrimPrefix(parts[0], serviceNetworkSourceShared+":"), family, "shared assignment")
		if err != nil {
			return serviceNetworkAddressPlan{}, err
		}
		plan.Assignment = assignment
	default:
		return serviceNetworkAddressPlan{}, fmt.Errorf("unsupported source %q", parts[0])
	}
	var err error
	plan.Subnet.Prefix, err = parseServicePrefix(parts[1], family, "subnet")
	if err != nil {
		return serviceNetworkAddressPlan{}, err
	}
	plan.IPRange.Prefix, err = parseServicePrefix(parts[2], family, "dynamic range")
	if err != nil {
		return serviceNetworkAddressPlan{}, err
	}
	plan.Gateway.Addr, err = parseServiceAddr(parts[3], family, "gateway")
	if err != nil {
		return serviceNetworkAddressPlan{}, err
	}
	if plan.IPRange.Prefix.Bits() < plan.Subnet.Prefix.Bits() {
		return serviceNetworkAddressPlan{}, fmt.Errorf("dynamic range must not be larger than subnet")
	}
	if plan.Source == serviceNetworkSourceLocal {
		if !prefixContainsPrefix(plan.Subnet.Prefix, plan.IPRange.Prefix) {
			return serviceNetworkAddressPlan{}, fmt.Errorf("dynamic range %s must be contained by subnet %s", plan.IPRange.Prefix, plan.Subnet.Prefix)
		}
		if !plan.Subnet.Prefix.Contains(plan.Gateway.Addr) || plan.Gateway.Addr == plan.Subnet.Prefix.Addr() {
			return serviceNetworkAddressPlan{}, fmt.Errorf("gateway %s must be a usable address in subnet %s", plan.Gateway.Addr, plan.Subnet.Prefix)
		}
	} else if family == 6 {
		plan.Subnet.Relative = strings.HasPrefix(parts[1], "::")
		plan.IPRange.Relative = strings.HasPrefix(parts[2], "::")
		plan.Gateway.Relative = strings.HasPrefix(parts[3], "::")
	}
	return plan, nil
}

func parseLegacyServiceNetworkIPv6(value serviceNetworkIPAMConfigYAML) (serviceNetworkAddressPlan, error) {
	subnet, err := parseServicePrefix(value.Subnet, 6, "subnet")
	if err != nil {
		return serviceNetworkAddressPlan{}, err
	}
	var ipRange netip.Prefix
	if strings.TrimSpace(value.IPRange) != "" {
		ipRange, err = parseServicePrefix(value.IPRange, 6, "ip_range")
		if err != nil {
			return serviceNetworkAddressPlan{}, err
		}
		if !prefixContainsPrefix(subnet, ipRange) {
			return serviceNetworkAddressPlan{}, fmt.Errorf("ip_range %s must be contained by subnet %s", ipRange, subnet)
		}
	}
	gateway, err := parseServiceAddr(value.Gateway, 6, "gateway")
	if err != nil {
		return serviceNetworkAddressPlan{}, err
	}
	if !subnet.Contains(gateway) || gateway == subnet.Addr() {
		return serviceNetworkAddressPlan{}, fmt.Errorf("gateway %s must be a usable IPv6 address in subnet %s", gateway, subnet)
	}
	return serviceNetworkAddressPlan{
		Family: 6, Source: serviceNetworkSourceLegacy,
		Subnet: servicePrefixExpr{Prefix: subnet}, IPRange: servicePrefixExpr{Prefix: ipRange}, Gateway: serviceAddrExpr{Addr: gateway},
	}, nil
}

func parseServicePrefix(raw string, family int, field string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid %s %q: %w", field, raw, err)
	}
	if (family == 4) != prefix.Addr().Is4() || prefix.Addr().Is4In6() {
		return netip.Prefix{}, fmt.Errorf("%s %s must be IPv%d", field, prefix, family)
	}
	if prefix != prefix.Masked() {
		return netip.Prefix{}, fmt.Errorf("%s %s is not canonical; use %s", field, prefix, prefix.Masked())
	}
	return prefix, nil
}

func parseServiceAddr(raw string, family int, field string) (netip.Addr, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil {
		return netip.Addr{}, fmt.Errorf("invalid %s %q: %w", field, raw, err)
	}
	if (family == 4) != addr.Is4() || addr.Is4In6() {
		return netip.Addr{}, fmt.Errorf("%s %s must be IPv%d", field, addr, family)
	}
	return addr, nil
}

func parseServiceInstanceConfig(value serviceInstanceConfigYAML, networks map[string]serviceNetworkConfig) (serviceInstanceConfig, error) {
	id, err := higgsservice.NormalizeID(value.ID)
	if err != nil {
		return serviceInstanceConfig{}, err
	}
	serviceType := strings.ToLower(strings.TrimSpace(value.Type))
	if serviceType != higgsservice.TypeSOCKS5 {
		return serviceInstanceConfig{}, fmt.Errorf("type must be %q", higgsservice.TypeSOCKS5)
	}
	region := strings.TrimSpace(value.Region)
	if region == "" {
		return serviceInstanceConfig{}, fmt.Errorf("region is required")
	}
	if value.Port == 0 {
		return serviceInstanceConfig{}, fmt.Errorf("service port must be between 1 and 65535")
	}
	networkID, err := higgsservice.NormalizeID(value.Network)
	if err != nil {
		return serviceInstanceConfig{}, fmt.Errorf("network: %w", err)
	}
	if _, ok := networks[networkID]; !ok {
		return serviceInstanceConfig{}, fmt.Errorf("unknown network %q", networkID)
	}
	addressRaw := strings.TrimSpace(value.Address)
	addr, err := netip.ParseAddr(addressRaw)
	if err != nil {
		return serviceInstanceConfig{}, fmt.Errorf("invalid address %q: %w", value.Address, err)
	}
	address := serviceAddressSpec{Raw: addressRaw, Addr: addr, Relative: addr.Is6() && strings.HasPrefix(addressRaw, "::")}
	allowZones := make([]higgsservice.ZoneSelector, 0, len(value.AllowZones))
	seenZones := make(map[string]struct{}, len(value.AllowZones))
	for _, raw := range value.AllowZones {
		selector, err := higgsservice.ParseZoneSelector(raw)
		if err != nil {
			return serviceInstanceConfig{}, fmt.Errorf("invalid allow_zones entry %q: %w", raw, err)
		}
		canonical := selector.String()
		if _, exists := seenZones[canonical]; exists {
			continue
		}
		seenZones[canonical] = struct{}{}
		allowZones = append(allowZones, selector)
	}
	return serviceInstanceConfig{
		ID: id, Type: serviceType, Region: region, Network: networkID, Address: address, Port: value.Port, AllowZones: allowZones,
		Compose: serviceComposeConfig{
			OutputDir: strings.TrimSpace(value.Compose.OutputDir), ProjectName: strings.TrimSpace(value.Compose.ProjectName),
			Image: strings.TrimSpace(value.Compose.Image), ContainerName: strings.TrimSpace(value.Compose.ContainerName),
		},
	}, nil
}

func findRoutingInstance(config routingConfig, id string) (RoutingInstance, bool) {
	for _, instance := range config.Instances {
		if instance.ID == id {
			return instance, true
		}
	}
	return RoutingInstance{}, false
}

func prefixContainsPrefix(parent, child netip.Prefix) bool {
	return parent.IsValid() && child.IsValid() && parent.Addr().Is4() == child.Addr().Is4() && parent.Bits() <= child.Bits() && parent.Contains(child.Addr())
}
