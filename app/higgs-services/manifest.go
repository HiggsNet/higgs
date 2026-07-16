package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strings"

	higgsservice "github.com/Catofes/higgs/pkg/service"
	"gopkg.in/yaml.v3"
)

const (
	defaultOutputDir     = "/etc/higgs/services"
	defaultGostImage     = "ginuerzh/gost:2.11.5"
	defaultSmartDNSImage = "ghcr.io/higgsnet/smartdns:v1.0.4"
)

type manifest struct {
	Version   int                      `yaml:"version"`
	OutputDir string                   `yaml:"output_dir,omitempty"`
	Images    imageConfig              `yaml:"images,omitempty"`
	Networks  map[string]networkConfig `yaml:"networks"`
	SOCKS5    map[string]socks5Config  `yaml:"socks5"`
}

type imageConfig struct {
	Gost     string `yaml:"gost,omitempty"`
	SmartDNS string `yaml:"smartdns,omitempty"`
}

type networkConfig struct {
	IPv4 string `yaml:"ipv4,omitempty"`
	IPv6 string `yaml:"ipv6,omitempty"`
}

type socks5Config struct {
	Region     string            `yaml:"region"`
	Publish    string            `yaml:"publish"`
	Port       uint16            `yaml:"port,omitempty"`
	Networks   map[string]string `yaml:"networks"`
	AllowZones []string          `yaml:"allow_zones,omitempty"`
}

type runtimeAssignment struct {
	Prefix string `json:"prefix"`
	Source string `json:"source"`
	Shared bool   `json:"shared,omitempty"`
}

type resolvedManifest struct {
	OutputDir string                     `json:"output_dir"`
	Images    imageConfig                `json:"images"`
	Networks  map[string]resolvedNetwork `json:"networks"`
	SOCKS5    map[string]resolvedSOCKS5  `json:"socks5"`
}

type resolvedNetwork struct {
	Name string        `json:"name"`
	IPv4 *resolvedIPAM `json:"ipv4,omitempty"`
	IPv6 *resolvedIPAM `json:"ipv6,omitempty"`
}

type resolvedIPAM struct {
	Source     string `json:"source"`
	Assignment string `json:"assignment,omitempty"`
	Subnet     string `json:"subnet"`
	IPRange    string `json:"ip_range"`
	Gateway    string `json:"gateway"`
}

type resolvedSOCKS5 struct {
	Name       string                       `json:"name"`
	Region     string                       `json:"region"`
	Publish    string                       `json:"publish"`
	Address    string                       `json:"address"`
	Port       uint16                       `json:"port"`
	AllowZones []string                     `json:"allow_zones,omitempty"`
	Networks   map[string]resolvedRoleAddrs `json:"networks"`
	ConfigHash string                       `json:"config_hash"`
}

type resolvedRoleAddrs struct {
	SOCKS string `json:"socks"`
	DNS   string `json:"dns"`
	H2    string `json:"h2"`
}

func loadManifest(path string) (manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return manifest{}, err
	}
	var value manifest
	decoder := yaml.NewDecoder(strings.NewReader(string(data)))
	decoder.KnownFields(true)
	if err := decoder.Decode(&value); err != nil {
		return manifest{}, fmt.Errorf("decode %s: %w", path, err)
	}
	if value.Version == 0 {
		value.Version = 1
	}
	if value.Version != 1 {
		return manifest{}, fmt.Errorf("unsupported service manifest version %d", value.Version)
	}
	if value.OutputDir == "" {
		value.OutputDir = defaultOutputDir
	}
	if value.Images.Gost == "" {
		value.Images.Gost = defaultGostImage
	}
	if value.Images.SmartDNS == "" {
		value.Images.SmartDNS = defaultSmartDNSImage
	}
	if len(value.Networks) == 0 {
		return manifest{}, fmt.Errorf("networks is required")
	}
	if len(value.SOCKS5) == 0 {
		return manifest{}, fmt.Errorf("socks5 is required")
	}
	return value, nil
}

func resolveManifest(value manifest, rawAssignments []runtimeAssignment) (resolvedManifest, error) {
	assignments := make([]netip.Prefix, 0, len(rawAssignments))
	for _, raw := range rawAssignments {
		if raw.Shared {
			continue
		}
		prefix, err := netip.ParsePrefix(raw.Prefix)
		if err != nil || prefix != prefix.Masked() {
			return resolvedManifest{}, fmt.Errorf("invalid runtime assignment %q", raw.Prefix)
		}
		assignments = append(assignments, prefix)
	}
	result := resolvedManifest{OutputDir: value.OutputDir, Images: value.Images, Networks: map[string]resolvedNetwork{}, SOCKS5: map[string]resolvedSOCKS5{}}
	for name, configured := range value.Networks {
		id, err := higgsservice.NormalizeID(name)
		if err != nil {
			return resolvedManifest{}, fmt.Errorf("network name: %w", err)
		}
		if id != name {
			return resolvedManifest{}, fmt.Errorf("network name %q is not canonical; use %q", name, id)
		}
		network := resolvedNetwork{Name: "higgs-" + id}
		if configured.IPv4 != "" {
			resolved, err := resolveDescriptor(configured.IPv4, 4, assignments)
			if err != nil {
				return resolvedManifest{}, fmt.Errorf("network %s ipv4: %w", name, err)
			}
			network.IPv4 = &resolved
		}
		if configured.IPv6 != "" {
			resolved, err := resolveDescriptor(configured.IPv6, 6, assignments)
			if err != nil {
				return resolvedManifest{}, fmt.Errorf("network %s ipv6: %w", name, err)
			}
			network.IPv6 = &resolved
		}
		if network.IPv4 == nil && network.IPv6 == nil {
			return resolvedManifest{}, fmt.Errorf("network %s has no ipv4 or ipv6 plan", name)
		}
		for previousName, previous := range result.Networks {
			if network.IPv4 != nil && previous.IPv4 != nil && netip.MustParsePrefix(network.IPv4.Subnet).Overlaps(netip.MustParsePrefix(previous.IPv4.Subnet)) {
				return resolvedManifest{}, fmt.Errorf("network %s ipv4 subnet %s overlaps network %s subnet %s", name, network.IPv4.Subnet, previousName, previous.IPv4.Subnet)
			}
			if network.IPv6 != nil && previous.IPv6 != nil && netip.MustParsePrefix(network.IPv6.Subnet).Overlaps(netip.MustParsePrefix(previous.IPv6.Subnet)) {
				return resolvedManifest{}, fmt.Errorf("network %s ipv6 subnet %s overlaps network %s subnet %s", name, network.IPv6.Subnet, previousName, previous.IPv6.Subnet)
			}
		}
		result.Networks[name] = network
	}
	usedAddresses := map[string]string{}
	for name, configured := range value.SOCKS5 {
		id, err := higgsservice.NormalizeID(name)
		if err != nil {
			return resolvedManifest{}, fmt.Errorf("socks5 name: %w", err)
		}
		if id != name {
			return resolvedManifest{}, fmt.Errorf("socks5 name %q is not canonical; use %q", name, id)
		}
		if strings.TrimSpace(configured.Region) == "" {
			return resolvedManifest{}, fmt.Errorf("socks5 %s: region is required", name)
		}
		if configured.Port == 0 {
			configured.Port = 3128
		}
		if configured.Publish == "" {
			return resolvedManifest{}, fmt.Errorf("socks5 %s: publish network is required", name)
		}
		service := resolvedSOCKS5{Name: name, Region: configured.Region, Publish: configured.Publish, Port: configured.Port, Networks: map[string]resolvedRoleAddrs{}}
		for _, raw := range configured.AllowZones {
			selector, err := higgsservice.ParseZoneSelector(raw)
			if err != nil {
				return resolvedManifest{}, fmt.Errorf("socks5 %s allow_zones: %w", name, err)
			}
			service.AllowZones = append(service.AllowZones, selector.String())
		}
		for networkName, baseText := range configured.Networks {
			network, ok := result.Networks[networkName]
			if !ok {
				return resolvedManifest{}, fmt.Errorf("socks5 %s: unknown network %q", name, networkName)
			}
			base, familyIPAM, err := resolveServiceBase(baseText, network)
			if err != nil {
				return resolvedManifest{}, fmt.Errorf("socks5 %s network %s: %w", name, networkName, err)
			}
			roles, err := resolveRoleAddresses(base, *familyIPAM)
			if err != nil {
				return resolvedManifest{}, fmt.Errorf("socks5 %s network %s: %w", name, networkName, err)
			}
			for role, address := range map[string]string{"socks": roles.SOCKS, "dns": roles.DNS, "h2": roles.H2} {
				key := networkName + "/" + address
				if previous, exists := usedAddresses[key]; exists {
					return resolvedManifest{}, fmt.Errorf("socks5 %s %s address %s on network %s conflicts with %s", name, role, address, networkName, previous)
				}
				usedAddresses[key] = name + "/" + role
			}
			service.Networks[networkName] = roles
		}
		published, ok := service.Networks[configured.Publish]
		if !ok {
			return resolvedManifest{}, fmt.Errorf("socks5 %s: publish network %q is not attached", name, configured.Publish)
		}
		service.Address = published.SOCKS
		hashInput, _ := json.Marshal(struct {
			Name     string
			Config   socks5Config
			Networks map[string]resolvedNetwork
		}{name, configured, result.Networks})
		hash := sha256.Sum256(hashInput)
		service.ConfigHash = hex.EncodeToString(hash[:])
		result.SOCKS5[name] = service
	}
	return result, nil
}

func resolveDescriptor(raw string, family int, assignments []netip.Prefix) (resolvedIPAM, error) {
	parts := strings.Split(raw, ";")
	if len(parts) != 4 {
		return resolvedIPAM{}, fmt.Errorf("expected source;subnet;dynamic-range;gateway")
	}
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	source := parts[0]
	var base netip.Prefix
	switch {
	case source == "local":
	case source == "auto":
		var matches []netip.Prefix
		for _, assignment := range assignments {
			if addressFamily(assignment.Addr()) == family {
				matches = append(matches, assignment)
			}
		}
		if len(matches) != 1 {
			return resolvedIPAM{}, fmt.Errorf("auto requires exactly one non-shared IPv%d assignment, found %d", family, len(matches))
		}
		base = matches[0]
	case strings.HasPrefix(source, "assignment:"):
		wanted, err := parsePrefix(strings.TrimPrefix(source, "assignment:"), family)
		if err != nil {
			return resolvedIPAM{}, err
		}
		for _, assignment := range assignments {
			if assignment == wanted {
				base = assignment
				break
			}
		}
		if !base.IsValid() {
			return resolvedIPAM{}, fmt.Errorf("assignment %s is not active for this node", wanted)
		}
	default:
		return resolvedIPAM{}, fmt.Errorf("unsupported source %q", source)
	}
	subnet, err := resolvePrefix(parts[1], family, base)
	if err != nil {
		return resolvedIPAM{}, fmt.Errorf("subnet: %w", err)
	}
	ipRange, err := resolvePrefix(parts[2], family, base)
	if err != nil {
		return resolvedIPAM{}, fmt.Errorf("dynamic range: %w", err)
	}
	gateway, err := resolveAddr(parts[3], family, base)
	if err != nil {
		return resolvedIPAM{}, fmt.Errorf("gateway: %w", err)
	}
	if base.IsValid() && !containsPrefix(base, subnet) {
		return resolvedIPAM{}, fmt.Errorf("subnet %s is outside assignment %s", subnet, base)
	}
	if !containsPrefix(subnet, ipRange) {
		return resolvedIPAM{}, fmt.Errorf("dynamic range %s is outside subnet %s", ipRange, subnet)
	}
	if !subnet.Contains(gateway) || gateway == subnet.Addr() {
		return resolvedIPAM{}, fmt.Errorf("gateway %s is not usable in %s", gateway, subnet)
	}
	resolved := resolvedIPAM{Source: source, Subnet: subnet.String(), IPRange: ipRange.String(), Gateway: gateway.String()}
	if base.IsValid() {
		resolved.Assignment = base.String()
	}
	return resolved, nil
}

func resolveServiceBase(raw string, network resolvedNetwork) (netip.Addr, *resolvedIPAM, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil {
		return netip.Addr{}, nil, err
	}
	var ipam *resolvedIPAM
	if addr.Is4() {
		ipam = network.IPv4
	} else {
		ipam = network.IPv6
	}
	if ipam == nil {
		return netip.Addr{}, nil, fmt.Errorf("network has no matching address family")
	}
	subnet := netip.MustParsePrefix(ipam.Subnet)
	if addr.Is6() && strings.HasPrefix(strings.TrimSpace(raw), "::") {
		addr, err = addAddress(subnet.Addr(), addr)
		if err != nil {
			return netip.Addr{}, nil, err
		}
	}
	return addr, ipam, nil
}

func resolveRoleAddresses(base netip.Addr, ipam resolvedIPAM) (resolvedRoleAddrs, error) {
	subnet, dynamic := netip.MustParsePrefix(ipam.Subnet), netip.MustParsePrefix(ipam.IPRange)
	gateway := netip.MustParseAddr(ipam.Gateway)
	values := make([]netip.Addr, 3)
	for i := range values {
		addr, err := addSmallOffset(base, i)
		if err != nil {
			return resolvedRoleAddrs{}, err
		}
		if !subnet.Contains(addr) || addr == gateway || dynamic.Contains(addr) {
			return resolvedRoleAddrs{}, fmt.Errorf("role address %s conflicts with subnet, gateway or dynamic range", addr)
		}
		values[i] = addr
	}
	return resolvedRoleAddrs{SOCKS: values[0].String(), DNS: values[1].String(), H2: values[2].String()}, nil
}

func resolvePrefix(raw string, family int, base netip.Prefix) (netip.Prefix, error) {
	prefix, err := parsePrefix(raw, family)
	if err != nil {
		return netip.Prefix{}, err
	}
	if base.IsValid() && family == 6 && strings.HasPrefix(raw, "::") {
		addr, err := addAddress(base.Addr(), prefix.Addr())
		if err != nil {
			return netip.Prefix{}, err
		}
		prefix = netip.PrefixFrom(addr, prefix.Bits()).Masked()
	}
	return prefix, nil
}

func resolveAddr(raw string, family int, base netip.Prefix) (netip.Addr, error) {
	addr, err := netip.ParseAddr(raw)
	if err != nil || addressFamily(addr) != family {
		return netip.Addr{}, fmt.Errorf("invalid IPv%d address %q", family, raw)
	}
	if base.IsValid() && family == 6 && strings.HasPrefix(raw, "::") {
		return addAddress(base.Addr(), addr)
	}
	return addr, nil
}

func parsePrefix(raw string, family int) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(raw)
	if err != nil || addressFamily(prefix.Addr()) != family {
		return netip.Prefix{}, fmt.Errorf("invalid IPv%d prefix %q", family, raw)
	}
	if prefix != prefix.Masked() {
		return netip.Prefix{}, fmt.Errorf("prefix %s is not canonical", prefix)
	}
	return prefix, nil
}

func addSmallOffset(addr netip.Addr, offset int) (netip.Addr, error) {
	if offset == 0 {
		return addr, nil
	}
	var raw netip.Addr
	if addr.Is4() {
		raw = netip.AddrFrom4([4]byte{0, 0, 0, byte(offset)})
	} else {
		var b [16]byte
		b[15] = byte(offset)
		raw = netip.AddrFrom16(b)
	}
	return addAddress(addr, raw)
}

func addAddress(base, offset netip.Addr) (netip.Addr, error) {
	if base.Is4() != offset.Is4() {
		return netip.Addr{}, fmt.Errorf("address families differ")
	}
	if base.Is4() {
		b, o := base.As4(), offset.As4()
		var out [4]byte
		carry := 0
		for i := 3; i >= 0; i-- {
			sum := int(b[i]) + int(o[i]) + carry
			out[i] = byte(sum)
			carry = sum >> 8
		}
		if carry != 0 {
			return netip.Addr{}, fmt.Errorf("IPv4 address overflow")
		}
		return netip.AddrFrom4(out), nil
	}
	b, o := base.As16(), offset.As16()
	var out [16]byte
	carry := 0
	for i := 15; i >= 0; i-- {
		sum := int(b[i]) + int(o[i]) + carry
		out[i] = byte(sum)
		carry = sum >> 8
	}
	if carry != 0 {
		return netip.Addr{}, fmt.Errorf("IPv6 address overflow")
	}
	return netip.AddrFrom16(out), nil
}

func containsPrefix(parent, child netip.Prefix) bool {
	return parent.IsValid() && child.IsValid() && parent.Bits() <= child.Bits() && parent.Contains(child.Addr())
}
func addressFamily(addr netip.Addr) int {
	if addr.Is4() {
		return 4
	}
	return 6
}

func sortedKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
