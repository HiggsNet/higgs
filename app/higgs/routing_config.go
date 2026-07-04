package main

import (
	"fmt"
	"net/netip"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Catofes/higgs/pkg/transport/ipsec"
)

// netnsConfig holds the set of named network namespaces the node declares.
type netnsConfig struct {
	// Names maps netns name → spec. The name is used as the stable key
	// referenced by overlays and routing instances.
	Names map[string]ipsec.NetNSSpec
	// Default is the preferred default reference key.
	Default string
}

// netnsConfigYAML is the raw YAML model for the top-level `netns:` section.
type netnsConfigYAML struct {
	// Default is the optional default netns, equivalent to a named entry.
	Default *ipsec.NetNSSpec `yaml:"default"`
	// Entries is a map of named netns definitions, declared alongside default.
	Entries map[string]ipsec.NetNSSpec `yaml:",inline"`
}

// routingConfig holds top-level routing instance definitions.
type routingConfig struct {
	Instances []RoutingInstance
}

// RoutingInstance is a per-netns BIRD instance configuration.
type RoutingInstance struct {
	ID             string
	NetNS          string // references a netns name from netnsConfig
	Enabled        bool
	Protocol       string
	Mode           string
	ShutdownPolicy string
	ControlSocket  string
	PIDFile        string
	ConfigFile     string
	TableID        string
	MetricBase     uint
	MetricStaged   uint
	MetricDraining uint
	ECMP           bool
	ECMPLimit      uint
	InterfacePat   string
	RouterIDLabel  string   // required for path netns
	Overlays       []string // overlays that share this instance (auto-derived)
	Upstream       *UpstreamConfig
}

// UpstreamConfig holds optional veth upstream configuration that connects
// the mesh netns to the main network (init netns or another ns).
type UpstreamConfig struct {
	Enabled          bool
	Interface        string // mesh netns side of the veth pair
	CreateVeth       bool   // if true, Higgs creates and maintains the veth pair
	PeerInterface    string // main network side of the veth pair
	PeerNetns        string // empty = init/main netns
	IPv4LL           string // optional IPv4 link-local for the mesh side
	IPv6LL           string // optional IPv6 link-local for the mesh side
	DownstreamIPv4LL string // optional IPv4 link-local for the peer side
	DownstreamIPv6LL string // optional IPv6 link-local for the peer side
}

// routingInstancesYAML is the raw YAML model for the top-level `routing:` section.
type routingInstancesYAML struct {
	Instances []routingInstanceYAML `yaml:"instances"`
}

type routingInstanceYAML struct {
	ID             string              `yaml:"id"`
	NetNS          string              `yaml:"netns"`
	Enabled        *bool               `yaml:"enabled"`
	Disabled       *bool               `yaml:"disabled"`
	Provider       string              `yaml:"provider"`
	Mode           string              `yaml:"mode"`
	ShutdownPolicy string              `yaml:"shutdown_policy"`
	ControlSocket  string              `yaml:"control_socket"`
	PIDFile        string              `yaml:"pid_file"`
	ConfigFile     string              `yaml:"config_file"`
	TableID        string              `yaml:"table"`
	MetricBase     uint                `yaml:"metric_base"`
	MetricStaged   uint                `yaml:"metric_staged"`
	MetricDraining uint                `yaml:"metric_draining"`
	ECMP           *bool               `yaml:"ecmp"`
	ECMPLimit      uint                `yaml:"ecmp_limit"`
	InterfacePat   string              `yaml:"interface_pattern"`
	RouterIDLabel  string              `yaml:"router_id_label"`
	Upstream       *upstreamConfigYAML `yaml:"upstream"`
}

// upstreamConfigYAML is the raw YAML model for routing.instances[].upstream.
type upstreamConfigYAML struct {
	Enabled             *bool  `yaml:"enabled"`
	Disabled            *bool  `yaml:"disabled"`
	UpstreamInterface   string `yaml:"upstream_interface"`
	DownstreamInterface string `yaml:"downstream_interface"`
	Interface           string `yaml:"interface"`
	CreateVeth          *bool  `yaml:"create_veth"`
	PeerInterface       string `yaml:"peer_interface"`
	PeerNetns           string `yaml:"peer_netns"`
	UpstreamIPv4LL      string `yaml:"upstream_ipv4_ll"`
	UpstreamIPv6LL      string `yaml:"upstream_ipv6_ll"`
	DownstreamIPv4LL    string `yaml:"downstream_ipv4_ll"`
	DownstreamIPv6LL    string `yaml:"downstream_ipv6_ll"`
	IPv4LL              string `yaml:"ipv4_ll"`
	IPv6LL              string `yaml:"ipv6_ll"`
}

const (
	routingShutdownPolicyPersist = "persist"
	routingShutdownPolicyStop    = "stop"
)

// parseNetnsConfig parses the top-level `netns:` section into netnsConfig.
func parseNetnsConfig(yamlCfg *netnsConfigYAML, fallback ipsec.NetNSSpec) (netnsConfig, error) {
	cfg := netnsConfig{Names: make(map[string]ipsec.NetNSSpec)}
	if yamlCfg == nil {
		n := fallback.Normalized()
		addNetnsSpec(&cfg, "default", n)
		return cfg, nil
	}
	if yamlCfg.Default != nil {
		n := yamlCfg.Default.Normalized()
		if err := n.Validate(); err != nil {
			return cfg, fmt.Errorf("netns.default: %w", err)
		}
		addNetnsSpec(&cfg, "default", n)
	}
	for name, spec := range yamlCfg.Entries {
		n := spec.Normalized()
		if err := n.Validate(); err != nil {
			return cfg, fmt.Errorf("netns.%s: %w", name, err)
		}
		if name == "" {
			name = n.Target()
		}
		cfg.Names[name] = n
		if name == "default" && cfg.Default == "" {
			cfg.Default = name
		}
	}
	if len(cfg.Names) == 0 {
		n := fallback.Normalized()
		addNetnsSpec(&cfg, "default", n)
	}
	if cfg.Default == "" {
		cfg.Default = "default"
	}
	return cfg, nil
}

func addNetnsSpec(cfg *netnsConfig, name string, spec ipsec.NetNSSpec) {
	if cfg.Names == nil {
		cfg.Names = make(map[string]ipsec.NetNSSpec)
	}
	if name == "" {
		name = spec.Target()
	}
	if name == "" {
		name = ipsec.NetNSHost
	}
	cfg.Names[name] = spec
	if name == "default" {
		cfg.Default = name
		if target := spec.Target(); target != "" {
			cfg.Names[target] = spec
		}
	}
}

// parseRoutingConfigInstances parses `routing.instances[]` into routingConfig.
func parseRoutingConfigInstances(yamlInstances []routingInstanceYAML, netnsCfg netnsConfig, dataDir string) (routingConfig, error) {
	var instances []RoutingInstance
	for i, yi := range yamlInstances {
		inst, err := parseRoutingInstance(yi, netnsCfg, dataDir)
		if err != nil {
			return routingConfig{}, fmt.Errorf("routing.instances[%d]: %w", i, err)
		}
		instances = append(instances, inst)
	}
	return routingConfig{Instances: instances}, nil
}

func parseRoutingInstance(yi routingInstanceYAML, netnsCfg netnsConfig, dataDir string) (RoutingInstance, error) {
	if yi.ID == "" {
		return RoutingInstance{}, fmt.Errorf("id is required")
	}
	if yi.NetNS == "" {
		yi.NetNS = "default"
	}
	spec, ok := netnsCfg.Names[yi.NetNS]
	if !ok {
		return RoutingInstance{}, fmt.Errorf("netns %q not found in netns section", yi.NetNS)
	}
	// path netns requires router_id_label
	if spec.Kind == ipsec.NetNSPath && yi.RouterIDLabel == "" {
		return RoutingInstance{}, fmt.Errorf("router_id_label is required when netns uses path mode")
	}

	enabled, err := enabledFromPresence("routing.instances[].enabled", "routing.instances[].disabled", true, yi.Enabled, yi.Disabled)
	if err != nil {
		return RoutingInstance{}, err
	}

	mode := yi.Mode
	if mode == "" {
		mode = ipsec.RoutingModeManaged
	}
	if !oneOfRoutingMode(mode) {
		return RoutingInstance{}, fmt.Errorf("unsupported routing mode %q", mode)
	}
	shutdownPolicy := normalizedRoutingShutdownPolicy(strings.TrimSpace(yi.ShutdownPolicy))
	if !oneOfRoutingShutdownPolicy(shutdownPolicy) {
		return RoutingInstance{}, fmt.Errorf("unsupported shutdown_policy %q", shutdownPolicy)
	}
	provider := yi.Provider
	if provider == "" {
		provider = "bird"
	}
	if provider != "bird" {
		return RoutingInstance{}, fmt.Errorf("unsupported routing provider %q", provider)
	}
	tableID := yi.TableID
	if tableID == "" {
		tableID = ipsec.DefaultRoutingTable
	}
	metricBase := yi.MetricBase
	if metricBase == 0 {
		metricBase = ipsec.DefaultMetricBase
	}
	metricStaged := yi.MetricStaged
	if metricStaged == 0 {
		metricStaged = ipsec.DefaultMetricStaged
	}
	metricDraining := yi.MetricDraining
	if metricDraining == 0 {
		metricDraining = ipsec.DefaultMetricDrained
	}
	ecmp := true
	if yi.ECMP != nil {
		ecmp = *yi.ECMP
	}
	ecmpLimit := yi.ECMPLimit
	if ecmpLimit == 0 {
		ecmpLimit = 16
	}
	ifacePat := yi.InterfacePat
	if ifacePat == "" {
		ifacePat = "hgs*"
	}

	configDir := filepath.Join(dataDir, "bird")
	controlSocket := yi.ControlSocket
	if controlSocket == "" {
		controlSocket = filepath.Join(configDir, fmt.Sprintf("bird-%s.ctl", yi.NetNS))
	}
	pidFile := yi.PIDFile
	if pidFile == "" {
		pidFile = filepath.Join(configDir, fmt.Sprintf("bird-%s.pid", yi.NetNS))
	}
	configFile := yi.ConfigFile
	if configFile == "" {
		configFile = filepath.Join(configDir, fmt.Sprintf("bird-%s.conf", yi.NetNS))
	}

	upstream, err := parseUpstreamConfig(yi.Upstream)
	if err != nil {
		return RoutingInstance{}, fmt.Errorf("upstream: %w", err)
	}

	return RoutingInstance{
		ID:             yi.ID,
		NetNS:          yi.NetNS,
		Enabled:        enabled,
		Protocol:       provider,
		Mode:           mode,
		ShutdownPolicy: shutdownPolicy,
		ControlSocket:  controlSocket,
		PIDFile:        pidFile,
		ConfigFile:     configFile,
		TableID:        tableID,
		MetricBase:     metricBase,
		MetricStaged:   metricStaged,
		MetricDraining: metricDraining,
		ECMP:           ecmp,
		ECMPLimit:      ecmpLimit,
		InterfacePat:   ifacePat,
		RouterIDLabel:  yi.RouterIDLabel,
		Upstream:       upstream,
	}, nil
}

func parseUpstreamConfig(yu *upstreamConfigYAML) (*UpstreamConfig, error) {
	if yu == nil {
		return nil, nil
	}
	enabled, err := enabledFromPresence("routing.instances[].upstream.enabled", "routing.instances[].upstream.disabled", true, yu.Enabled, yu.Disabled)
	if err != nil {
		return nil, err
	}
	if !enabled {
		return &UpstreamConfig{Enabled: false}, nil
	}

	upstreamInterface, err := mergeAliasField("upstream_interface", strings.TrimSpace(yu.UpstreamInterface), "interface", strings.TrimSpace(yu.Interface))
	if err != nil {
		return nil, err
	}
	downstreamInterface, err := mergeAliasField("downstream_interface", strings.TrimSpace(yu.DownstreamInterface), "peer_interface", strings.TrimSpace(yu.PeerInterface))
	if err != nil {
		return nil, err
	}
	upstreamIPv4, err := mergeAliasField("upstream_ipv4_ll", strings.TrimSpace(yu.UpstreamIPv4LL), "ipv4_ll", strings.TrimSpace(yu.IPv4LL))
	if err != nil {
		return nil, err
	}
	upstreamIPv6, err := mergeAliasField("upstream_ipv6_ll", strings.TrimSpace(yu.UpstreamIPv6LL), "ipv6_ll", strings.TrimSpace(yu.IPv6LL))
	if err != nil {
		return nil, err
	}

	uc := &UpstreamConfig{
		Enabled:          true,
		Interface:        upstreamInterface,
		PeerInterface:    downstreamInterface,
		PeerNetns:        strings.TrimSpace(yu.PeerNetns),
		IPv4LL:           upstreamIPv4,
		IPv6LL:           upstreamIPv6,
		DownstreamIPv4LL: strings.TrimSpace(yu.DownstreamIPv4LL),
		DownstreamIPv6LL: strings.TrimSpace(yu.DownstreamIPv6LL),
	}
	if yu.CreateVeth != nil {
		uc.CreateVeth = *yu.CreateVeth
	}

	// Default interface name when upstream is enabled but not specified.
	if uc.Interface == "" {
		uc.Interface = "hgs-2host"
	}
	if uc.PeerInterface == "" {
		uc.PeerInterface = "hgs-2higgs"
	}

	// Validate IPv4/IPv6 link-local if provided.
	if err := validateOptionalPrefix("upstream_ipv4_ll", uc.IPv4LL); err != nil {
		return nil, err
	}
	if err := validateOptionalPrefix("upstream_ipv6_ll", uc.IPv6LL); err != nil {
		return nil, err
	}
	if err := validateOptionalPrefix("downstream_ipv4_ll", uc.DownstreamIPv4LL); err != nil {
		return nil, err
	}
	if err := validateOptionalPrefix("downstream_ipv6_ll", uc.DownstreamIPv6LL); err != nil {
		return nil, err
	}

	return uc, nil
}

func mergeAliasField(primaryName, primary, legacyName, legacy string) (string, error) {
	if primary != "" && legacy != "" && primary != legacy {
		return "", fmt.Errorf("%s %q conflicts with legacy %s %q", primaryName, primary, legacyName, legacy)
	}
	if primary != "" {
		return primary, nil
	}
	return legacy, nil
}

func validateOptionalPrefix(field, value string) error {
	if value == "" {
		return nil
	}
	if _, err := netip.ParsePrefix(value); err != nil {
		return fmt.Errorf("invalid %s %q: %w", field, value, err)
	}
	return nil
}

func oneOfRoutingMode(mode string) bool {
	return mode == ipsec.RoutingModeManaged || mode == ipsec.RoutingModeExternal || mode == ipsec.RoutingModeDisabled
}

func oneOfRoutingShutdownPolicy(policy string) bool {
	return policy == routingShutdownPolicyPersist || policy == routingShutdownPolicyStop
}

func normalizedRoutingShutdownPolicy(policy string) string {
	if policy == "" {
		return routingShutdownPolicyPersist
	}
	return policy
}

// resolveOverlayNetNSName returns the netns name for an overlay group.
// If the group has a named netns, its Target() is returned.
// Otherwise, the fallback default netns name is used.
func resolveOverlayNetNSName(group ipsec.LinkGroupSpec, defaultNetNS ipsec.NetNSSpec) string {
	netns := group.NetNS.Normalized()
	if netns.Kind == "" || (netns.Kind == ipsec.NetNSName && netns.Name == "") {
		netns = defaultNetNS.Normalized()
	}
	name := netns.Target()
	if name == "" {
		return ipsec.NetNSHost
	}
	return name
}

// routingNetnsNames returns sorted unique netns names used by routing instances.
func routingNetnsNames(cfg routingConfig) []string {
	seen := make(map[string]bool)
	var out []string
	for _, inst := range cfg.Instances {
		if !seen[inst.NetNS] {
			seen[inst.NetNS] = true
			out = append(out, inst.NetNS)
		}
	}
	sort.Strings(out)
	return out
}

// netnsRouterIDLabel returns the stable label used for StableRouterID derivation.
// For host netns → "host"; for named netns → the name; for path netns → router_id_label.
func netnsRouterIDLabel(netnsName string, netnsCfg netnsConfig, inst RoutingInstance) string {
	if inst.RouterIDLabel != "" {
		return inst.RouterIDLabel
	}
	if spec, ok := netnsCfg.Names[netnsName]; ok {
		if spec.Kind == ipsec.NetNSPath {
			// path netns without label should have been rejected at parse time
			return netnsName
		}
		if spec.Kind == ipsec.NetNSHost {
			return ipsec.NetNSHost
		}
		return spec.Target()
	}
	return netnsName
}

// trim strings.Fields helper to avoid importing in multiple places
var _ = strings.TrimSpace
