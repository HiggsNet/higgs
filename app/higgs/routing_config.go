package main

import (
	"crypto/sha256"
	"fmt"
	"net/netip"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Catofes/higgs/pkg/firewall"
	"github.com/Catofes/higgs/pkg/routing/bird"
	"github.com/Catofes/higgs/pkg/transport/ipsec"
)

// netnsConfig holds the set of named network namespaces the node declares.
type netnsConfig struct {
	// Names maps netns name → spec. The name is used as the stable key
	// referenced by overlays and routing instances.
	Names map[string]ipsec.NetNSSpec
	// Forwarding holds the single routing/firewall forwarding policy owned by
	// each network namespace. Alias keys (notably "default" and its target)
	// point at the same value.
	Forwarding map[string]firewall.ForwardingPolicy
	// Default is the preferred default reference key.
	Default string
}

// netnsConfigYAML is the raw YAML model for the top-level `netns:` section.
type netnsConfigYAML struct {
	// Default is the optional default netns, equivalent to a named entry.
	Default *netnsSpecYAML `yaml:"default"`
	// Entries is a map of named netns definitions, declared alongside default.
	Entries map[string]netnsSpecYAML `yaml:",inline"`
}

type netnsSpecYAML struct {
	Kind       string          `yaml:"kind"`
	Name       string          `yaml:"name"`
	Path       string          `yaml:"path"`
	Create     *bool           `yaml:"create"`
	Forwarding *forwardingYAML `yaml:"forwarding"`
}

// netNSSpec applies netns-specific YAML defaults. A declared named netns is
// Higgs-owned by default; create: false opts into reusing an existing one.
func (raw netnsSpecYAML) netNSSpec() ipsec.NetNSSpec {
	spec := ipsec.NetNSSpec{
		Kind: raw.Kind,
		Name: raw.Name,
		Path: raw.Path,
	}
	if raw.Create != nil {
		spec.Create = *raw.Create
	}
	spec = spec.Normalized()
	if raw.Create == nil && spec.Kind == ipsec.NetNSName {
		spec.Create = true
	}
	return spec
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
	Enabled           bool
	Mode              string // static or external
	CreateVeth        bool   // if true, Higgs creates and maintains the veth pair
	MeshInterface     string // routing instance netns side of the veth pair
	MeshIPv4LL        string // optional IPv4 link-local for the mesh side
	MeshIPv6LL        string // optional IPv6 link-local for the mesh side
	ExternalInterface string // host/upstream netns side of the veth pair
	ExternalNetns     string // empty = init/main host netns
	ExternalIPv4LL    string // optional IPv4 link-local for the external side
	ExternalIPv6LL    string // optional IPv6 link-local for the external side
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
	Enabled    *bool                `yaml:"enabled"`
	Disabled   *bool                `yaml:"disabled"`
	Mode       string               `yaml:"mode"`
	CreateVeth *bool                `yaml:"create_veth"`
	Mesh       upstreamEndpointYAML `yaml:"mesh"`
	External   upstreamEndpointYAML `yaml:"external"`
}

type upstreamEndpointYAML struct {
	Interface string `yaml:"interface"`
	NetNS     string `yaml:"netns"`
	IPv4LL    string `yaml:"ipv4_ll"`
	IPv6LL    string `yaml:"ipv6_ll"`
}

const (
	routingShutdownPolicyPersist = "persist"
	routingShutdownPolicyStop    = "stop"

	upstreamModeStatic   = "static"
	upstreamModeExternal = "external"

	defaultMeshIPv4LL     = "169.254.254.1/30"
	defaultMeshIPv6LL     = "fe80::a1:1/64"
	defaultExternalIPv4LL = "169.254.254.2/30"
	defaultExternalIPv6LL = "fe80::a1:2/64"
	defaultMeshVeth       = "hgv2host"
	defaultExternalVeth   = "hgv2mesh"
)

// parseNetnsConfig parses the top-level `netns:` section into netnsConfig.
func parseNetnsConfig(yamlCfg *netnsConfigYAML, fallback ipsec.NetNSSpec) (netnsConfig, error) {
	cfg := netnsConfig{Names: make(map[string]ipsec.NetNSSpec), Forwarding: make(map[string]firewall.ForwardingPolicy)}
	if yamlCfg == nil {
		n := fallback.Normalized()
		addNetnsSpec(&cfg, "default", n)
		return cfg, nil
	}
	if yamlCfg.Default != nil {
		n := yamlCfg.Default.netNSSpec()
		if err := n.Validate(); err != nil {
			return cfg, fmt.Errorf("netns.default: %w", err)
		}
		addNetnsSpec(&cfg, "default", n)
		if err := addNetnsForwarding(&cfg, "default", n, yamlCfg.Default.Forwarding); err != nil {
			return cfg, fmt.Errorf("netns.default: %w", err)
		}
	}
	for name, entry := range yamlCfg.Entries {
		n := entry.netNSSpec()
		if err := n.Validate(); err != nil {
			return cfg, fmt.Errorf("netns.%s: %w", name, err)
		}
		if name == "" {
			name = n.Target()
		}
		cfg.Names[name] = n
		if err := addNetnsForwarding(&cfg, name, n, entry.Forwarding); err != nil {
			return cfg, fmt.Errorf("netns.%s: %w", name, err)
		}
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
	netnsName := routingNetNSTarget(spec)
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
		controlSocket, err = defaultBirdControlSocketPath(configDir, netnsName)
		if err != nil {
			return RoutingInstance{}, err
		}
	} else if err := validateBirdControlSocketPath(controlSocket); err != nil {
		return RoutingInstance{}, err
	}
	pidFile := yi.PIDFile
	if pidFile == "" {
		pidFile = filepath.Join(configDir, fmt.Sprintf("bird-%s.pid", netnsName))
	}
	configFile := yi.ConfigFile
	if configFile == "" {
		configFile = filepath.Join(configDir, fmt.Sprintf("bird-%s.conf", netnsName))
	}

	upstream, err := parseUpstreamConfig(yi.Upstream)
	if err != nil {
		return RoutingInstance{}, fmt.Errorf("upstream: %w", err)
	}

	return RoutingInstance{
		ID:             yi.ID,
		NetNS:          netnsName,
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

func defaultBirdControlSocketPath(configDir, netnsName string) (string, error) {
	path := filepath.Join(configDir, fmt.Sprintf("bird-%s.ctl", netnsName))
	if len(path) <= bird.MaxControlSocketPathBytes {
		return path, nil
	}

	sum := sha256.Sum256([]byte(netnsName))
	path = filepath.Join(configDir, fmt.Sprintf("bird-%x.ctl", sum[:8]))
	if len(path) <= bird.MaxControlSocketPathBytes {
		return path, nil
	}

	// A long data_dir can consume the entire sockaddr_un budget even after the
	// filename is hashed. Managed BIRD already needs a runtime socket, so use a
	// stable path below /run keyed by the complete desired path. Including the
	// data-dir-derived path keeps concurrent isolated smoke runs distinct.
	sum = sha256.Sum256([]byte(path))
	path = filepath.Join("/run/higgs/bird", fmt.Sprintf("bird-%x.ctl", sum[:8]))
	return path, validateBirdControlSocketPath(path)
}

func validateBirdControlSocketPath(path string) error {
	if len(path) > bird.MaxControlSocketPathBytes {
		return fmt.Errorf("BIRD control socket path is %d bytes, exceeds Linux limit %d: %s", len(path), bird.MaxControlSocketPathBytes, path)
	}
	return nil
}

func routingNetNSTarget(spec ipsec.NetNSSpec) string {
	if target := spec.Target(); target != "" {
		return target
	}
	return ipsec.NetNSHost
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

	uc := &UpstreamConfig{
		Enabled:           true,
		Mode:              normalizedUpstreamMode(strings.TrimSpace(yu.Mode)),
		CreateVeth:        true,
		MeshInterface:     strings.TrimSpace(yu.Mesh.Interface),
		MeshIPv4LL:        strings.TrimSpace(yu.Mesh.IPv4LL),
		MeshIPv6LL:        strings.TrimSpace(yu.Mesh.IPv6LL),
		ExternalInterface: strings.TrimSpace(yu.External.Interface),
		ExternalNetns:     strings.TrimSpace(yu.External.NetNS),
		ExternalIPv4LL:    strings.TrimSpace(yu.External.IPv4LL),
		ExternalIPv6LL:    strings.TrimSpace(yu.External.IPv6LL),
	}
	if yu.CreateVeth != nil {
		uc.CreateVeth = *yu.CreateVeth
	}

	// Apply default link-local addresses when upstream is enabled and the user
	// did not provide explicit values. These are used both for the veth
	// endpoints and as the next-hop for static routes toward the mesh netns.
	if uc.MeshIPv4LL == "" {
		uc.MeshIPv4LL = defaultMeshIPv4LL
	}
	if uc.MeshIPv6LL == "" {
		uc.MeshIPv6LL = defaultMeshIPv6LL
	}
	if uc.ExternalIPv4LL == "" {
		uc.ExternalIPv4LL = defaultExternalIPv4LL
	}
	if uc.ExternalIPv6LL == "" {
		uc.ExternalIPv6LL = defaultExternalIPv6LL
	}

	// Default endpoint interface names when upstream is enabled but not specified.
	if uc.MeshInterface == "" {
		uc.MeshInterface = defaultMeshVeth
	}
	if uc.ExternalInterface == "" {
		uc.ExternalInterface = defaultExternalVeth
	}
	if !oneOfUpstreamMode(uc.Mode) {
		return nil, fmt.Errorf("unsupported mode %q", uc.Mode)
	}

	// Validate IPv4/IPv6 link-local if provided.
	if err := validateOptionalPrefix("mesh.ipv4_ll", uc.MeshIPv4LL); err != nil {
		return nil, err
	}
	if err := validateOptionalPrefix("mesh.ipv6_ll", uc.MeshIPv6LL); err != nil {
		return nil, err
	}
	if err := validateOptionalPrefix("external.ipv4_ll", uc.ExternalIPv4LL); err != nil {
		return nil, err
	}
	if err := validateOptionalPrefix("external.ipv6_ll", uc.ExternalIPv6LL); err != nil {
		return nil, err
	}

	return uc, nil
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

func oneOfUpstreamMode(mode string) bool {
	return mode == upstreamModeStatic || mode == upstreamModeExternal
}

func normalizedUpstreamMode(mode string) string {
	if mode == "" {
		return upstreamModeStatic
	}
	return mode
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
