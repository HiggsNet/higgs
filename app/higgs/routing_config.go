package main

import (
	"fmt"
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
}

// netnsConfigYAML is the raw YAML model for the top-level `netns:` section.
type netnsConfigYAML struct {
	// Default is the optional default netns, equivalent to a named entry.
	Default *ipsec.NetNSSpec `yaml:"default"`
	// Entries is a map of named netns definitions.
	Entries map[string]ipsec.NetNSSpec `yaml:"names"`
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
}

// routingInstancesYAML is the raw YAML model for the top-level `routing:` section.
type routingInstancesYAML struct {
	Instances []routingInstanceYAML `yaml:"instances"`
}

type routingInstanceYAML struct {
	ID             string `yaml:"id"`
	NetNS          string `yaml:"netns"`
	Enabled        *bool  `yaml:"enabled"`
	Protocol       string `yaml:"protocol"`
	Mode           string `yaml:"mode"`
	ControlSocket  string `yaml:"control_socket"`
	PIDFile        string `yaml:"pid_file"`
	ConfigFile     string `yaml:"config_file"`
	TableID        string `yaml:"table"`
	MetricBase     uint   `yaml:"metric_base"`
	MetricStaged   uint   `yaml:"metric_staged"`
	MetricDraining uint   `yaml:"metric_draining"`
	ECMP           *bool  `yaml:"ecmp"`
	ECMPLimit      uint   `yaml:"ecmp_limit"`
	InterfacePat   string `yaml:"interface_pattern"`
	RouterIDLabel  string `yaml:"router_id_label"`
}

// parseNetnsConfig parses the top-level `netns:` section into netnsConfig.
func parseNetnsConfig(yamlCfg *netnsConfigYAML, fallback ipsec.NetNSSpec) netnsConfig {
	cfg := netnsConfig{Names: make(map[string]ipsec.NetNSSpec)}
	if yamlCfg == nil {
		n := fallback.Normalized()
		cfg.Names[n.Target()] = n
		return cfg
	}
	if yamlCfg.Default != nil {
		n := yamlCfg.Default.Normalized()
		if err := n.Validate(); err == nil {
			name := n.Target()
			if name == "" {
				name = ipsec.NetNSHost
			}
			cfg.Names[name] = n
		}
	}
	for name, spec := range yamlCfg.Entries {
		n := spec.Normalized()
		if err := n.Validate(); err == nil {
			if name == "" {
				name = n.Target()
			}
			cfg.Names[name] = n
		}
	}
	if len(cfg.Names) == 0 {
		n := fallback.Normalized()
		cfg.Names[n.Target()] = n
	}
	return cfg
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
		return RoutingInstance{}, fmt.Errorf("netns is required (reference a name from the netns section)")
	}
	spec, ok := netnsCfg.Names[yi.NetNS]
	if !ok {
		return RoutingInstance{}, fmt.Errorf("netns %q not found in netns section", yi.NetNS)
	}
	// path netns requires router_id_label
	if spec.Kind == ipsec.NetNSPath && yi.RouterIDLabel == "" {
		return RoutingInstance{}, fmt.Errorf("router_id_label is required when netns uses path mode")
	}

	enabled := true
	if yi.Enabled != nil {
		enabled = *yi.Enabled
	}

	mode := yi.Mode
	if mode == "" {
		mode = ipsec.RoutingModeManaged
	}
	if !oneOfRoutingMode(mode) {
		return RoutingInstance{}, fmt.Errorf("unsupported routing mode %q", mode)
	}
	protocol := yi.Protocol
	if protocol == "" {
		protocol = "bird"
	}
	if protocol != "bird" {
		return RoutingInstance{}, fmt.Errorf("unsupported routing protocol %q", protocol)
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

	return RoutingInstance{
		ID:             yi.ID,
		NetNS:          yi.NetNS,
		Enabled:        enabled,
		Protocol:       protocol,
		Mode:           mode,
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
	}, nil
}

func oneOfRoutingMode(mode string) bool {
	return mode == ipsec.RoutingModeManaged || mode == ipsec.RoutingModeExternal || mode == ipsec.RoutingModeDisabled
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

// routingInstancesByNetNS groups routing instances by netns name.
func routingInstancesByNetNS(cfg routingConfig) map[string]*RoutingInstance {
	out := make(map[string]*RoutingInstance)
	for i := range cfg.Instances {
		out[cfg.Instances[i].NetNS] = &cfg.Instances[i]
	}
	return out
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
