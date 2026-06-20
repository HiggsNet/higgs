package main

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/Catofes/higgs/pkg/firewall"
	"github.com/Catofes/higgs/pkg/transport/ipsec"
)

// firewallConfig holds top-level firewall instance definitions.
type firewallConfig struct {
	Instances []FirewallInstanceConfig
}

// FirewallInstanceConfig is a per-netns (or host) firewall instance configuration.
type FirewallInstanceConfig struct {
	ID            string
	NetNS         string // netns name, or "host"
	IsHost        bool
	Enabled       bool
	Mode          string // managed | external | disabled
	Backend       string // auto | nft | iptables | none
	DefaultPolicy string // drop | accept
	OwnerPrefix   string

	XFRMTunnelPattern string
	UpstreamPatterns  []string

	LocalServices []firewall.LocalService

	HostPorts     firewall.HostPortConfig
	RedirectGrace firewall.RedirectGrace

	Hooks firewall.Hooks

	// Forwarding policy for this instance's overlay.
	Forwarding firewall.ForwardingPolicy
}

// firewallConfigYAML is the raw YAML model for the top-level `firewall:` section.
type firewallConfigYAML struct {
	Instances []firewallInstanceYAML `yaml:"instances"`
}

type firewallInstanceYAML struct {
	ID            string `yaml:"id"`
	NetNS         string `yaml:"netns"`
	Host          *bool  `yaml:"host"`
	Enabled       *bool  `yaml:"enabled"`
	Mode          string `yaml:"mode"`
	Backend       string `yaml:"backend"`
	DefaultPolicy string `yaml:"default_policy"`
	OwnerPrefix   string `yaml:"owner_prefix"`

	XFRMTunnelPattern string   `yaml:"xfrm_tunnel_pattern"`
	UpstreamPatterns  []string `yaml:"upstream_patterns"`

	LocalServices []localServiceYAML `yaml:"local_services"`

	HostPorts     *hostPortsYAML     `yaml:"host_ports"`
	RedirectGrace *redirectGraceYAML `yaml:"redirect_grace"`

	Hooks *hooksYAML `yaml:"hooks"`

	Forwarding *forwardingYAML `yaml:"forwarding"`
}

type localServiceYAML struct {
	Proto   string   `yaml:"proto"`
	Port    uint16   `yaml:"port"`
	Sources []string `yaml:"sources"`
}

type hostPortsYAML struct {
	IKE  *bool `yaml:"ike"`
	NATT *bool `yaml:"natt"`
}

type redirectGraceYAML struct {
	Enabled *bool `yaml:"enabled"`
}

type hooksYAML struct {
	PreInput           string `yaml:"pre_input"`
	PostInput          string `yaml:"post_input"`
	PreForward         string `yaml:"pre_forward"`
	PostForward        string `yaml:"post_forward"`
	PreOutput          string `yaml:"pre_output"`
	PostOutput         string `yaml:"post_output"`
	HostPrePrerouting  string `yaml:"host_pre_prerouting"`
	HostPostPrerouting string `yaml:"host_post_prerouting"`
	HostPreInput       string `yaml:"host_pre_input"`
	HostPostInput      string `yaml:"host_post_input"`
}

type forwardingYAML struct {
	Transit       *bool    `yaml:"transit"`
	AllowPrefixes []string `yaml:"allow_prefixes"`
	DenyPrefixes  []string `yaml:"deny_prefixes"`
	AllowPeers    []string `yaml:"allow_peers"`
	DenyPeers     []string `yaml:"deny_peers"`
	MetricHint    uint     `yaml:"metric_hint"`
}

func parseFirewallConfig(yamlCfg *firewallConfigYAML, netnsCfg netnsConfig, dataDir string) (firewallConfig, error) {
	cfg := firewallConfig{}
	if yamlCfg == nil {
		return cfg, nil
	}
	for i, yi := range yamlCfg.Instances {
		inst, err := parseFirewallInstance(yi, netnsCfg)
		if err != nil {
			return firewallConfig{}, fmt.Errorf("firewall.instances[%d]: %w", i, err)
		}
		cfg.Instances = append(cfg.Instances, inst)
	}
	return cfg, nil
}

func parseFirewallInstance(yi firewallInstanceYAML, netnsCfg netnsConfig) (FirewallInstanceConfig, error) {
	if yi.ID == "" {
		return FirewallInstanceConfig{}, fmt.Errorf("id is required")
	}

	isHost := false
	if yi.Host != nil {
		isHost = *yi.Host
	}
	if isHost && yi.NetNS != "" {
		return FirewallInstanceConfig{}, fmt.Errorf("host: true conflicts with netns %q; choose either host: true or netns", yi.NetNS)
	}
	if yi.NetNS == "" && !isHost {
		return FirewallInstanceConfig{}, fmt.Errorf("netns is required (reference a name from the netns section, or set host: true)")
	}
	if isHost {
		yi.NetNS = "host"
	} else {
		if _, ok := netnsCfg.Names[yi.NetNS]; !ok {
			return FirewallInstanceConfig{}, fmt.Errorf("netns %q not found in netns section", yi.NetNS)
		}
	}

	enabled := true
	if yi.Enabled != nil {
		enabled = *yi.Enabled
	}

	mode := yi.Mode
	if mode == "" {
		mode = firewall.ModeManaged
	}
	if !oneOfFirewallMode(mode) {
		return FirewallInstanceConfig{}, fmt.Errorf("unsupported firewall mode %q", mode)
	}

	backend := yi.Backend
	if backend == "" {
		backend = firewall.BackendAuto
	}
	if !oneOfFirewallBackend(backend) {
		return FirewallInstanceConfig{}, fmt.Errorf("unsupported firewall backend %q", backend)
	}

	defaultPolicy := yi.DefaultPolicy
	if defaultPolicy == "" {
		defaultPolicy = firewall.DefaultPolicyDrop
	}
	if defaultPolicy != firewall.DefaultPolicyDrop && defaultPolicy != firewall.DefaultPolicyAccept {
		return FirewallInstanceConfig{}, fmt.Errorf("invalid default_policy %q", defaultPolicy)
	}

	ownerPrefix := yi.OwnerPrefix
	if ownerPrefix == "" {
		ownerPrefix = "higgs"
	}

	xfrmPat := yi.XFRMTunnelPattern
	if xfrmPat == "" && !isHost {
		xfrmPat = "hgs*"
	}

	upstreamPats := yi.UpstreamPatterns

	localServices, err := parseLocalServices(yi.LocalServices)
	if err != nil {
		return FirewallInstanceConfig{}, fmt.Errorf("local_services: %w", err)
	}

	hostPorts := firewall.HostPortConfig{}
	if yi.HostPorts != nil {
		if yi.HostPorts.IKE != nil {
			hostPorts.IKE = *yi.HostPorts.IKE
		}
		if yi.HostPorts.NATT != nil {
			hostPorts.NATT = *yi.HostPorts.NATT
		}
	}

	redirectGrace := firewall.RedirectGrace{}
	if yi.RedirectGrace != nil && yi.RedirectGrace.Enabled != nil {
		redirectGrace.Enabled = *yi.RedirectGrace.Enabled
	}

	hooks := firewall.Hooks{}
	if yi.Hooks != nil {
		hooks = firewall.Hooks{
			PreInput:           yi.Hooks.PreInput,
			PostInput:          yi.Hooks.PostInput,
			PreForward:         yi.Hooks.PreForward,
			PostForward:        yi.Hooks.PostForward,
			PreOutput:          yi.Hooks.PreOutput,
			PostOutput:         yi.Hooks.PostOutput,
			HostPrePrerouting:  yi.Hooks.HostPrePrerouting,
			HostPostPrerouting: yi.Hooks.HostPostPrerouting,
			HostPreInput:       yi.Hooks.HostPreInput,
			HostPostInput:      yi.Hooks.HostPostInput,
		}
	}

	forwarding := firewall.ForwardingPolicy{}
	if yi.Forwarding != nil {
		allowPrefixes, err := parsePrefixList(yi.Forwarding.AllowPrefixes)
		if err != nil {
			return FirewallInstanceConfig{}, fmt.Errorf("forwarding.allow_prefixes: %w", err)
		}
		denyPrefixes, err := parsePrefixList(yi.Forwarding.DenyPrefixes)
		if err != nil {
			return FirewallInstanceConfig{}, fmt.Errorf("forwarding.deny_prefixes: %w", err)
		}
		transit := false
		if yi.Forwarding.Transit != nil {
			transit = *yi.Forwarding.Transit
		}
		forwarding = firewall.BuildForwardingPolicy(
			transit,
			allowPrefixes,
			denyPrefixes,
			yi.Forwarding.AllowPeers,
			yi.Forwarding.DenyPeers,
			yi.Forwarding.MetricHint,
		)
	}

	return FirewallInstanceConfig{
		ID:                yi.ID,
		NetNS:             yi.NetNS,
		IsHost:            isHost,
		Enabled:           enabled,
		Mode:              mode,
		Backend:           backend,
		DefaultPolicy:     defaultPolicy,
		OwnerPrefix:       ownerPrefix,
		XFRMTunnelPattern: xfrmPat,
		UpstreamPatterns:  upstreamPats,
		LocalServices:     localServices,
		HostPorts:         hostPorts,
		RedirectGrace:     redirectGrace,
		Hooks:             hooks,
		Forwarding:        forwarding,
	}, nil
}

func parseLocalServices(items []localServiceYAML) ([]firewall.LocalService, error) {
	if len(items) == 0 {
		return nil, nil
	}
	var out []firewall.LocalService
	for i, svc := range items {
		proto := strings.ToLower(strings.TrimSpace(svc.Proto))
		if proto != "tcp" && proto != "udp" {
			return nil, fmt.Errorf("[%d]: proto must be tcp or udp", i)
		}
		if svc.Port == 0 {
			return nil, fmt.Errorf("[%d]: port is required", i)
		}
		var srcs []netip.Prefix
		for _, s := range svc.Sources {
			p, err := netip.ParsePrefix(s)
			if err != nil {
				return nil, fmt.Errorf("[%d]: invalid source %q: %w", i, s, err)
			}
			srcs = append(srcs, p.Masked())
		}
		out = append(out, firewall.LocalService{Proto: proto, Port: svc.Port, Sources: srcs})
	}
	return out, nil
}

func parsePrefixList(items []string) ([]netip.Prefix, error) {
	if len(items) == 0 {
		return nil, nil
	}
	var out []netip.Prefix
	for _, s := range items {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("invalid prefix %q: %w", s, err)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

func oneOfFirewallMode(mode string) bool {
	return mode == firewall.ModeManaged || mode == firewall.ModeExternal || mode == firewall.ModeDisabled
}

func oneOfFirewallBackend(backend string) bool {
	switch backend {
	case firewall.BackendAuto, firewall.BackendNFT, firewall.BackendIptables, firewall.BackendNone:
		return true
	}
	return false
}

// firewallInstancesEnabled returns enabled, non-disabled firewall instances.
func firewallInstancesEnabled(config *appConfig) []FirewallInstanceConfig {
	if config == nil {
		return nil
	}
	var out []FirewallInstanceConfig
	for _, inst := range config.Firewall.Instances {
		if inst.Enabled && inst.Mode != firewall.ModeDisabled {
			out = append(out, inst)
		}
	}
	return out
}

// firewallInstanceSpecFromConfig converts a FirewallInstanceConfig into a
// firewall.FirewallInstanceSpec ready for the planner.
func firewallInstanceSpecFromConfig(inst FirewallInstanceConfig, listenAddrs []netip.Addr, charonIKEPort, charonNATTPort uint16) firewall.FirewallInstanceSpec {
	return firewall.FirewallInstanceSpec{
		ID:                inst.ID,
		NetNS:             inst.NetNS,
		IsHost:            inst.IsHost,
		Enabled:           inst.Enabled,
		Mode:              inst.Mode,
		Backend:           inst.Backend,
		DefaultPolicy:     inst.DefaultPolicy,
		OwnerPrefix:       inst.OwnerPrefix,
		XFRMTunnelPattern: inst.XFRMTunnelPattern,
		UpstreamPatterns:  inst.UpstreamPatterns,
		LocalServices:     inst.LocalServices,
		HostPorts:         inst.HostPorts,
		RedirectGrace:     inst.RedirectGrace,
		ListenAddrs:       listenAddrs,
		CharonIKEPort:     charonIKEPort,
		CharonNATTPort:    charonNATTPort,
		Hooks:             inst.Hooks,
	}
}

// ensure ipsec import is used (for NetNSSpec constants if needed in future).
var _ = ipsec.NetNSHost
