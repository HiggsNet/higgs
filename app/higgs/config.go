package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Catofes/higgs/pkg/core/gossip"
	"github.com/Catofes/higgs/pkg/core/zone"
	"github.com/Catofes/higgs/pkg/transport/ipsec"
	"gopkg.in/yaml.v3"
)

const (
	defaultConfigPath              = "/etc/higgs/config.yaml"
	defaultDataDir                 = "/etc/higgs"
	defaultStateFile               = "higgs.db"
	defaultIPsecPortPreviousGrace  = 2 * time.Hour
	defaultIPsecRotateRetentionSec = 3600
)

type appConfig struct {
	DataDir              string
	StatePath            string
	ManagedZone          zone.ZonePath
	Identity             identityConfig
	PeerID               string
	ListenAddr           string
	ListenPort           int
	Bootstrap            []syncConfigPeer
	TrustedRootPublicKey ed25519.PublicKey
	MaxMessageBytes      int
	MaxSyncZones         int
	MaxSyncRecords       int
	LogLevel             string
	Log                  logConfig
	AdvertiseAddrs       []string
	Reflectors           []string
	ReflectorInterval    time.Duration
	ReflectorTimeout     time.Duration
	EndpointTTL          time.Duration
	EndpointGrace        time.Duration
	PublishEndpoints     bool
	EndpointDiscovery    string
	EndpointSourceOrder  []string
	FilterPrivateIPv4    bool
	Overlay              overlayConfig
	IPsec                ipsecConfig
	IPAM                 ipamConfig
	Netns                netnsConfig
	Routing              routingConfig
	Firewall             firewallConfig
	PeerLifecycle        PeerLifecycleConfig
	Health               healthConfig
	Observer             observerConfig
}

type configYAML struct {
	DataDir     string `yaml:"data_dir"`
	DatabaseDir string `yaml:"database_dir"`
	DBDir       string `yaml:"db_dir"`

	StatePath    string `yaml:"state_path"`
	DatabasePath string `yaml:"database_path"`
	DBPath       string `yaml:"db_path"`

	ManagedZone string       `yaml:"managed_zone"`
	Identity    identityYAML `yaml:"identity"`

	PeerID     string `yaml:"peer_id"`
	ListenAddr string `yaml:"listen_addr"`
	ListenPort *int   `yaml:"listen_port"`

	Bootstrap []syncConfigPeer `yaml:"bootstrap"`

	TrustedRootPublicKey string `yaml:"trusted_root_public_key"`
	RootPublicKey        string `yaml:"root_public_key"`
	TrustedRootKey       string `yaml:"trusted_root_key"`

	MaxMessageBytes     *int `yaml:"max_message_bytes"`
	MaxDatagramBytes    *int `yaml:"max_datagram_bytes"`
	TargetDatagramBytes *int `yaml:"target_datagram_bytes"`
	MaxSyncZones        *int `yaml:"max_sync_zones"`
	MaxSyncRecords      *int `yaml:"max_sync_records"`

	LogLevel string        `yaml:"log_level"`
	Log      logConfigYAML `yaml:"log"`

	AdvertiseAddr  string           `yaml:"advertise_addr"`
	AdvertiseAddrs configStringList `yaml:"advertise_addrs"`
	Reflector      string           `yaml:"reflector"`
	Reflectors     configStringList `yaml:"reflectors"`

	ReflectorInterval   string           `yaml:"reflector_interval"`
	ReflectorTimeout    string           `yaml:"reflector_timeout"`
	EndpointTTL         string           `yaml:"endpoint_ttl"`
	EndpointGrace       string           `yaml:"endpoint_grace"`
	EndpointGracePeriod string           `yaml:"endpoint_grace_period"`
	PublishEndpoints    *bool            `yaml:"publish_endpoints"`
	EndpointDiscovery   string           `yaml:"endpoint_discovery"`
	EndpointSourceOrder configStringList `yaml:"endpoint_source_order"`

	FilterPrivateIPv4 *bool                    `yaml:"filter_private_ipv4"`
	Overlay           overlayDefaultsYAML      `yaml:"overlay"`
	IPsec             ipsecConfigYAML          `yaml:"ipsec"`
	IPAM              ipamConfigYAML           `yaml:"ipam"`
	Netns             *netnsConfigYAML         `yaml:"netns"`
	Routing           *routingInstancesYAML    `yaml:"routing"`
	Firewall          *firewallConfigYAML      `yaml:"firewall"`
	PeerLifecycle     *peerLifecycleYAML       `yaml:"peer_lifecycle"`
	Health            *healthConfigYAML        `yaml:"health"`
	Observer          *observerConfigYAML      `yaml:"observer"`
	Overlays          []overlayGroupConfigYAML `yaml:"overlays"`
}

// peerLifecycleYAML is the YAML representation of PeerLifecycleConfig.
type peerLifecycleYAML struct {
	StaleAfter       string `yaml:"stale_after"`
	OfflineAfter     string `yaml:"offline_after"`
	CleanupAfter     string `yaml:"cleanup_after"`
	KeepSAWhileStale *bool  `yaml:"keep_sa_while_stale"`
}

type configStringList []string

type identityConfig struct {
	KeyPath string
}

type identityYAML struct {
	KeyPath string `yaml:"key_path"`
}

type logConfig struct {
	Level          string
	Mode           string
	File           string
	SyslogFacility string
}

type logConfigYAML struct {
	Level          string `yaml:"level"`
	Mode           string `yaml:"mode"`
	File           string `yaml:"file"`
	SyslogFacility string `yaml:"syslog_facility"`
}

type overlayConfig struct {
	DefaultNetNS ipsec.NetNSSpec
}

type overlayDefaultsYAML struct {
	DefaultNetNS ipsec.NetNSSpec `yaml:"default_netns"`
}

type ipsecConfig struct {
	DefaultNetNS         ipsec.NetNSSpec
	LinkGroups           []ipsec.LinkGroupSpec
	Accept               string
	Driver               string
	VICISocket           string
	PortMode             string
	PortRange            ipsec.PortRange
	PortRotateInterval   time.Duration
	PortPreviousGrace    time.Duration
	AnnounceAddrs        []string
	AnnounceDNS          []string
	PublishFromEndpoints bool
}

type ipsecConfigYAML struct {
	DefaultNetNS         ipsec.NetNSSpec  `yaml:"default_netns"`
	Accept               string           `yaml:"accept"`
	Driver               string           `yaml:"driver"`
	VICISocket           string           `yaml:"vici_socket"`
	PortMode             string           `yaml:"port_mode"`
	PortRange            ipsec.PortRange  `yaml:"port_range"`
	PortRotateInterval   string           `yaml:"port_rotate_interval"`
	PortPreviousGrace    string           `yaml:"port_previous_grace"`
	AnnounceAddrs        configStringList `yaml:"announce_addrs"`
	AnnounceDNS          configStringList `yaml:"announce_dns"`
	PublishFromEndpoints *bool            `yaml:"publish_from_endpoints"`
}

type ipamConfig struct {
	AutoAnnounceAssignedIPs bool
}

type ipamConfigYAML struct {
	AutoAnnounceAssignedIPs *bool `yaml:"auto_announce_assigned_ips"`
}

type tunnelAddressConfigYAML struct {
	Mode   string `yaml:"mode"`
	Family string `yaml:"family"`
	Pool   string `yaml:"pool"`
}

type overlayGroupConfigYAML struct {
	ID                 string                  `yaml:"id"`
	Name               string                  `yaml:"name"`
	Provider           string                  `yaml:"provider"`
	NetNS              netnsRefYAML            `yaml:"netns"`
	DefaultPathMode    string                  `yaml:"default_path_mode"`
	Direction          string                  `yaml:"direction"`
	AddressSourceOrder configStringList        `yaml:"address_source_order"`
	MaxPeers           *int                    `yaml:"max_peers"`
	MaxLinksPerPeer    *int                    `yaml:"max_links_per_peer"`
	TunnelAddressPool  string                  `yaml:"tunnel_address_pool"`
	TunnelAddress      tunnelAddressConfigYAML `yaml:"tunnel_address"`
	Reconcile          overlayReconcileYAML    `yaml:"reconcile"`
	Connect            configStringList        `yaml:"connect"`
	Deny               configStringList        `yaml:"deny"`
}

type overlayReconcileYAML struct {
	Interval        string             `yaml:"interval"`
	RotateRetention string             `yaml:"rotate_retention"`
	Backoff         overlayBackoffYAML `yaml:"backoff"`
}

type overlayBackoffYAML struct {
	Initial string `yaml:"initial"`
	Max     string `yaml:"max"`
}

type netnsRefYAML struct {
	Ref        string
	Spec       ipsec.NetNSSpec
	InlineSpec bool
}

func (n *netnsRefYAML) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		n.Ref = strings.TrimSpace(node.Value)
		return nil
	case yaml.MappingNode:
		var spec ipsec.NetNSSpec
		if err := node.Decode(&spec); err != nil {
			return err
		}
		n.Spec = spec
		n.InlineSpec = true
		return nil
	default:
		return fmt.Errorf("netns must be a reference string or netns spec object")
	}
}

func loadAppConfig() (*appConfig, error) {
	config := defaultAppConfig()
	path, explicit := selectedConfigPath()
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && !explicit {
			normalizeAppConfig(config)
			return config, nil
		}
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	if err := parseConfigYAML(string(data), config); err != nil {
		return nil, err
	}
	normalizeAppConfig(config)
	return config, nil
}

func defaultAppConfig() *appConfig {
	return &appConfig{
		DataDir:             defaultDataDir,
		ListenPort:          gossip.DefaultPort,
		MaxMessageBytes:     gossip.DefaultMaxMessage,
		MaxSyncZones:        gossip.DefaultSyncLimits().MaxZones,
		MaxSyncRecords:      gossip.DefaultSyncLimits().MaxRecords,
		ReflectorInterval:   5 * time.Minute,
		ReflectorTimeout:    3 * time.Second,
		EndpointTTL:         time.Hour,
		EndpointGrace:       gossip.DefaultEndpointGrace,
		PublishEndpoints:    true,
		EndpointSourceOrder: []string{"advertise", "bootstrap", "reflector", "interface"},
		FilterPrivateIPv4:   true,
		Overlay: overlayConfig{
			DefaultNetNS: ipsec.NetNSSpec{}.Normalized(),
		},
		IPsec: ipsecConfig{
			DefaultNetNS:         ipsec.NetNSSpec{}.Normalized(),
			Accept:               ipsec.AcceptInbound,
			Driver:               ipsecDriverStrongSwan,
			PortMode:             ipsec.PortModeFixed,
			PortRotateInterval:   0,
			PortPreviousGrace:    defaultIPsecPortPreviousGrace,
			PublishFromEndpoints: true,
		},
		IPAM: ipamConfig{
			AutoAnnounceAssignedIPs: false,
		},
		Health:   defaultHealthConfig(),
		Observer: defaultObserverConfig(),
	}
}

func normalizeAppConfig(config *appConfig) {
	if config.DataDir == "" {
		config.DataDir = defaultDataDir
	}
	if config.StatePath == "" {
		config.StatePath = filepath.Join(config.DataDir, defaultStateFile)
	}
	if config.ListenPort == 0 {
		config.ListenPort = gossip.DefaultPort
	}
	if config.ListenAddr == "" {
		config.ListenAddr = fmt.Sprintf("0.0.0.0:%d", config.ListenPort)
	}
	if config.MaxMessageBytes <= 0 {
		config.MaxMessageBytes = gossip.DefaultMaxMessage
	}
	if config.MaxSyncZones <= 0 {
		config.MaxSyncZones = gossip.DefaultSyncLimits().MaxZones
	}
	if config.MaxSyncRecords <= 0 {
		config.MaxSyncRecords = gossip.DefaultSyncLimits().MaxRecords
	}
	if config.Log.Level == "" {
		config.Log.Level = config.LogLevel
	}
	if config.LogLevel == "" {
		config.LogLevel = config.Log.Level
	}
	if config.Log.Mode == "" {
		config.Log.Mode = string(logModeStderr)
	}
	if config.Log.SyslogFacility == "" {
		config.Log.SyslogFacility = "daemon"
	}
	config.Overlay.DefaultNetNS = config.Overlay.DefaultNetNS.Normalized()
	config.IPsec.DefaultNetNS = config.Overlay.DefaultNetNS
	if config.IPsec.Accept == "" {
		config.IPsec.Accept = ipsec.AcceptInbound
	}
	if config.IPsec.Driver == "" {
		config.IPsec.Driver = ipsecDriverStrongSwan
	}
	if config.IPsec.PortMode == "" {
		config.IPsec.PortMode = ipsec.PortModeFixed
	}
	if config.IPsec.PortPreviousGrace <= 0 {
		config.IPsec.PortPreviousGrace = defaultIPsecPortPreviousGrace
	}
}

func parseConfigYAML(input string, config *appConfig) error {
	if strings.TrimSpace(input) == "" {
		return nil
	}
	topLevelKeys, err := yamlTopLevelKeys(input)
	if err != nil {
		return fmt.Errorf("config.yaml: %w", err)
	}
	var file configYAML
	decoder := yaml.NewDecoder(strings.NewReader(input))
	decoder.KnownFields(true)
	if err := decoder.Decode(&file); err != nil {
		return fmt.Errorf("config.yaml: %w", err)
	}
	return applyConfigYAML(config, file, topLevelKeys)
}

func yamlTopLevelKeys(input string) (map[string]bool, error) {
	var root yaml.Node
	if err := yaml.Unmarshal([]byte(input), &root); err != nil {
		return nil, err
	}
	keys := make(map[string]bool)
	if len(root.Content) == 0 || root.Content[0].Kind != yaml.MappingNode {
		return keys, nil
	}
	for i := 0; i+1 < len(root.Content[0].Content); i += 2 {
		keys[root.Content[0].Content[i].Value] = true
	}
	return keys, nil
}

func applyConfigYAML(config *appConfig, file configYAML, topLevelKeys map[string]bool) error {
	if value := firstNonEmpty(file.DataDir, file.DatabaseDir, file.DBDir); value != "" {
		config.DataDir = value
		config.StatePath = ""
	}
	if value := firstNonEmpty(file.StatePath, file.DatabasePath, file.DBPath); value != "" {
		config.StatePath = value
	}
	if file.ManagedZone != "" {
		path := zone.ZonePath(strings.TrimSpace(file.ManagedZone))
		if !path.Valid() || path == zone.RootZone {
			return fmt.Errorf("invalid managed_zone: %s", file.ManagedZone)
		}
		config.ManagedZone = path
	}
	if file.Identity.KeyPath != "" {
		config.Identity.KeyPath = file.Identity.KeyPath
	}
	config.PeerID = firstNonEmpty(file.PeerID, config.PeerID)
	config.ListenAddr = firstNonEmpty(file.ListenAddr, config.ListenAddr)
	if file.ListenPort != nil {
		if *file.ListenPort <= 0 || *file.ListenPort > 65535 {
			return fmt.Errorf("invalid listen_port: %d", *file.ListenPort)
		}
		config.ListenPort = *file.ListenPort
		if config.ListenAddr == "" {
			config.ListenAddr = fmt.Sprintf("0.0.0.0:%d", *file.ListenPort)
		}
	}
	config.Bootstrap = append(config.Bootstrap, file.Bootstrap...)
	if value := firstNonEmpty(file.TrustedRootPublicKey, file.RootPublicKey, file.TrustedRootKey); value != "" {
		key, err := decodePublicKey(value)
		if err != nil {
			return err
		}
		config.TrustedRootPublicKey = key
	}
	// max_datagram_bytes / target_datagram_bytes take precedence over legacy max_message_bytes.
	if file.MaxDatagramBytes != nil {
		if err := applyPositiveInt(&config.MaxMessageBytes, file.MaxDatagramBytes, "max_datagram_bytes"); err != nil {
			return err
		}
	} else if file.TargetDatagramBytes != nil {
		if err := applyPositiveInt(&config.MaxMessageBytes, file.TargetDatagramBytes, "target_datagram_bytes"); err != nil {
			return err
		}
	} else if err := applyPositiveInt(&config.MaxMessageBytes, file.MaxMessageBytes, "max_message_bytes"); err != nil {
		return err
	}
	if err := applyPositiveInt(&config.MaxSyncZones, file.MaxSyncZones, "max_sync_zones"); err != nil {
		return err
	}
	if err := applyPositiveInt(&config.MaxSyncRecords, file.MaxSyncRecords, "max_sync_records"); err != nil {
		return err
	}
	if file.LogLevel != "" {
		config.LogLevel = strings.ToLower(file.LogLevel)
	}
	if file.Log.Level != "" {
		config.Log.Level = strings.ToLower(file.Log.Level)
		config.LogLevel = config.Log.Level
	}
	if file.Log.Mode != "" {
		mode := parseLogMode(file.Log.Mode)
		if !isValidLogMode(file.Log.Mode) {
			return fmt.Errorf("invalid log.mode: %s", file.Log.Mode)
		}
		config.Log.Mode = string(mode)
	}
	if file.Log.File != "" {
		config.Log.File = file.Log.File
	}
	if file.Log.SyslogFacility != "" {
		config.Log.SyslogFacility = strings.ToLower(strings.TrimSpace(file.Log.SyslogFacility))
	}
	if file.AdvertiseAddr != "" {
		config.AdvertiseAddrs = append(config.AdvertiseAddrs, file.AdvertiseAddr)
	}
	config.AdvertiseAddrs = append(config.AdvertiseAddrs, file.AdvertiseAddrs...)
	if file.Reflector != "" {
		config.Reflectors = append(config.Reflectors, file.Reflector)
	}
	config.Reflectors = append(config.Reflectors, file.Reflectors...)
	config.Reflectors = gossip.ResolvePublicIPReflectors(config.Reflectors)
	if file.ReflectorInterval != "" {
		d, err := parseConfigDuration(file.ReflectorInterval, "reflector_interval")
		if err != nil {
			return err
		}
		config.ReflectorInterval = d
	}
	if file.ReflectorTimeout != "" {
		d, err := parseConfigDuration(file.ReflectorTimeout, "reflector_timeout")
		if err != nil {
			return err
		}
		config.ReflectorTimeout = d
	}
	if file.EndpointTTL != "" {
		d, err := parseConfigDuration(file.EndpointTTL, "endpoint_ttl")
		if err != nil {
			return err
		}
		config.EndpointTTL = d
	}
	if value := firstNonEmpty(file.EndpointGrace, file.EndpointGracePeriod); value != "" {
		d, err := parseConfigDuration(value, "endpoint_grace")
		if err != nil {
			return err
		}
		config.EndpointGrace = d
	}
	if file.PublishEndpoints != nil {
		config.PublishEndpoints = *file.PublishEndpoints
	}
	if file.EndpointDiscovery != "" {
		config.EndpointDiscovery = file.EndpointDiscovery
	}
	if len(file.EndpointSourceOrder) > 0 {
		config.EndpointSourceOrder = normalizeEndpointSourceOrder([]string(file.EndpointSourceOrder))
	}
	if file.FilterPrivateIPv4 != nil {
		config.FilterPrivateIPv4 = *file.FilterPrivateIPv4
	}
	if netnsConfigured(file.IPsec.DefaultNetNS) {
		netns := file.IPsec.DefaultNetNS.Normalized()
		if err := netns.Validate(); err != nil {
			return fmt.Errorf("ipsec.default_netns: %w", err)
		}
		config.Overlay.DefaultNetNS = netns
	}
	if file.IPsec.Driver != "" {
		driver, err := parseIPsecDriver(file.IPsec.Driver)
		if err != nil {
			return err
		}
		config.IPsec.Driver = driver
	}
	if file.IPsec.Accept != "" {
		accept := strings.ToLower(strings.TrimSpace(file.IPsec.Accept))
		switch accept {
		case ipsec.AcceptNone, ipsec.AcceptInbound, ipsec.AcceptBidirectional:
			config.IPsec.Accept = accept
		default:
			return fmt.Errorf("invalid ipsec.accept %q", file.IPsec.Accept)
		}
	}
	if file.IPsec.VICISocket != "" {
		config.IPsec.VICISocket = file.IPsec.VICISocket
	}
	if file.IPsec.PortMode != "" {
		mode := strings.ToLower(strings.TrimSpace(file.IPsec.PortMode))
		if !ipsec.ValidPortMode(mode) {
			return fmt.Errorf("invalid ipsec.port_mode %q", file.IPsec.PortMode)
		}
		config.IPsec.PortMode = mode
	}
	if config.IPsec.PortMode == ipsec.PortModeRange {
		if file.IPsec.PortRange.From == 0 || file.IPsec.PortRange.To == 0 || file.IPsec.PortRange.From > file.IPsec.PortRange.To {
			return fmt.Errorf("invalid ipsec.port_range %d-%d", file.IPsec.PortRange.From, file.IPsec.PortRange.To)
		}
		config.IPsec.PortRange = file.IPsec.PortRange
	}
	if file.IPsec.PortRotateInterval != "" {
		d, err := parseConfigDuration(file.IPsec.PortRotateInterval, "ipsec.port_rotate_interval")
		if err != nil {
			return err
		}
		config.IPsec.PortRotateInterval = d
	}
	if file.IPsec.PortPreviousGrace != "" {
		d, err := parseConfigDuration(file.IPsec.PortPreviousGrace, "ipsec.port_previous_grace")
		if err != nil {
			return err
		}
		config.IPsec.PortPreviousGrace = d
	}
	config.IPsec.AnnounceAddrs = append(config.IPsec.AnnounceAddrs, file.IPsec.AnnounceAddrs...)
	config.IPsec.AnnounceDNS = append(config.IPsec.AnnounceDNS, file.IPsec.AnnounceDNS...)
	if file.IPsec.PublishFromEndpoints != nil {
		config.IPsec.PublishFromEndpoints = *file.IPsec.PublishFromEndpoints
	}
	if netnsConfigured(file.Overlay.DefaultNetNS) {
		netns := file.Overlay.DefaultNetNS.Normalized()
		if err := netns.Validate(); err != nil {
			return fmt.Errorf("overlay.default_netns: %w", err)
		}
		config.Overlay.DefaultNetNS = netns
	}
	config.IPsec.DefaultNetNS = config.Overlay.DefaultNetNS
	// Parse top-level netns section, falling back to legacy overlay.default_netns.
	config.Netns = parseNetnsConfig(file.Netns, config.Overlay.DefaultNetNS)
	// Parse routing.instances[], if any.
	if file.Routing != nil {
		var err error
		config.Routing, err = parseRoutingConfigInstances(file.Routing.Instances, config.Netns, config.DataDir)
		if err != nil {
			return err
		}
	}
	// Parse firewall.instances[], if any.
	if file.Firewall != nil {
		var err error
		config.Firewall, err = parseFirewallConfig(file.Firewall, config.Netns, config.IPsec, config.DataDir)
		if err != nil {
			return err
		}
	}
	if len(file.Overlays) > 0 {
		groups, err := parseOverlayConfigs(file.Overlays, config.Netns, config.Overlay.DefaultNetNS)
		if err != nil {
			return err
		}
		config.IPsec.LinkGroups = groups
	}
	if err := validateRotateWindows(config); err != nil {
		return err
	}
	if file.IPAM.AutoAnnounceAssignedIPs != nil {
		config.IPAM.AutoAnnounceAssignedIPs = *file.IPAM.AutoAnnounceAssignedIPs
	}
	if file.PeerLifecycle != nil {
		pl, err := parsePeerLifecycleConfig(file.PeerLifecycle)
		if err != nil {
			return err
		}
		config.PeerLifecycle = pl
	}
	if topLevelKeys["health"] {
		health := file.Health
		if health == nil {
			health = &healthConfigYAML{}
		}
		hc, err := parseHealthConfig(health)
		if err != nil {
			return err
		}
		config.Health = hc
	}
	if topLevelKeys["observer"] {
		observer := file.Observer
		if observer == nil {
			observer = &observerConfigYAML{}
		}
		oc, err := parseObserverConfig(observer)
		if err != nil {
			return err
		}
		config.Observer = oc
	}
	return nil
}

// parsePeerLifecycleConfig parses the peer_lifecycle YAML section with validation.
func parsePeerLifecycleConfig(y *peerLifecycleYAML) (PeerLifecycleConfig, error) {
	def := defaultPeerLifecycleConfig()
	out := PeerLifecycleConfig{
		StaleAfter:       def.StaleAfter,
		OfflineAfter:     def.OfflineAfter,
		CleanupAfter:     def.CleanupAfter,
		KeepSAWhileStale: def.KeepSAWhileStale,
	}
	if y.StaleAfter != "" {
		d, err := parseConfigDuration(y.StaleAfter, "peer_lifecycle.stale_after")
		if err != nil {
			return PeerLifecycleConfig{}, err
		}
		if d <= 0 {
			return PeerLifecycleConfig{}, fmt.Errorf("peer_lifecycle.stale_after must be positive, got %s", d)
		}
		out.StaleAfter = d
	}
	if y.OfflineAfter != "" {
		d, err := parseConfigDuration(y.OfflineAfter, "peer_lifecycle.offline_after")
		if err != nil {
			return PeerLifecycleConfig{}, err
		}
		if d <= 0 {
			return PeerLifecycleConfig{}, fmt.Errorf("peer_lifecycle.offline_after must be positive, got %s", d)
		}
		out.OfflineAfter = d
	}
	if y.CleanupAfter != "" {
		d, err := parseConfigDuration(y.CleanupAfter, "peer_lifecycle.cleanup_after")
		if err != nil {
			return PeerLifecycleConfig{}, err
		}
		if d <= 0 {
			return PeerLifecycleConfig{}, fmt.Errorf("peer_lifecycle.cleanup_after must be positive, got %s", d)
		}
		out.CleanupAfter = d
	}
	if y.KeepSAWhileStale != nil {
		out.KeepSAWhileStale = *y.KeepSAWhileStale
	}
	// Validate threshold ordering: stale < offline < cleanup.
	if out.StaleAfter >= out.OfflineAfter {
		return PeerLifecycleConfig{}, fmt.Errorf("peer_lifecycle.stale_after %s must be less than offline_after %s", out.StaleAfter, out.OfflineAfter)
	}
	if out.OfflineAfter >= out.CleanupAfter {
		return PeerLifecycleConfig{}, fmt.Errorf("peer_lifecycle.offline_after %s must be less than cleanup_after %s", out.OfflineAfter, out.CleanupAfter)
	}
	return out, nil
}

func validateRotateWindows(config *appConfig) error {
	maxRetention := time.Duration(0)
	for _, group := range config.IPsec.LinkGroups {
		retention := group.Normalized().Reconcile.RotateRetentionSeconds
		if retention == 0 {
			retention = defaultIPsecRotateRetentionSec
		}
		if d := time.Duration(retention) * time.Second; d > maxRetention {
			maxRetention = d
		}
	}
	if maxRetention > 0 && config.IPsec.PortPreviousGrace < maxRetention {
		return fmt.Errorf("ipsec.port_previous_grace %s must be at least overlays[].reconcile.rotate_retention %s", config.IPsec.PortPreviousGrace, maxRetention)
	}
	return nil
}

const (
	ipsecDriverDryRun     = "dry-run"
	ipsecDriverStrongSwan = "strongswan"
)

func parseIPsecDriver(value string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", ipsecDriverDryRun:
		return ipsecDriverDryRun, nil
	case ipsecDriverStrongSwan, "system", "vici":
		return ipsecDriverStrongSwan, nil
	default:
		return "", fmt.Errorf("invalid ipsec.driver %q: expected dry-run or strongswan", value)
	}
}

func parseTunnelAddressConfig(cfg tunnelAddressConfigYAML) (ipsec.TunnelAddressSpec, error) {
	mode := ipsec.TunnelAddressMode(strings.ToLower(strings.TrimSpace(cfg.Mode)))
	switch mode {
	case "", ipsec.TunnelAddressDerivedLinkLocal, ipsec.TunnelAddressDerivedPool, ipsec.TunnelAddressSequentialPool, ipsec.TunnelAddressDisabled:
		// ok
	default:
		return ipsec.TunnelAddressSpec{}, fmt.Errorf("invalid tunnel_address.mode %q", cfg.Mode)
	}
	family := strings.ToLower(strings.TrimSpace(cfg.Family))
	switch family {
	case "", ipsec.FamilyIPv4, ipsec.FamilyIPv6:
		// ok
	default:
		return ipsec.TunnelAddressSpec{}, fmt.Errorf("invalid tunnel_address.family %q", cfg.Family)
	}
	var prefix netip.Prefix
	if cfg.Pool != "" {
		var err error
		prefix, err = netip.ParsePrefix(cfg.Pool)
		if err != nil {
			return ipsec.TunnelAddressSpec{}, fmt.Errorf("invalid tunnel_address.pool %q: %w", cfg.Pool, err)
		}
		if family == "" {
			if prefix.Addr().Is4() {
				family = ipsec.FamilyIPv4
			} else {
				family = ipsec.FamilyIPv6
			}
		}
		if prefix.Addr().Is4() && family != ipsec.FamilyIPv4 {
			return ipsec.TunnelAddressSpec{}, fmt.Errorf("tunnel_address.family %q does not match pool %q", cfg.Family, cfg.Pool)
		}
		if prefix.Addr().Is6() && family != ipsec.FamilyIPv6 {
			return ipsec.TunnelAddressSpec{}, fmt.Errorf("tunnel_address.family %q does not match pool %q", cfg.Family, cfg.Pool)
		}
	}
	if mode == "" {
		if family == ipsec.FamilyIPv4 {
			mode = ipsec.TunnelAddressDisabled
		} else {
			mode = ipsec.TunnelAddressDerivedLinkLocal
		}
	}
	if (mode == ipsec.TunnelAddressDerivedPool || mode == ipsec.TunnelAddressSequentialPool) && !prefix.IsValid() {
		return ipsec.TunnelAddressSpec{}, fmt.Errorf("tunnel_address.mode %q requires a pool", mode)
	}
	return ipsec.TunnelAddressSpec{
		Mode:   mode,
		Family: family,
		Pool:   prefix,
	}, nil
}

func parseOverlayConfigs(overlays []overlayGroupConfigYAML, netnsCfg netnsConfig, defaultNetNS ipsec.NetNSSpec) ([]ipsec.LinkGroupSpec, error) {
	groups := make([]ipsec.LinkGroupSpec, 0, len(overlays))
	for i, overlay := range overlays {
		group, err := parseOverlayConfig(overlay, netnsCfg, defaultNetNS)
		if err != nil {
			return nil, fmt.Errorf("overlays[%d]: %w", i, err)
		}
		groups = append(groups, group)
	}
	return groups, nil
}

func parseOverlayConfig(overlay overlayGroupConfigYAML, netnsCfg netnsConfig, defaultNetNS ipsec.NetNSSpec) (ipsec.LinkGroupSpec, error) {
	netns, err := resolveNetNSRef(overlay.NetNS, netnsCfg, defaultNetNS)
	if err != nil {
		return ipsec.LinkGroupSpec{}, fmt.Errorf("netns: %w", err)
	}
	if overlay.Direction != "" {
		return ipsec.LinkGroupSpec{}, fmt.Errorf("overlays[].direction is deprecated; use ipsec.accept instead")
	}
	group := ipsec.LinkGroupSpec{
		ID:                 overlay.ID,
		Name:               overlay.Name,
		Provider:           overlay.Provider,
		NetNS:              netns,
		DefaultPathMode:    overlay.DefaultPathMode,
		AddressSourceOrder: append([]string(nil), overlay.AddressSourceOrder...),
		ConnectRules:       append([]string(nil), overlay.Connect...),
		DenyRules:          append([]string(nil), overlay.Deny...),
	}
	if group.ID == "" {
		group.ID = group.Name
	}
	if overlay.MaxPeers != nil {
		group.MaxPeers = *overlay.MaxPeers
	}
	if overlay.MaxLinksPerPeer != nil {
		group.MaxLinksPerPeer = *overlay.MaxLinksPerPeer
	}
	legacyPoolSet := overlay.TunnelAddressPool != ""
	newBlockSet := overlay.TunnelAddress.Mode != "" || overlay.TunnelAddress.Family != "" || overlay.TunnelAddress.Pool != ""
	if legacyPoolSet && newBlockSet {
		return ipsec.LinkGroupSpec{}, fmt.Errorf("cannot mix tunnel_address_pool with tunnel_address")
	}
	if legacyPoolSet {
		prefix, err := netip.ParsePrefix(overlay.TunnelAddressPool)
		if err != nil {
			return ipsec.LinkGroupSpec{}, fmt.Errorf("invalid tunnel_address_pool %q: %w", overlay.TunnelAddressPool, err)
		}
		group.TunnelAddressPool = prefix
	}
	if newBlockSet {
		spec, err := parseTunnelAddressConfig(overlay.TunnelAddress)
		if err != nil {
			return ipsec.LinkGroupSpec{}, err
		}
		group.TunnelAddressSpec = spec
	}
	if overlay.Reconcile.Interval != "" {
		d, err := parseConfigDuration(overlay.Reconcile.Interval, "reconcile.interval")
		if err != nil {
			return ipsec.LinkGroupSpec{}, err
		}
		group.Reconcile.IntervalSeconds = durationSeconds(d)
	}
	if overlay.Reconcile.RotateRetention != "" {
		d, err := parseConfigDuration(overlay.Reconcile.RotateRetention, "reconcile.rotate_retention")
		if err != nil {
			return ipsec.LinkGroupSpec{}, err
		}
		group.Reconcile.RotateRetentionSeconds = durationSeconds(d)
	}
	if overlay.Reconcile.Backoff.Initial != "" {
		d, err := parseConfigDuration(overlay.Reconcile.Backoff.Initial, "reconcile.backoff.initial")
		if err != nil {
			return ipsec.LinkGroupSpec{}, err
		}
		group.Reconcile.Backoff.InitialSeconds = durationSeconds(d)
	}
	if overlay.Reconcile.Backoff.Max != "" {
		d, err := parseConfigDuration(overlay.Reconcile.Backoff.Max, "reconcile.backoff.max")
		if err != nil {
			return ipsec.LinkGroupSpec{}, err
		}
		group.Reconcile.Backoff.MaxSeconds = durationSeconds(d)
	}
	if err := group.Validate(); err != nil {
		return ipsec.LinkGroupSpec{}, err
	}
	if _, err := ipsec.ParseMeshPolicyRules(group.ConnectRules); err != nil {
		return ipsec.LinkGroupSpec{}, fmt.Errorf("connect: %w", err)
	}
	if _, err := ipsec.ParseMeshPolicyRules(group.DenyRules); err != nil {
		return ipsec.LinkGroupSpec{}, fmt.Errorf("deny: %w", err)
	}
	return group.Normalized(), nil
}

func resolveNetNSRef(ref netnsRefYAML, netnsCfg netnsConfig, fallback ipsec.NetNSSpec) (ipsec.NetNSSpec, error) {
	if ref.Ref != "" {
		spec, ok := netnsCfg.Names[ref.Ref]
		if !ok {
			return ipsec.NetNSSpec{}, fmt.Errorf("unknown netns %q", ref.Ref)
		}
		return spec, nil
	}
	if ref.InlineSpec {
		spec := ref.Spec.Normalized()
		if err := spec.Validate(); err != nil {
			return ipsec.NetNSSpec{}, err
		}
		return spec, nil
	}
	key := netnsCfg.Default
	if key == "" {
		key = "default"
	}
	if spec, ok := netnsCfg.Names[key]; ok {
		return spec, nil
	}
	spec := fallback.Normalized()
	if err := spec.Validate(); err != nil {
		return ipsec.NetNSSpec{}, err
	}
	return spec, nil
}

func (list *configStringList) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.SequenceNode {
		var values []string
		if err := node.Decode(&values); err != nil {
			return err
		}
		*list = append((*list)[:0], values...)
		return nil
	}
	var value string
	if err := node.Decode(&value); err != nil {
		return err
	}
	*list = (*list)[:0]
	for _, v := range strings.Split(value, ",") {
		if v = strings.TrimSpace(v); v != "" {
			*list = append(*list, v)
		}
	}
	return nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func netnsConfigured(spec ipsec.NetNSSpec) bool {
	return spec.Kind != "" || spec.Name != "" || spec.Path != "" || spec.Create
}

func applyPositiveInt(target *int, value *int, name string) error {
	if value == nil {
		return nil
	}
	if *value <= 0 {
		return fmt.Errorf("invalid %s: %d", name, *value)
	}
	*target = *value
	return nil
}

func parseConfigDuration(value, name string) (time.Duration, error) {
	d, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("invalid %s: %q", name, value)
	}
	return d, nil
}

func normalizeEndpointSourceOrder(order []string) []string {
	valid := map[string]bool{"bootstrap": true, "advertise": true, "reflector": true, "interface": true}
	seen := make(map[string]bool)
	var out []string
	for _, s := range order {
		s = strings.ToLower(strings.TrimSpace(s))
		if s == "" || !valid[s] || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	if len(out) == 0 {
		return []string{"advertise", "bootstrap", "reflector", "interface"}
	}
	return out
}

func durationSeconds(d time.Duration) int {
	if d <= 0 {
		return 0
	}
	return int(d.Round(time.Second) / time.Second)
}

func decodePublicKey(value string) (ed25519.PublicKey, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	if decoded, err := hex.DecodeString(value); err == nil {
		if len(decoded) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("trusted root public key must be %d bytes", ed25519.PublicKeySize)
		}
		return ed25519.PublicKey(decoded), nil
	}
	for _, encoding := range []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
	} {
		decoded, err := encoding.DecodeString(value)
		if err == nil {
			if len(decoded) != ed25519.PublicKeySize {
				return nil, fmt.Errorf("trusted root public key must be %d bytes", ed25519.PublicKeySize)
			}
			return ed25519.PublicKey(decoded), nil
		}
	}
	return nil, fmt.Errorf("trusted root public key must be hex or base64")
}

func configPath() string {
	path, _ := selectedConfigPath()
	return path
}

func selectedConfigPath() (string, bool) {
	if path := os.Getenv("HIGGS_CONFIG"); path != "" {
		return path, true
	}
	return defaultConfigPath, false
}

func configuredStatePath() (string, error) {
	if path := statePathOverride(); path != "" {
		return path, nil
	}
	config, err := loadAppConfig()
	if err != nil {
		return "", err
	}
	return config.StatePath, nil
}

func statePathOverride() string {
	return os.Getenv("HIGGS_STATE")
}

func configuredSyncConfig(state *stateFile) (*syncConfigFile, error) {
	config, err := loadAppConfig()
	if err != nil {
		return nil, err
	}
	return syncConfigFromAppConfig(config, state), nil
}

func syncConfigFromAppConfig(config *appConfig, state *stateFile) *syncConfigFile {
	peerID := config.PeerID
	if peerID == "" {
		peerID = defaultPeerID(state)
	}
	return &syncConfigFile{
		PeerID:                 peerID,
		ListenAddr:             config.ListenAddr,
		Bootstrap:              config.Bootstrap,
		MaxMessageBytes:        config.MaxMessageBytes,
		MaxSyncZones:           config.MaxSyncZones,
		MaxSyncRecords:         config.MaxSyncRecords,
		LogLevel:               config.LogLevel,
		LogMode:                config.Log.Mode,
		LogFile:                config.Log.File,
		LogSyslogFacility:      config.Log.SyslogFacility,
		AdvertiseAddrs:         config.AdvertiseAddrs,
		Reflectors:             config.Reflectors,
		ReflectorInterval:      config.ReflectorInterval,
		ReflectorTimeout:       config.ReflectorTimeout,
		EndpointTTL:            config.EndpointTTL,
		EndpointGrace:          config.EndpointGrace,
		DisableEndpointPublish: !config.PublishEndpoints,
		EndpointDiscovery:      config.EndpointDiscovery,
		EndpointSourceOrder:    config.EndpointSourceOrder,
		FilterPrivateIPv4:      config.FilterPrivateIPv4,
	}
}

func configuredKnownPeers(config *syncConfigFile) map[string]*net.UDPAddr {
	peers := make(map[string]*net.UDPAddr, len(config.Bootstrap))
	for _, peer := range config.Bootstrap {
		if peer.ID == "" || peer.Addr == "" {
			continue
		}
		addr, err := net.ResolveUDPAddr("udp", peer.Addr)
		if err != nil {
			continue
		}
		peers[peer.ID] = addr
	}
	return peers
}

func enabledFromPresence(enabledName, disabledName string, presentDefault bool, enabled, disabled *bool) (bool, error) {
	out := presentDefault
	if enabled != nil {
		out = *enabled
	}
	if disabled != nil {
		disabledValue := *disabled
		if enabled != nil && *enabled == disabledValue {
			return false, fmt.Errorf("%s conflicts with %s", enabledName, disabledName)
		}
		out = !disabledValue
	}
	return out, nil
}
