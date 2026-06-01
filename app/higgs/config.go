package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Catofes/higgs/pkg/core/gossip"
	"gopkg.in/yaml.v3"
)

const (
	defaultConfigPath = "config.yaml"
	defaultStateFile  = "higgs.db"
)

type appConfig struct {
	DataDir              string
	StatePath            string
	PeerID               string
	ListenAddr           string
	ListenPort           int
	Bootstrap            []syncConfigPeer
	TrustedRootPublicKey ed25519.PublicKey
	MaxMessageBytes      int
	MaxSyncZones         int
	MaxSyncRecords       int
	LogLevel             string
	AdvertiseAddrs       []string
	Reflectors           []string
	ReflectorInterval    time.Duration
	EndpointTTL          time.Duration
	EndpointGrace        time.Duration
}

type configYAML struct {
	DataDir     string `yaml:"data_dir"`
	DatabaseDir string `yaml:"database_dir"`
	DBDir       string `yaml:"db_dir"`

	StatePath    string `yaml:"state_path"`
	DatabasePath string `yaml:"database_path"`
	DBPath       string `yaml:"db_path"`

	PeerID     string `yaml:"peer_id"`
	ListenAddr string `yaml:"listen_addr"`
	ListenPort *int   `yaml:"listen_port"`

	Bootstrap []syncConfigPeer `yaml:"bootstrap"`

	TrustedRootPublicKey string `yaml:"trusted_root_public_key"`
	RootPublicKey        string `yaml:"root_public_key"`
	TrustedRootKey       string `yaml:"trusted_root_key"`

	MaxMessageBytes *int `yaml:"max_message_bytes"`
	MaxSyncZones    *int `yaml:"max_sync_zones"`
	MaxSyncRecords  *int `yaml:"max_sync_records"`

	LogLevel string `yaml:"log_level"`

	AdvertiseAddr  string           `yaml:"advertise_addr"`
	AdvertiseAddrs configStringList `yaml:"advertise_addrs"`
	Reflector      string           `yaml:"reflector"`
	Reflectors     configStringList `yaml:"reflectors"`

	ReflectorInterval   string `yaml:"reflector_interval"`
	EndpointTTL         string `yaml:"endpoint_ttl"`
	EndpointGrace       string `yaml:"endpoint_grace"`
	EndpointGracePeriod string `yaml:"endpoint_grace_period"`
}

type configStringList []string

func loadAppConfig() (*appConfig, error) {
	config := defaultAppConfig()
	data, err := os.ReadFile(configPath())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			normalizeAppConfig(config)
			return config, nil
		}
		return nil, err
	}
	if err := parseConfigYAML(string(data), config); err != nil {
		return nil, err
	}
	normalizeAppConfig(config)
	return config, nil
}

func defaultAppConfig() *appConfig {
	return &appConfig{
		DataDir:           ".",
		ListenPort:        gossip.DefaultPort,
		MaxMessageBytes:   gossip.DefaultMaxMessage,
		MaxSyncZones:      gossip.DefaultSyncLimits().MaxZones,
		MaxSyncRecords:    gossip.DefaultSyncLimits().MaxRecords,
		ReflectorInterval: 5 * time.Minute,
		EndpointTTL:       time.Hour,
		EndpointGrace:     gossip.DefaultEndpointGrace,
	}
}

func normalizeAppConfig(config *appConfig) {
	if config.DataDir == "" {
		config.DataDir = "."
	}
	if config.StatePath == "" {
		if config.DataDir == "." {
			config.StatePath = defaultStatePath
		} else {
			config.StatePath = filepath.Join(config.DataDir, defaultStateFile)
		}
	}
	if config.ListenPort == 0 {
		config.ListenPort = gossip.DefaultPort
	}
	if config.ListenAddr == "" {
		config.ListenAddr = fmt.Sprintf(":%d", config.ListenPort)
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
}

func parseConfigYAML(input string, config *appConfig) error {
	if strings.TrimSpace(input) == "" {
		return nil
	}
	var file configYAML
	decoder := yaml.NewDecoder(strings.NewReader(input))
	decoder.KnownFields(true)
	if err := decoder.Decode(&file); err != nil {
		return fmt.Errorf("config.yaml: %w", err)
	}
	return applyConfigYAML(config, file)
}

func applyConfigYAML(config *appConfig, file configYAML) error {
	if value := firstNonEmpty(file.DataDir, file.DatabaseDir, file.DBDir); value != "" {
		config.DataDir = value
		config.StatePath = ""
	}
	if value := firstNonEmpty(file.StatePath, file.DatabasePath, file.DBPath); value != "" {
		config.StatePath = value
	}
	config.PeerID = firstNonEmpty(file.PeerID, config.PeerID)
	config.ListenAddr = firstNonEmpty(file.ListenAddr, config.ListenAddr)
	if file.ListenPort != nil {
		if *file.ListenPort <= 0 || *file.ListenPort > 65535 {
			return fmt.Errorf("invalid listen_port: %d", *file.ListenPort)
		}
		config.ListenPort = *file.ListenPort
		if config.ListenAddr == "" {
			config.ListenAddr = fmt.Sprintf(":%d", *file.ListenPort)
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
	if err := applyPositiveInt(&config.MaxMessageBytes, file.MaxMessageBytes, "max_message_bytes"); err != nil {
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
	if file.AdvertiseAddr != "" {
		config.AdvertiseAddrs = append(config.AdvertiseAddrs, file.AdvertiseAddr)
	}
	config.AdvertiseAddrs = append(config.AdvertiseAddrs, file.AdvertiseAddrs...)
	if file.Reflector != "" {
		config.Reflectors = append(config.Reflectors, file.Reflector)
	}
	config.Reflectors = append(config.Reflectors, file.Reflectors...)
	if file.ReflectorInterval != "" {
		d, err := parseConfigDuration(file.ReflectorInterval, "reflector_interval")
		if err != nil {
			return err
		}
		config.ReflectorInterval = d
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
	return nil
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
	if path := os.Getenv("HIGGS_CONFIG"); path != "" {
		return path
	}
	return defaultConfigPath
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
		PeerID:            peerID,
		ListenAddr:        config.ListenAddr,
		Bootstrap:         config.Bootstrap,
		MaxMessageBytes:   config.MaxMessageBytes,
		MaxSyncZones:      config.MaxSyncZones,
		MaxSyncRecords:    config.MaxSyncRecords,
		LogLevel:          config.LogLevel,
		AdvertiseAddrs:    config.AdvertiseAddrs,
		Reflectors:        config.Reflectors,
		ReflectorInterval: config.ReflectorInterval,
		EndpointTTL:       config.EndpointTTL,
		EndpointGrace:     config.EndpointGrace,
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
