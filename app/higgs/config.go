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
	"strconv"
	"strings"

	"github.com/Catofes/higgs/pkg/core/gossip"
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
}

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
		DataDir:    ".",
		ListenPort: gossip.DefaultPort,
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
}

func parseConfigYAML(input string, config *appConfig) error {
	var section string
	var currentPeer *syncConfigPeer
	for lineNumber, raw := range strings.Split(input, "\n") {
		line := strings.TrimSpace(stripYAMLComment(raw))
		if line == "" {
			continue
		}
		if line == "bootstrap:" {
			section = "bootstrap"
			currentPeer = nil
			continue
		}
		if strings.HasPrefix(line, "- ") {
			if section != "bootstrap" {
				return fmt.Errorf("config.yaml:%d: list item outside bootstrap", lineNumber+1)
			}
			config.Bootstrap = append(config.Bootstrap, syncConfigPeer{})
			currentPeer = &config.Bootstrap[len(config.Bootstrap)-1]
			rest := strings.TrimSpace(strings.TrimPrefix(line, "- "))
			if rest == "" {
				continue
			}
			key, value, err := parseYAMLKeyValue(rest)
			if err != nil {
				return fmt.Errorf("config.yaml:%d: %w", lineNumber+1, err)
			}
			applyBootstrapValue(currentPeer, key, value)
			continue
		}
		key, value, err := parseYAMLKeyValue(line)
		if err != nil {
			return fmt.Errorf("config.yaml:%d: %w", lineNumber+1, err)
		}
		if section == "bootstrap" && currentPeer != nil && (key == "id" || key == "addr") {
			applyBootstrapValue(currentPeer, key, value)
			continue
		}
		section = ""
		currentPeer = nil
		if err := applyConfigValue(config, key, value); err != nil {
			return fmt.Errorf("config.yaml:%d: %w", lineNumber+1, err)
		}
	}
	return nil
}

func stripYAMLComment(line string) string {
	inSingle := false
	inDouble := false
	for i, r := range line {
		switch r {
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
		case '#':
			if !inSingle && !inDouble {
				return line[:i]
			}
		}
	}
	return line
}

func parseYAMLKeyValue(line string) (string, string, error) {
	key, value, ok := strings.Cut(line, ":")
	if !ok {
		return "", "", fmt.Errorf("expected key: value")
	}
	key = strings.TrimSpace(key)
	value = unquoteYAMLValue(strings.TrimSpace(value))
	if key == "" {
		return "", "", fmt.Errorf("empty key")
	}
	return key, value, nil
}

func unquoteYAMLValue(value string) string {
	if len(value) < 2 {
		return value
	}
	if (value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'') {
		return value[1 : len(value)-1]
	}
	return value
}

func applyConfigValue(config *appConfig, key, value string) error {
	switch key {
	case "data_dir", "database_dir", "db_dir":
		config.DataDir = value
		config.StatePath = ""
	case "state_path", "database_path", "db_path":
		config.StatePath = value
	case "peer_id":
		config.PeerID = value
	case "listen_addr":
		config.ListenAddr = value
	case "listen_port":
		port, err := strconv.Atoi(value)
		if err != nil || port <= 0 || port > 65535 {
			return fmt.Errorf("invalid listen_port: %q", value)
		}
		config.ListenPort = port
		if config.ListenAddr == "" {
			config.ListenAddr = fmt.Sprintf(":%d", port)
		}
	case "trusted_root_public_key", "root_public_key", "trusted_root_key":
		key, err := decodePublicKey(value)
		if err != nil {
			return err
		}
		config.TrustedRootPublicKey = key
	default:
		return fmt.Errorf("unknown config key %q", key)
	}
	return nil
}

func applyBootstrapValue(peer *syncConfigPeer, key, value string) {
	switch key {
	case "id":
		peer.ID = value
	case "addr":
		peer.Addr = value
	}
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
	if path := os.Getenv("HIGGS_STATE"); path != "" {
		return path, nil
	}
	config, err := loadAppConfig()
	if err != nil {
		return "", err
	}
	return config.StatePath, nil
}

func configuredSyncConfig(state *stateFile) (*syncConfigFile, error) {
	config, err := loadAppConfig()
	if err != nil {
		return nil, err
	}
	peerID := config.PeerID
	if peerID == "" {
		peerID = defaultPeerID(state)
	}
	return &syncConfigFile{
		PeerID:     peerID,
		ListenAddr: config.ListenAddr,
		Bootstrap:  config.Bootstrap,
	}, nil
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
