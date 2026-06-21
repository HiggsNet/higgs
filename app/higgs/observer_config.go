package main

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// observerConfig is the application-layer configuration for the read-only web
// status observer (Phase 6.7). It maps to the observer.* YAML section.
//
// The observer provides a read-only HTTP server that serves REST snapshot APIs
// and a static UI for visualising daemon live state. It is disabled when the
// observer section is absent; a present observer section enables it unless
// observer.disabled: true (or legacy observer.enabled: false) is set.
type observerConfig struct {
	Enabled            bool
	BindAddr           string
	Port               int
	UIPath             string
	EventBufferSeconds int
}

// observerConfigYAML is the YAML representation of observerConfig.
type observerConfigYAML struct {
	Enabled            *bool  `yaml:"enabled"`
	Disabled           *bool  `yaml:"disabled"`
	Listen             string `yaml:"listen"`
	BindAddr           string `yaml:"bind_addr"`
	Port               *int   `yaml:"port"`
	UIPath             string `yaml:"ui_path"`
	EventBufferSeconds *int   `yaml:"event_buffer_seconds"`
}

const (
	defaultObserverBindAddr = "127.0.0.1"
	defaultObserverPort     = 8080
)

func defaultObserverConfig() observerConfig {
	return observerConfig{
		Enabled:            false,
		BindAddr:           defaultObserverBindAddr,
		Port:               defaultObserverPort,
		UIPath:             "",
		EventBufferSeconds: 0,
	}
}

// parseObserverConfig parses the observer.* YAML section with validation.
func parseObserverConfig(y *observerConfigYAML) (observerConfig, error) {
	out := defaultObserverConfig()
	if y == nil {
		return out, nil
	}
	enabled, err := enabledFromPresence("observer.enabled", "observer.disabled", true, y.Enabled, y.Disabled)
	if err != nil {
		return observerConfig{}, err
	}
	out.Enabled = enabled
	if y.Listen != "" {
		if y.BindAddr != "" || y.Port != nil {
			return observerConfig{}, fmt.Errorf("observer.listen cannot be combined with observer.bind_addr or observer.port")
		}
		host, portText, err := net.SplitHostPort(strings.TrimSpace(y.Listen))
		if err != nil {
			return observerConfig{}, fmt.Errorf("invalid observer.listen %q: %w", y.Listen, err)
		}
		if strings.TrimSpace(host) == "" {
			return observerConfig{}, fmt.Errorf("observer.listen host must not be empty")
		}
		port, err := strconv.Atoi(portText)
		if err != nil || port <= 0 || port > 65535 {
			return observerConfig{}, fmt.Errorf("observer.listen port must be between 1 and 65535, got %q", portText)
		}
		out.BindAddr = host
		out.Port = port
	}
	if y.BindAddr != "" {
		addr := strings.TrimSpace(y.BindAddr)
		if addr == "" {
			return observerConfig{}, fmt.Errorf("observer.bind_addr must not be empty")
		}
		out.BindAddr = addr
	}
	if y.Port != nil {
		if *y.Port <= 0 || *y.Port > 65535 {
			return observerConfig{}, fmt.Errorf("observer.port must be between 1 and 65535, got %d", *y.Port)
		}
		out.Port = *y.Port
	}
	if y.UIPath != "" {
		uiPath := strings.TrimSpace(y.UIPath)
		if uiPath != "" && !strings.HasPrefix(uiPath, "/") {
			uiPath = "/" + uiPath
		}
		out.UIPath = uiPath
	}
	if y.EventBufferSeconds != nil {
		if *y.EventBufferSeconds < 0 {
			return observerConfig{}, fmt.Errorf("observer.event_buffer_seconds must be non-negative, got %d", *y.EventBufferSeconds)
		}
		out.EventBufferSeconds = *y.EventBufferSeconds
	}
	return out, nil
}

// listenAddr returns the full listen address (host:port) for the observer.
func (c observerConfig) listenAddr() string {
	return net.JoinHostPort(c.BindAddr, strconv.Itoa(c.Port))
}

// isLoopbackBind returns true when the bind address is loopback, meaning the
// observer is only accessible from localhost.
func (c observerConfig) isLoopbackBind() bool {
	switch c.BindAddr {
	case "127.0.0.1", "::1", "localhost":
		return true
	default:
		return false
	}
}
