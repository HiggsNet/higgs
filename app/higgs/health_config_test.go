package main

import "testing"

func TestParseHealthConfigDefault(t *testing.T) {
	cfg, err := parseHealthConfig(nil)
	if err != nil {
		t.Fatalf("parseHealthConfig(nil): %v", err)
	}
	if cfg.Enabled {
		t.Fatal("default health should be disabled")
	}
}

func TestParseHealthConfigEnabledByPresence(t *testing.T) {
	cfg, err := parseHealthConfig(&healthConfigYAML{})
	if err != nil {
		t.Fatalf("parseHealthConfig: %v", err)
	}
	if !cfg.Enabled {
		t.Fatal("health should be enabled when the section is present")
	}
}

func TestParseHealthConfigDisabled(t *testing.T) {
	disabled := true
	cfg, err := parseHealthConfig(&healthConfigYAML{Disabled: &disabled})
	if err != nil {
		t.Fatalf("parseHealthConfig: %v", err)
	}
	if cfg.Enabled {
		t.Fatal("health should be disabled")
	}
}

func TestParseHealthConfigMetricsEnabledByPresence(t *testing.T) {
	cfg, err := parseHealthConfig(&healthConfigYAML{Metrics: &healthMetricsYAML{}})
	if err != nil {
		t.Fatalf("parseHealthConfig: %v", err)
	}
	if !cfg.MetricsEnabled {
		t.Fatal("health metrics should be enabled when the metrics section is present")
	}
}

func TestParseHealthConfigMetricsDisabled(t *testing.T) {
	disabled := true
	cfg, err := parseHealthConfig(&healthConfigYAML{Metrics: &healthMetricsYAML{Disabled: &disabled}})
	if err != nil {
		t.Fatalf("parseHealthConfig: %v", err)
	}
	if cfg.MetricsEnabled {
		t.Fatal("health metrics should be disabled")
	}
}
