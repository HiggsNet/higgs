package photonwindows

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func validConfigYAML() string {
	root := make([]byte, ed25519.PublicKeySize)
	for i := range root {
		root[i] = byte(i)
	}
	return `schema_version: 1
trusted_root_public_key: ` + base64.StdEncoding.EncodeToString(root) + `
managed_zone: laptop-a.catofes.
state:
  path: C:\ProgramData\HiggsNet\Photon Windows\photon.db
overlay:
  id: main
  split_routes:
    - 10.42.0.0/16
    - fd42::/16
gateway:
  allowed_zones:
    - gateway-a.catofes.
  bootstrap_hints:
    - peer: gateway-a.catofes.
      address: gateway.example.net:33434
wintun: {}
log: {}
reconnect: {}
`
}

func TestParseConfigAppliesSafeDefaults(t *testing.T) {
	config, err := ParseConfig(strings.NewReader(validConfigYAML()))
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	if config.ManagedZone != "laptop-a.catofes." || config.Wintun.AdapterName != "Photon Windows" {
		t.Fatalf("unexpected config: %#v", config)
	}
	if config.Wintun.MTU != 1400 || config.Log.Level != "info" {
		t.Fatalf("defaults MTU/log = %d/%q", config.Wintun.MTU, config.Log.Level)
	}
	if config.Reconnect.InitialBackoff != time.Second || config.Reconnect.MaxBackoff != time.Minute {
		t.Fatalf("reconnect defaults = %s/%s", config.Reconnect.InitialBackoff, config.Reconnect.MaxBackoff)
	}
	if len(config.Overlay.SplitRoutes) != 2 || len(config.Gateway.BootstrapHints) != 1 {
		t.Fatalf("routes/hints = %v/%v", config.Overlay.SplitRoutes, config.Gateway.BootstrapHints)
	}
}

func TestParseConfigRejectsUnknownField(t *testing.T) {
	_, err := ParseConfig(strings.NewReader(validConfigYAML() + "surprise: true\n"))
	if err == nil || !strings.Contains(err.Error(), "field surprise not found") {
		t.Fatalf("error = %v, want strict unknown-field failure", err)
	}
}

func TestParseConfigRejectsMissingRootTrust(t *testing.T) {
	input := strings.Replace(validConfigYAML(), "trusted_root_public_key: ", "unused: ", 1)
	_, err := ParseConfig(strings.NewReader(input))
	if err == nil {
		t.Fatal("ParseConfig accepted missing root trust")
	}
}

func TestParseConfigRejectsDefaultRoute(t *testing.T) {
	input := strings.Replace(validConfigYAML(), "10.42.0.0/16", "0.0.0.0/0", 1)
	_, err := ParseConfig(strings.NewReader(input))
	if err == nil || !strings.Contains(err.Error(), "split-tunnel only") {
		t.Fatalf("error = %v, want split-tunnel failure", err)
	}
}

func TestParseConfigRejectsUnselectedBootstrapPeer(t *testing.T) {
	input := strings.Replace(validConfigYAML(), "peer: gateway-a.catofes.", "peer: gateway-b.catofes.", 1)
	_, err := ParseConfig(strings.NewReader(input))
	if err == nil || !strings.Contains(err.Error(), "must appear") {
		t.Fatalf("error = %v, want selector failure", err)
	}
}

func TestParseConfigRejectsSecondDocument(t *testing.T) {
	_, err := ParseConfig(strings.NewReader(validConfigYAML() + "---\nlog: {}\n"))
	if err == nil || !strings.Contains(err.Error(), "multiple YAML documents") {
		t.Fatalf("error = %v, want multiple-document failure", err)
	}
}
