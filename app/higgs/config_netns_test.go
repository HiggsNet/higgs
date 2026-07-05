package main

import (
	"github.com/Catofes/higgs/pkg/transport/ipsec"
	"testing"
)

func TestParseConfigYAMLNetNSDefault(t *testing.T) {
	config := defaultAppConfig()
	input := `
netns:
  default:
    kind: name
    name: higgstesth2
    create: true
`
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	normalizeAppConfig(config)
	if config.Netns.Default != "default" {
		t.Fatalf("Netns.Default = %q, want default", config.Netns.Default)
	}
	spec := config.Netns.Names["default"]
	if spec.Kind != ipsec.NetNSName || spec.Name != "higgstesth2" || !spec.Create {
		t.Fatalf("Netns.Names[default] = %+v", spec)
	}
}

func TestParseConfigYAMLRejectsLegacyDefaultNetNS(t *testing.T) {
	for _, input := range []string{`
ipsec:
  default_netns:
    kind: name
    name: legacytesth2
    create: true
`, `
overlay:
  default_netns:
    kind: name
    name: legacytesth2
    create: true
`} {
		config := defaultAppConfig()
		if err := parseConfigYAML(input, config); err == nil {
			t.Fatalf("parseConfigYAML should reject legacy default_netns: %s", input)
		}
	}
}

func TestParseConfigYAMLNetNSNamedSiblings(t *testing.T) {
	config := defaultAppConfig()
	input := `
netns:
  default:
    kind: name
    name: higgstesth2
    create: true
  edge:
    kind: name
    name: edge
    create: true
`
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	normalizeAppConfig(config)
	if spec, ok := config.Netns.Names["default"]; !ok || spec.Name != "higgstesth2" || !spec.Create {
		t.Fatalf("netns.default = %+v, ok=%t", spec, ok)
	}
	if spec, ok := config.Netns.Names["edge"]; !ok || spec.Name != "edge" || !spec.Create {
		t.Fatalf("netns.edge = %+v, ok=%t", spec, ok)
	}
}
