package main

import "testing"

func TestParseConfigYAMLNetNSForwarding(t *testing.T) {
	config := defaultAppConfig()
	input := `
netns:
  default:
    kind: name
    name: higgstesth2
    create: true
    forwarding:
      transit: true
      allow_prefixes:
        - 10.42.0.0/16
      deny_prefixes:
        - 10.42.99.0/24
`
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	for _, key := range []string{"default", "higgstesth2"} {
		policy := config.Netns.Forwarding[key]
		if !policy.Transit || len(policy.AllowPrefixes) != 1 || len(policy.DenyPrefixes) != 1 {
			t.Fatalf("Netns.Forwarding[%q] = %+v", key, policy)
		}
	}
}

func TestParseConfigYAMLRejectsFirewallForwarding(t *testing.T) {
	config := defaultAppConfig()
	err := parseConfigYAML(`
firewall:
  instances:
    - id: mesh
      forwarding:
        transit: true
`, config)
	if err == nil {
		t.Fatal("parseConfigYAML should reject forwarding under firewall instance")
	}
}

func TestParseConfigYAMLNamedNetNSForwardingUsesTargetAlias(t *testing.T) {
	config := defaultAppConfig()
	if err := parseConfigYAML(`
netns:
  edge:
    kind: name
    name: physical-edge
    create: true
    forwarding:
      transit: true
`, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	if !netnsForwardingPolicy(config, "edge").Transit || !netnsForwardingPolicy(config, "physical-edge").Transit {
		t.Fatal("named netns policy should be available by config key and resolved target")
	}
}
