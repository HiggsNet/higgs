package text

import (
	"strings"
	"testing"

	"github.com/Catofes/higgs/internal/inspect"
)

func TestWriteDebugFirewallNotConfigured(t *testing.T) {
	var buf strings.Builder
	if err := WriteDebugFirewall(&buf, inspect.FirewallDebugView{}); err != nil {
		t.Fatalf("WriteDebugFirewall: %v", err)
	}
	if got, want := buf.String(), "firewall: not configured\n"; got != want {
		t.Fatalf("output = %q, want %q", got, want)
	}
}

func TestWriteDebugFirewallInstanceOutput(t *testing.T) {
	view := inspect.FirewallDebugView{
		Backend: "dry-run",
		Instances: []inspect.FirewallInstanceView{
			{
				ID:            "higgstesth2",
				Scope:         "higgstesth2",
				Mode:          "managed",
				Backend:       "auto",
				DefaultPolicy: "drop",
				Transit:       true,
				AllowPrefixes: 2,
				DenyPrefixes:  1,
				LocalServices: []inspect.FirewallLocalServiceView{{Proto: "udp", Port: 4500}},
				Generation:    5,
				OwnedObjects:  10,
				PolicyHash:    "abc123",
			},
			{
				ID:            "host",
				Scope:         "host",
				Mode:          "managed",
				DefaultPolicy: "drop",
				IsHost:        true,
				HostIKE:       true,
				HostNATT:      true,
				RedirectGrace: true,
			},
		},
	}
	var buf strings.Builder
	if err := WriteDebugFirewall(&buf, view); err != nil {
		t.Fatalf("WriteDebugFirewall: %v", err)
	}
	output := buf.String()
	required := []string{
		"backend: dry-run",
		"instance higgstesth2",
		"transit: true",
		"allow_prefixes: 2",
		"deny_prefixes: 1",
		"local_services: 1",
		"udp/4500",
		"generation: 5",
		"owned_objects: 10",
		"policy_hash: abc123",
		"host_ports: ike=true natt=true",
		"redirect_grace: true",
	}
	for _, want := range required {
		if !strings.Contains(output, want) {
			t.Fatalf("output missing %q:\n%s", want, output)
		}
	}
}
