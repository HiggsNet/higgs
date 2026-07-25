package text

import (
	"strings"
	"testing"

	"github.com/Catofes/higgs/internal/inspect"
)

func TestWriteFirewallSummaryFiltersAndHidesDebugDetails(t *testing.T) {
	view := inspect.FirewallDebugView{
		Backend: "nft",
		Instances: []inspect.FirewallInstanceView{
			{
				ID: "mesh-a", Scope: "higgs-a", Mode: "managed",
				ResolvedBackend: "nft", DefaultPolicy: "drop", Transit: true,
				AllowPrefixes: 2, AllowFilters: []string{"10.42.0.0/24", "fd42::/64"},
				AllowPeers: []string{"*-pek.catofes."}, DenyPeers: []string{"blocked.catofes."}, MetricHint: 20,
				LocalServices: []inspect.FirewallLocalServiceView{{Proto: "udp", Port: 4500}},
				Generation:    5, OwnedObjects: 10, PolicyHash: "secret-policy-hash",
				InlineHooks: []inspect.FirewallInlineHookView{{Expression: "secret hook"}},
			},
			{ID: "mesh-b", Scope: "higgs-b", Mode: "disabled"},
		},
	}
	var buf strings.Builder
	if err := WriteFirewall(&buf, view, "mesh-a", true); err != nil {
		t.Fatalf("WriteFirewall: %v", err)
	}
	output := buf.String()
	for _, want := range []string{
		"firewall: active",
		"backend: nft",
		"instances: 1/2",
		"INSTANCE",
		"SCOPE",
		"TRANSIT",
		"mesh-a",
		"higgs-a",
		"transit_policy: enabled=true default=drop",
		"allow_filters: 10.42.0.0/24, fd42::/64",
		"deny_filters: -",
		"allow_peers: *-pek.catofes.",
		"deny_peers: blocked.catofes.",
		"metric_hint: 20",
		"local_services: udp/4500",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("output missing %q:\n%s", want, output)
		}
	}
	for _, unwanted := range []string{"mesh-b", "secret-policy-hash", "secret hook"} {
		if strings.Contains(output, unwanted) {
			t.Fatalf("output unexpectedly contains %q:\n%s", unwanted, output)
		}
	}
}

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
				ID:              "higgstesth2",
				Scope:           "higgstesth2",
				Mode:            "managed",
				Backend:         "auto",
				ResolvedBackend: "nft",
				DefaultPolicy:   "drop",
				Transit:         true,
				AllowPrefixes:   2,
				DenyPrefixes:    1,
				LocalServices:   []inspect.FirewallLocalServiceView{{Proto: "udp", Port: 4500}},
				Generation:      5,
				OwnedObjects:    10,
				PolicyHash:      "abc123",
				InlineHooks: []inspect.FirewallInlineHookView{
					{Backend: "nft", Point: "pre_input", Expression: "counter", State: "active"},
					{Backend: "iptables", Family: "ipv4", Point: "pre_input", Expression: "-j ACCEPT", State: "inactive"},
				},
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
		"resolved_backend: nft",
		"instance higgstesth2",
		"transit: true",
		"allow_prefixes: 2",
		"deny_prefixes: 1",
		"local_services: 1",
		"udp/4500",
		"generation: 5",
		"owned_objects: 10",
		"policy_hash: abc123",
		"inline_hooks: 2",
		"[active] nft pre_input: counter",
		"[inactive] iptables/ipv4 pre_input: -j ACCEPT",
		"host_ports: ike=true natt=true",
		"redirect_grace: true",
	}
	for _, want := range required {
		if !strings.Contains(output, want) {
			t.Fatalf("output missing %q:\n%s", want, output)
		}
	}
}
