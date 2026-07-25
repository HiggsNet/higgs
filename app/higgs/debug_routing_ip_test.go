package main

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/Catofes/higgs/pkg/transport/ipsec"
)

func TestRoutingIPRouteCommandScopesNamespace(t *testing.T) {
	tests := []struct {
		name     string
		spec     ipsec.NetNSSpec
		family   string
		wantName string
		wantArgs string
	}{
		{
			name:     "host",
			spec:     ipsec.NetNSSpec{Kind: ipsec.NetNSHost},
			family:   "ipv4",
			wantName: "ip",
			wantArgs: "-4 route show",
		},
		{
			name:     "named",
			spec:     ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: "mesh"},
			family:   "ipv6",
			wantName: "ip",
			wantArgs: "netns exec mesh ip -6 route show",
		},
		{
			name:     "path",
			spec:     ipsec.NetNSSpec{Kind: ipsec.NetNSPath, Path: "/run/netns/mesh"},
			family:   "ipv4",
			wantName: "nsenter",
			wantArgs: "--net=/run/netns/mesh ip -4 route show",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name, args, err := routingIPRouteCommand(tt.spec, tt.family)
			if err != nil {
				t.Fatalf("routingIPRouteCommand: %v", err)
			}
			if name != tt.wantName || strings.Join(args, " ") != tt.wantArgs {
				t.Fatalf("command = %s %s, want %s %s", name, strings.Join(args, " "), tt.wantName, tt.wantArgs)
			}
		})
	}
}

func TestDebugRoutingIPRouteShowsKernelFIBByFamily(t *testing.T) {
	config := defaultAppConfig()
	config.Netns = netnsConfig{Names: map[string]ipsec.NetNSSpec{
		"mesh": {Kind: ipsec.NetNSName, Name: "mesh"},
	}}
	config.Routing = routingConfig{Instances: []RoutingInstance{
		{ID: "main", NetNS: "mesh", Enabled: true, Mode: ipsec.RoutingModeManaged},
	}}
	rt := &Runtime{Config: config}

	var commands []string
	runner := func(_ context.Context, name string, args ...string) ([]byte, error) {
		command := name + " " + strings.Join(args, " ")
		commands = append(commands, command)
		switch {
		case strings.Contains(command, " -4 route show"):
			return []byte("10.42.0.0/24 proto bird metric 32\n"), nil
		case strings.Contains(command, " -6 route show"):
			return []byte("fd42::/64 proto bird metric 32\n"), nil
		default:
			return nil, fmt.Errorf("unexpected command %q", command)
		}
	}

	var output strings.Builder
	if err := debugRoutingIPRouteWithRuntime(context.Background(), rt, &output, "main", "all", runner); err != nil {
		t.Fatalf("debugRoutingIPRouteWithRuntime: %v", err)
	}
	if len(commands) != 2 {
		t.Fatalf("commands = %#v, want IPv4 and IPv6", commands)
	}
	for _, want := range []string{
		"netns mesh",
		"instance_id: main",
		"namespace: name:mesh",
		"ipv4:",
		"10.42.0.0/24 proto bird metric 32",
		"ipv6:",
		"fd42::/64 proto bird metric 32",
	} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("output missing %q:\n%s", want, output.String())
		}
	}
}

func TestRoutingIPFamiliesRejectsUnknownFamily(t *testing.T) {
	if _, err := routingIPFamilies("mpls"); err == nil {
		t.Fatal("routingIPFamilies accepted unsupported family")
	}
}
