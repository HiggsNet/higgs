package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/Catofes/higgs/internal/inspect"
	inspecttext "github.com/Catofes/higgs/internal/inspect/text"
	"github.com/Catofes/higgs/pkg/firewall"
	"github.com/urfave/cli/v3"
)

func debugFirewall(_ context.Context, cmd *cli.Command) error {
	if cmd.Bool("host") && cmd.String("netns") != "" {
		return fmt.Errorf("--host and --netns cannot be used together")
	}
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	return debugFirewallWithRuntimeFiltered(rt, os.Stdout, cmd.String("netns"), cmd.Bool("host"), cmd.Bool("json"))
}

func debugFirewallWithRuntime(rt *Runtime, w io.Writer) error {
	return debugFirewallWithRuntimeFiltered(rt, w, "", false, false)
}

func debugFirewallWithRuntimeFiltered(rt *Runtime, w io.Writer, netns string, hostOnly, jsonOutput bool) error {
	response, ok, err := firewallStatusViaControl(rt)
	if err != nil {
		return err
	}
	state, err := rt.LoadState()
	if err != nil {
		return err
	}
	var snapshot *firewallReconcileState
	if ok && response.FirewallReconcile != nil {
		snapshot = response.FirewallReconcile
	} else {
		configureValidation(state.Network)
		snapshot = state.FirewallReconcile
	}
	instances := []FirewallInstanceConfig{}
	if rt != nil && rt.Config != nil {
		instances = rt.Config.Firewall.Instances
	}
	instances = filterFirewallDebugInstances(instances, netns, hostOnly)
	view := buildFirewallDebugView(rt.Config, instances, snapshot)
	if jsonOutput {
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		return encoder.Encode(view)
	}
	return inspecttext.WriteDebugFirewall(w, view)
}

func filterFirewallDebugInstances(instances []FirewallInstanceConfig, netns string, hostOnly bool) []FirewallInstanceConfig {
	if netns == "" && !hostOnly {
		return instances
	}
	filtered := make([]FirewallInstanceConfig, 0, len(instances))
	for _, inst := range instances {
		if hostOnly && !inst.IsHost {
			continue
		}
		if netns != "" && inst.NetNS != netns && inst.ID != netns {
			continue
		}
		filtered = append(filtered, inst)
	}
	return filtered
}

func writeDebugFirewall(w io.Writer, rt *Runtime, instances []FirewallInstanceConfig, snapshot *firewallReconcileState) error {
	var config *appConfig
	if rt != nil {
		config = rt.Config
	}
	return inspecttext.WriteDebugFirewall(w, buildFirewallDebugView(config, instances, snapshot))
}

func buildFirewallDebugView(config *appConfig, instances []FirewallInstanceConfig, snapshot *firewallReconcileState) inspect.FirewallDebugView {
	input := inspect.FirewallDebugInput{
		Instances: make([]inspect.FirewallInstanceInput, 0, len(instances)),
		Reconcile: snapshot,
	}
	for _, inst := range instances {
		policy := netnsForwardingPolicy(config, inst.NetNS)
		scope := inst.NetNS
		if inst.IsHost {
			scope = "host"
		}
		instInput := inspect.FirewallInstanceInput{
			ID:            inst.ID,
			Scope:         scope,
			Enabled:       inst.Enabled,
			Mode:          inst.Mode,
			Backend:       inst.Backend,
			DefaultPolicy: inst.DefaultPolicy,
			OwnerPrefix:   inst.OwnerPrefix,
			Transit:       policy.Transit,
			AllowPrefixes: len(policy.AllowPrefixes),
			DenyPrefixes:  len(policy.DenyPrefixes),
			IsHost:        inst.IsHost,
			HostIKE:       inst.HostPorts.IKE,
			HostNATT:      inst.HostPorts.NATT,
			RedirectGrace: inst.RedirectGrace.Enabled,
			InlineHooks:   firewallInlineHookViews(inst.NativeHooks),
		}
		for _, svc := range inst.LocalServices {
			instInput.LocalServices = append(instInput.LocalServices, inspect.FirewallLocalServiceView{
				Proto: svc.Proto,
				Port:  svc.Port,
			})
		}
		input.Instances = append(input.Instances, instInput)
	}
	return inspect.BuildFirewallDebug(input)
}

func firewallInlineHookViews(hooks firewall.NativeHooks) []inspect.FirewallInlineHookView {
	points := []firewall.HookPoint{
		firewall.HookPreInput,
		firewall.HookPostInput,
		firewall.HookPreForward,
		firewall.HookPostForward,
		firewall.HookPreOutput,
		firewall.HookPostOutput,
		firewall.HookHostPrePrerouting,
		firewall.HookHostPostPrerouting,
		firewall.HookHostPreInput,
		firewall.HookHostPostInput,
	}
	var out []inspect.FirewallInlineHookView
	appendRules := func(backend, family string, rules firewall.InlineHookRules) {
		for _, point := range points {
			for _, expression := range rules.Rules(point) {
				out = append(out, inspect.FirewallInlineHookView{
					Backend: backend, Family: family, Point: string(point), Expression: expression,
				})
			}
		}
	}
	appendRules(firewall.BackendNFT, "", hooks.NFT)
	appendRules(firewall.BackendIptables, "ipv4", hooks.IPTables.IPv4)
	appendRules(firewall.BackendIptables, "ipv6", hooks.IPTables.IPv6)
	return out
}

func firewallStatusViaControl(rt *Runtime) (*controlResponse, bool, error) {
	path := controlSocketPath(rt.Config)
	response, err := sendControlRequest(path, controlRequest{Method: "firewall_status"})
	if err != nil && isControlSocketUnavailable(err) {
		return nil, false, nil
	}
	return response, true, err
}
