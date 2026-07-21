package main

import (
	"context"
	"io"
	"os"

	"github.com/Catofes/higgs/internal/inspect"
	inspecttext "github.com/Catofes/higgs/internal/inspect/text"
	"github.com/Catofes/higgs/pkg/firewall"
	"github.com/urfave/cli/v3"
)

func debugFirewall(_ context.Context, _ *cli.Command) error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	return debugFirewallWithRuntime(rt, os.Stdout)
}

func debugFirewallWithRuntime(rt *Runtime, w io.Writer) error {
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
	return writeDebugFirewall(w, rt, instances, snapshot)
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
