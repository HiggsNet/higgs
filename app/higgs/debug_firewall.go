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

func writeDebugFirewall(w io.Writer, _ *Runtime, instances []FirewallInstanceConfig, snapshot *firewallReconcileState) error {
	return inspecttext.WriteDebugFirewall(w, buildFirewallDebugView(instances, snapshot))
}

func buildFirewallDebugView(instances []FirewallInstanceConfig, snapshot *firewallReconcileState) inspect.FirewallDebugView {
	view := inspect.FirewallDebugView{}
	if len(instances) == 0 {
		return view
	}
	if snapshot != nil && snapshot.Backend != "" {
		view.Backend = snapshot.Backend
	}
	if snapshot != nil && snapshot.LastError != "" {
		view.LastError = snapshot.LastError
	}
	for _, inst := range instances {
		mode := inst.Mode
		if mode == "" {
			mode = firewall.ModeManaged
		}
		if !inst.Enabled {
			mode = "disabled"
		}
		scope := inst.NetNS
		if inst.IsHost {
			scope = "host"
		}
		instView := inspect.FirewallInstanceView{
			ID:            inst.ID,
			Scope:         scope,
			Mode:          mode,
			Backend:       inst.Backend,
			DefaultPolicy: inst.DefaultPolicy,
			OwnerPrefix:   inst.OwnerPrefix,
			Transit:       inst.Forwarding.Transit,
			AllowPrefixes: len(inst.Forwarding.AllowPrefixes),
			DenyPrefixes:  len(inst.Forwarding.DenyPrefixes),
			IsHost:        inst.IsHost,
			HostIKE:       inst.HostPorts.IKE,
			HostNATT:      inst.HostPorts.NATT,
			RedirectGrace: inst.RedirectGrace.Enabled,
		}
		for _, svc := range inst.LocalServices {
			instView.LocalServices = append(instView.LocalServices, inspect.FirewallLocalServiceView{
				Proto: svc.Proto,
				Port:  svc.Port,
			})
		}
		if snapshot != nil && snapshot.Instances != nil {
			if entry := snapshot.Instances[inst.ID]; entry != nil {
				instView.Generation = entry.Generation
				instView.OwnedObjects = entry.OwnedObjects
				instView.PolicyHash = entry.PolicyHash
				instView.LastError = entry.LastError
			}
		}
		view.Instances = append(view.Instances, instView)
	}
	return view
}

func firewallStatusViaControl(rt *Runtime) (*controlResponse, bool, error) {
	path := controlSocketPath(rt.Config)
	response, err := sendControlRequest(path, controlRequest{Method: "firewall_status"})
	if err != nil && isControlSocketUnavailable(err) {
		return nil, false, nil
	}
	return response, true, err
}
