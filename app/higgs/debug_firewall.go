package main

import (
	"context"
	"fmt"
	"io"
	"os"

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
	if len(instances) == 0 {
		fmt.Fprintln(w, "firewall: not configured")
		return nil
	}
	if snapshot != nil && snapshot.Backend != "" {
		fmt.Fprintf(w, "backend: %s\n", snapshot.Backend)
	}
	if snapshot != nil && snapshot.LastError != "" {
		fmt.Fprintf(w, "last_reconcile_error: %s\n", snapshot.LastError)
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
		fmt.Fprintf(w, "instance %s\n", inst.ID)
		fmt.Fprintf(w, "  scope: %s\n", scope)
		fmt.Fprintf(w, "  mode: %s\n", mode)
		fmt.Fprintf(w, "  backend: %s\n", defaultStr(inst.Backend, "auto"))
		fmt.Fprintf(w, "  default_policy: %s\n", defaultStr(inst.DefaultPolicy, "drop"))
		if inst.OwnerPrefix != "" {
			fmt.Fprintf(w, "  owner_prefix: %s\n", inst.OwnerPrefix)
		}
		fmt.Fprintf(w, "  transit: %t\n", inst.Forwarding.Transit)
		if len(inst.Forwarding.AllowPrefixes) > 0 {
			fmt.Fprintf(w, "  allow_prefixes: %d\n", len(inst.Forwarding.AllowPrefixes))
		}
		if len(inst.Forwarding.DenyPrefixes) > 0 {
			fmt.Fprintf(w, "  deny_prefixes: %d\n", len(inst.Forwarding.DenyPrefixes))
		}
		if len(inst.LocalServices) > 0 {
			fmt.Fprintf(w, "  local_services: %d\n", len(inst.LocalServices))
			for _, svc := range inst.LocalServices {
				fmt.Fprintf(w, "    %s/%d\n", svc.Proto, svc.Port)
			}
		}
		if inst.IsHost {
			fmt.Fprintf(w, "  host_ports: ike=%t natt=%t\n", inst.HostPorts.IKE, inst.HostPorts.NATT)
			fmt.Fprintf(w, "  redirect_grace: %t\n", inst.RedirectGrace.Enabled)
		}
		if snapshot != nil && snapshot.Instances != nil {
			if entry := snapshot.Instances[inst.ID]; entry != nil {
				fmt.Fprintf(w, "  generation: %d\n", entry.Generation)
				fmt.Fprintf(w, "  owned_objects: %d\n", entry.OwnedObjects)
				if entry.PolicyHash != "" {
					fmt.Fprintf(w, "  policy_hash: %s\n", entry.PolicyHash)
				}
				if entry.LastError != "" {
					fmt.Fprintf(w, "  last_error: %s\n", entry.LastError)
				}
			}
		}
	}
	return nil
}

func firewallStatusViaControl(rt *Runtime) (*controlResponse, bool, error) {
	path := controlSocketPath(rt.Config)
	response, err := sendControlRequest(path, controlRequest{Method: "firewall_status"})
	if err != nil && isControlSocketUnavailable(err) {
		return nil, false, nil
	}
	return response, true, err
}

func defaultStr(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

