package text

import (
	"io"
	"strings"

	"github.com/Catofes/higgs/internal/inspect"
)

func WriteFirewall(w io.Writer, view inspect.FirewallDebugView, filter string, verbose bool) error {
	if len(view.Instances) == 0 {
		out := newLineWriter(w)
		out.Println("firewall: not configured")
		return out.Err()
	}
	filter = strings.ToLower(strings.TrimSpace(filter))
	instances := make([]inspect.FirewallInstanceView, 0, len(view.Instances))
	for _, instance := range view.Instances {
		searchable := strings.Join([]string{
			instance.ID,
			instance.Scope,
			instance.Mode,
			instance.Backend,
			instance.ResolvedBackend,
			instance.LastError,
		}, " ")
		if filter == "" || strings.Contains(strings.ToLower(searchable), filter) {
			instances = append(instances, instance)
		}
	}

	out := newLineWriter(w)
	if view.LastError != "" {
		out.Println("firewall: error")
	} else {
		out.Println("firewall: active")
	}
	out.LineIf(view.Backend != "", "backend: %s", view.Backend)
	out.Linef("instances: %s", filteredCount(len(instances), len(view.Instances), filter))
	for _, instance := range instances {
		backend := defaultText(instance.ResolvedBackend, defaultText(instance.Backend, "auto"))
		out.Linef("  %s scope=%s mode=%s backend=%s status=%s",
			instance.ID,
			defaultText(instance.Scope, "-"),
			defaultText(instance.Mode, "managed"),
			backend,
			firewallInstanceStatus(instance),
		)
		if !verbose {
			continue
		}
		out.Linef("    default_policy: %s", defaultText(instance.DefaultPolicy, "drop"))
		out.Linef("    transit: %t", instance.Transit)
		out.Linef("    prefixes: allow=%d deny=%d", instance.AllowPrefixes, instance.DenyPrefixes)
		out.Linef("    local_services: %d", len(instance.LocalServices))
		if instance.IsHost {
			out.Linef("    host_ports: ike=%t natt=%t", instance.HostIKE, instance.HostNATT)
		}
		out.Linef("    generation: %d", instance.Generation)
		out.Linef("    owned_objects: %d", instance.OwnedObjects)
		out.LineIf(instance.LastError != "", "    last_error: %s", instance.LastError)
	}
	out.LineIf(view.LastError != "", "last_error: %s", view.LastError)
	return out.Err()
}

func firewallInstanceStatus(instance inspect.FirewallInstanceView) string {
	switch {
	case instance.LastError != "":
		return "error"
	case instance.Mode == "disabled":
		return "disabled"
	case instance.ResolvedBackend != "":
		return "active"
	default:
		return "pending"
	}
}

func WriteDebugFirewall(w io.Writer, view inspect.FirewallDebugView) error {
	out := newLineWriter(w)
	if len(view.Instances) == 0 {
		out.Linef("firewall: not configured")
		return out.Err()
	}
	out.LineIf(view.Backend != "", "backend: %s", view.Backend)
	out.LineIf(view.LastError != "", "last_reconcile_error: %s", view.LastError)
	for _, inst := range view.Instances {
		out.Linef("instance %s", inst.ID)
		out.Linef("  scope: %s", inst.Scope)
		out.Linef("  mode: %s", inst.Mode)
		out.Linef("  backend: %s", defaultText(inst.Backend, "auto"))
		out.LineIf(inst.ResolvedBackend != "", "  resolved_backend: %s", inst.ResolvedBackend)
		out.Linef("  default_policy: %s", defaultText(inst.DefaultPolicy, "drop"))
		out.LineIf(inst.OwnerPrefix != "", "  owner_prefix: %s", inst.OwnerPrefix)
		out.Linef("  transit: %t", inst.Transit)
		out.LineIf(inst.AllowPrefixes > 0, "  allow_prefixes: %d", inst.AllowPrefixes)
		out.LineIf(inst.DenyPrefixes > 0, "  deny_prefixes: %d", inst.DenyPrefixes)
		if len(inst.LocalServices) > 0 {
			out.Linef("  local_services: %d", len(inst.LocalServices))
			for _, svc := range inst.LocalServices {
				out.Linef("    %s/%d", svc.Proto, svc.Port)
			}
		}
		if inst.IsHost {
			out.Linef("  host_ports: ike=%t natt=%t", inst.HostIKE, inst.HostNATT)
			out.Linef("  redirect_grace: %t", inst.RedirectGrace)
		}
		if len(inst.InlineHooks) > 0 {
			out.Linef("  inline_hooks: %d", len(inst.InlineHooks))
			for _, hook := range inst.InlineHooks {
				backend := hook.Backend
				if hook.Family != "" {
					backend += "/" + hook.Family
				}
				out.Linef("    [%s] %s %s: %s", defaultText(hook.State, "pending"), backend, hook.Point, hook.Expression)
			}
		}
		out.LineIf(inst.Generation != 0, "  generation: %d", inst.Generation)
		out.LineIf(inst.OwnedObjects != 0, "  owned_objects: %d", inst.OwnedObjects)
		out.LineIf(inst.PolicyHash != "", "  policy_hash: %s", inst.PolicyHash)
		out.LineIf(inst.LastError != "", "  last_error: %s", inst.LastError)
	}
	return out.Err()
}
