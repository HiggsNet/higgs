package text

import (
	"io"

	"github.com/Catofes/higgs/internal/inspect"
)

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
		out.LineIf(inst.Generation != 0, "  generation: %d", inst.Generation)
		out.LineIf(inst.OwnedObjects != 0, "  owned_objects: %d", inst.OwnedObjects)
		out.LineIf(inst.PolicyHash != "", "  policy_hash: %s", inst.PolicyHash)
		out.LineIf(inst.LastError != "", "  last_error: %s", inst.LastError)
	}
	return out.Err()
}

func defaultText(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
