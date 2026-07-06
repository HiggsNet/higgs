package text

import (
	"io"
	"sort"
	"strings"

	"github.com/Catofes/higgs/internal/inspect"
)

func WriteBirdDump(w io.Writer, dump *inspect.BirdDumpResponse) error {
	out := newLineWriter(w)
	if dump == nil || len(dump.Instances) == 0 {
		out.Linef("bird_dump: no instances")
		return out.Err()
	}
	netnsNames := make([]string, 0, len(dump.Instances))
	for netnsName := range dump.Instances {
		netnsNames = append(netnsNames, netnsName)
	}
	sort.Strings(netnsNames)
	for _, netnsName := range netnsNames {
		inst := dump.Instances[netnsName]
		out.Linef("netns %s", inst.NetNS)
		out.Linef("  instance_id: %s", dash(inst.InstanceID))
		out.Linef("  control_socket: %s", dash(inst.ControlSocket))
		out.LineIf(inst.Error != "", "  error: %s", inst.Error)
		commands := make([]string, 0, len(inst.Raw))
		for cmd := range inst.Raw {
			commands = append(commands, cmd)
		}
		sort.Strings(commands)
		for _, cmd := range commands {
			out.Linef("  command: %s", cmd)
			raw := strings.TrimRight(inst.Raw[cmd], "\n")
			if raw == "" {
				out.Linef("    -")
				continue
			}
			for line := range strings.SplitSeq(raw, "\n") {
				out.Linef("    %s", line)
			}
		}
	}
	return out.Err()
}

func WriteBabelDebug(w io.Writer, view inspect.BabelDebugView) error {
	out := newLineWriter(w)
	if len(view.Instances) == 0 {
		out.Linef("routing: not configured")
		return out.Err()
	}
	out.LineIf(view.LastReconcileError != "", "last_reconcile_error: %s", view.LastReconcileError)
	for _, inst := range view.Instances {
		out.Linef("netns %s", inst.NetNS)
		out.Linef("  instance_id: %s", inst.InstanceID)
		out.Linef("  mode: %s", inst.Mode)
		out.LineIf(inst.ShutdownPolicy != "", "  shutdown_policy: %s", inst.ShutdownPolicy)
		if !inst.Enabled {
			out.Linef("  state: disabled")
			continue
		}
		if inst.HasState {
			out.Linef("  router_id: %d", inst.RouterID)
			out.Linef("  control_socket: %s", dash(inst.ControlSocket))
			out.Linef("  config_path: %s", dash(inst.ConfigPath))
			out.Linef("  pid_file: %s", dash(inst.PIDFile))
			out.Linef("  last_config_hash: %s", dash(shortTextHash(inst.LastConfigHash)))
			out.LineIf(len(inst.Overlays) > 0, "  overlays: %s", strings.Join(inst.Overlays, ", "))
			out.Linef("  state: %s", defaultText(inst.State, "pending"))
			out.Linef("  last_error: %s", dash(inst.LastError))
			continue
		}
		out.Linef("  router_id: -")
		out.Linef("  control_socket: -")
		out.Linef("  config_path: -")
		out.Linef("  pid_file: -")
		out.Linef("  last_config_hash: -")
		out.Linef("  state: pending")
		out.Linef("  last_error: -")
	}
	return out.Err()
}

func shortTextHash(hash string) string {
	if len(hash) <= 12 {
		return hash
	}
	return hash[:12]
}
