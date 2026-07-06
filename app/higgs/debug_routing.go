package main

import (
	"context"
	"fmt"
	"io"
	"net/netip"
	"os"
	"sort"
	"strings"
	"time"

	inspecttext "github.com/Catofes/higgs/internal/inspect/text"
	"github.com/Catofes/higgs/pkg/routing"
	"github.com/Catofes/higgs/pkg/routing/bird"
	"github.com/Catofes/higgs/pkg/transport/ipsec"
	"github.com/urfave/cli/v3"
)

func debugBabel(_ context.Context, _ *cli.Command) error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	return debugBabelWithRuntime(rt, os.Stdout)
}

func debugRoutingReload(_ context.Context, _ *cli.Command) error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	return debugRoutingReloadWithRuntime(rt, os.Stdout)
}

func debugRoutingReloadWithRuntime(rt *Runtime, w io.Writer) error {
	response, ok, err := routingReloadViaControl(rt)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("daemon control socket unavailable; start the daemon to reload routing")
	}
	msg := "routing reloaded"
	if response.Message != "" {
		msg = response.Message
	}
	fmt.Fprintln(w, msg)
	return nil
}

func debugBirdDump(_ context.Context, cmd *cli.Command) error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	return debugBirdDumpWithRuntime(rt, cmd.String("netns"), cmd.String("command"), os.Stdout)
}

func debugBirdDumpWithRuntime(rt *Runtime, netnsName, command string, w io.Writer) error {
	response, ok, err := birdDumpViaControl(rt, netnsName, command)
	if err != nil {
		return err
	}
	if !ok {
		dump, err := birdDumpOffline(rt, netnsName, command)
		if err != nil {
			return err
		}
		return writeDebugBirdDump(w, dump)
	}
	return writeDebugBirdDump(w, response.BirdDump)
}

func birdDumpOffline(rt *Runtime, netnsName, command string) (*birdDumpResponse, error) {
	if rt == nil || rt.Config == nil {
		return &birdDumpResponse{Instances: map[string]birdDumpInstance{}}, nil
	}
	state, err := rt.LoadState()
	if err != nil {
		return nil, err
	}
	commands := defaultBirdDumpCommands()
	if trimmed := strings.TrimSpace(command); trimmed != "" {
		command = trimmed
		commands = []string{command}
	} else {
		command = ""
	}
	response := &birdDumpResponse{Instances: map[string]birdDumpInstance{}}
	for _, inst := range rt.Config.Routing.Instances {
		if !inst.Enabled || inst.Mode == ipsec.RoutingModeDisabled {
			continue
		}
		if netnsName != "" && inst.NetNS != netnsName && inst.ID != netnsName {
			continue
		}
		controlSocket := inst.ControlSocket
		if state != nil && state.BirdInstances != nil {
			if bi := state.BirdInstances[inst.NetNS]; bi != nil && bi.ControlSocket != "" {
				controlSocket = bi.ControlSocket
			}
		}
		item := birdDumpInstance{
			NetNS:         inst.NetNS,
			InstanceID:    inst.ID,
			ControlSocket: controlSocket,
			Command:       command,
			Raw:           map[string]string{},
		}
		if controlSocket == "" {
			item.Error = "control socket is not configured"
			response.Instances[inst.NetNS] = item
			continue
		}
		client := bird.NewClient(controlSocket, 10*time.Second)
		for _, cmd := range commands {
			out, err := client.Raw(context.Background(), cmd)
			if err != nil {
				if item.Error == "" {
					item.Error = err.Error()
				}
				item.Raw[cmd] = out
				continue
			}
			item.Raw[cmd] = out
		}
		response.Instances[inst.NetNS] = item
	}
	return response, nil
}

func writeDebugBirdDump(w io.Writer, dump *birdDumpResponse) error {
	if dump == nil || len(dump.Instances) == 0 {
		fmt.Fprintln(w, "bird_dump: no instances")
		return nil
	}
	netnsNames := make([]string, 0, len(dump.Instances))
	for netnsName := range dump.Instances {
		netnsNames = append(netnsNames, netnsName)
	}
	sort.Strings(netnsNames)
	for _, netnsName := range netnsNames {
		inst := dump.Instances[netnsName]
		fmt.Fprintf(w, "netns %s\n", inst.NetNS)
		fmt.Fprintf(w, "  instance_id: %s\n", dash(inst.InstanceID))
		fmt.Fprintf(w, "  control_socket: %s\n", dash(inst.ControlSocket))
		if inst.Error != "" {
			fmt.Fprintf(w, "  error: %s\n", inst.Error)
		}
		commands := make([]string, 0, len(inst.Raw))
		for cmd := range inst.Raw {
			commands = append(commands, cmd)
		}
		sort.Strings(commands)
		for _, cmd := range commands {
			fmt.Fprintf(w, "  command: %s\n", cmd)
			out := strings.TrimRight(inst.Raw[cmd], "\n")
			if out == "" {
				fmt.Fprintln(w, "    -")
				continue
			}
			for _, line := range strings.Split(out, "\n") {
				fmt.Fprintf(w, "    %s\n", line)
			}
		}
	}
	return nil
}

func debugBabelWithRuntime(rt *Runtime, w io.Writer) error {
	response, ok, err := birdStatusViaControl(rt)
	if err != nil {
		return err
	}
	state, err := rt.LoadState()
	if err != nil {
		return err
	}
	if !ok {
		response = nil
	}
	return writeDebugBabel(w, rt, state, response)
}

func writeDebugBabel(w io.Writer, rt *Runtime, state *stateFile, response *controlResponse) error {
	instances := map[string]*BirdInstanceState{}
	if response != nil && response.BirdInstances != nil {
		for id, inst := range response.BirdInstances {
			instances[id] = inst
		}
	}
	if len(instances) == 0 && state != nil && state.BirdInstances != nil {
		for id, inst := range state.BirdInstances {
			instances[id] = inst
		}
	}
	routingInstances := []RoutingInstance{}
	if rt != nil && rt.Config != nil {
		routingInstances = rt.Config.Routing.Instances
	}
	if len(routingInstances) == 0 {
		fmt.Fprintln(w, "routing: not configured")
		return nil
	}
	if response != nil && response.LastRoutingError != "" {
		fmt.Fprintf(w, "last_reconcile_error: %s\n", response.LastRoutingError)
	}
	for _, inst := range routingInstances {
		mode := inst.Mode
		if mode == "" {
			mode = "managed"
		}
		if !inst.Enabled {
			mode = "disabled"
		}
		fmt.Fprintf(w, "netns %s\n", inst.NetNS)
		fmt.Fprintf(w, "  instance_id: %s\n", inst.ID)
		fmt.Fprintf(w, "  mode: %s\n", mode)
		if inst.Mode != ipsec.RoutingModeExternal && inst.Mode != ipsec.RoutingModeDisabled {
			fmt.Fprintf(w, "  shutdown_policy: %s\n", normalizedRoutingShutdownPolicy(inst.ShutdownPolicy))
		}
		if !inst.Enabled {
			fmt.Fprintln(w, "  state: disabled")
			continue
		}
		bi := instances[inst.NetNS]
		if bi != nil {
			fmt.Fprintf(w, "  router_id: %d\n", bi.RouterID)
			fmt.Fprintf(w, "  control_socket: %s\n", dash(bi.ControlSocket))
			fmt.Fprintf(w, "  config_path: %s\n", dash(bi.ConfigPath))
			fmt.Fprintf(w, "  pid_file: %s\n", dash(bi.PIDFile))
			fmt.Fprintf(w, "  last_config_hash: %s\n", dash(shortHash(bi.LastConfigHash)))
			if len(bi.Overlays) > 0 {
				fmt.Fprintf(w, "  overlays: %s\n", strings.Join(bi.Overlays, ", "))
			}
			st := bi.State
			if st == "" {
				st = "pending"
			}
			fmt.Fprintf(w, "  state: %s\n", st)
			fmt.Fprintf(w, "  last_error: %s\n", dash(bi.LastError))
		} else {
			fmt.Fprintln(w, "  router_id: -")
			fmt.Fprintln(w, "  control_socket: -")
			fmt.Fprintln(w, "  config_path: -")
			fmt.Fprintln(w, "  pid_file: -")
			fmt.Fprintln(w, "  last_config_hash: -")
			fmt.Fprintln(w, "  state: pending")
			fmt.Fprintln(w, "  last_error: -")
		}
	}
	return nil
}

func debugRoutes(_ context.Context, _ *cli.Command) error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	return debugRoutesWithRuntime(rt, os.Stdout)
}

func debugRoutesWithRuntime(rt *Runtime, w io.Writer) error {
	response, ok, err := routesDumpViaControl(rt)
	if err != nil {
		return err
	}
	var dump *routesDumpResponse
	if ok && response.RoutesDump != nil {
		dump = response.RoutesDump
	} else {
		state, err := rt.LoadState()
		if err != nil {
			return err
		}
		configureValidation(state.Network)
		ars, err := routing.BuildAuthorizedRouteSet(state.Network, rt.Now())
		if err != nil {
			return err
		}
		dump = buildRoutesDumpResponse(state.ManagedZone, ars)
	}
	return inspecttext.WriteRoutesDebug(w, dump)
}

func debugRoute(_ context.Context, cmd *cli.Command) error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	return debugRouteWithRuntime(rt, cmd.Args().First(), os.Stdout)
}

func debugRouteWithRuntime(rt *Runtime, prefixArg string, w io.Writer) error {
	canonical, err := routing.CanonicalizePrefix(prefixArg)
	if err != nil {
		return fmt.Errorf("invalid prefix %q: %w", prefixArg, err)
	}
	prefix, err := netip.ParsePrefix(canonical)
	if err != nil {
		return err
	}
	response, ok, err := routesDumpViaControl(rt)
	if err != nil {
		return err
	}
	var dump *routesDumpResponse
	if ok && response.RoutesDump != nil {
		dump = response.RoutesDump
	} else {
		state, err := rt.LoadState()
		if err != nil {
			return err
		}
		configureValidation(state.Network)
		ars, err := routing.BuildAuthorizedRouteSet(state.Network, rt.Now())
		if err != nil {
			return err
		}
		dump = buildRoutesDumpResponse(state.ManagedZone, ars)
	}
	return inspecttext.WriteRouteDebug(w, prefix, dump)
}

// routingNetnsForOverlay returns the netns name for a given overlay group ID.
// Used by debug links routing state lookup.
func routingNetnsForOverlay(rt *Runtime, overlayID string) string {
	if rt == nil || rt.Config == nil {
		return ""
	}
	// Find the overlay group, resolve its netns name.
	for _, group := range rt.Config.IPsec.LinkGroups {
		if group.ID == overlayID {
			return resolveOverlayNetNSName(group, rt.Config.Overlay.DefaultNetNS)
		}
	}
	return ""
}

// routingNetnsNameForLinkInstance returns the netns name for a link instance.
// LinkInstance.GroupID = overlay ID; we map overlay → netns via config.
func routingNetnsNameForLinkInstance(rt *Runtime, groupID string) string {
	return routingNetnsForOverlay(rt, groupID)
}

// _ ensures import is used
var _ = ipsec.NetNSName
