package main

import (
	"context"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/Catofes/higgs/internal/inspect"
	inspecthttp "github.com/Catofes/higgs/internal/inspect/http"
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

func birdDumpOffline(rt *Runtime, netnsName, command string) (*inspect.BirdDumpResponse, error) {
	if rt == nil || rt.Config == nil {
		return &inspect.BirdDumpResponse{Instances: map[string]inspect.BirdDumpInstance{}}, nil
	}
	state, err := rt.LoadState()
	if err != nil {
		return nil, err
	}
	customCommand := ""
	if trimmed := strings.TrimSpace(command); trimmed != "" {
		command = trimmed
		customCommand = command
	} else {
		command = ""
	}
	response := &inspect.BirdDumpResponse{Instances: map[string]inspect.BirdDumpInstance{}}
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
		item := inspect.BirdDumpInstance{
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
		commands := defaultBirdDumpCommands(inst.NetNS)
		if customCommand != "" {
			commands = []string{customCommand}
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

func writeDebugBirdDump(w io.Writer, dump *inspect.BirdDumpResponse) error {
	return inspecttext.WriteBirdDump(w, dump)
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
	return inspecttext.WriteBabelDebug(w, buildBabelDebugView(rt, state, response))
}

func buildBabelDebugView(rt *Runtime, state *stateFile, response *controlResponse) inspect.BabelDebugView {
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
	input := inspect.BabelDebugInput{}
	if len(routingInstances) == 0 {
		return inspect.BuildBabelDebug(input)
	}
	if response != nil && response.LastRoutingError != "" {
		input.LastReconcileError = response.LastRoutingError
	}
	input.RuntimeStates = instances
	for _, inst := range routingInstances {
		input.Instances = append(input.Instances, inspect.BabelInstanceInput{
			NetNS:          inst.NetNS,
			InstanceID:     inst.ID,
			Mode:           inst.Mode,
			ShutdownPolicy: inst.ShutdownPolicy,
			Enabled:        inst.Enabled,
		})
	}
	return inspect.BuildBabelDebug(input)
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
	var dump *inspecthttp.RoutesResponse
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
		dump = inspecthttp.RoutesFromAuthorizedSet(state.ManagedZone, ars)
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
	var dump *inspecthttp.RoutesResponse
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
		dump = inspecthttp.RoutesFromAuthorizedSet(state.ManagedZone, ars)
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
