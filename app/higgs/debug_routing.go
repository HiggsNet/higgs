package main

import (
	"context"
	"fmt"
	"io"
	"net/netip"
	"os"
	"sort"
	"strings"

	"github.com/Catofes/higgs/pkg/routing"
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
		return fmt.Errorf("daemon control socket unavailable; start the daemon to dump live BIRD output")
	}
	return writeDebugBirdDump(w, response.BirdDump)
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
	return writeDebugRoutes(w, dump)
}

func writeDebugRoutes(w io.Writer, dump *routesDumpResponse) error {
	fmt.Fprintf(w, "local_zone: %s\n", dump.LocalZone)
	fmt.Fprintf(w, "export_prefixes: %d\n", len(dump.ExportSet))
	for _, p := range dump.ExportSet {
		fmt.Fprintf(w, "  %s\n", p)
	}
	zones := make([]string, 0, len(dump.Authorized))
	for z := range dump.Authorized {
		zones = append(zones, z)
	}
	sort.Strings(zones)
	fmt.Fprintf(w, "authorized_prefixes: %d zones\n", len(zones))
	for _, z := range zones {
		fmt.Fprintf(w, "zone %s\n", z)
		for _, p := range dump.Authorized[z] {
			fmt.Fprintf(w, "  %s\n", p)
		}
	}
	fmt.Fprintf(w, "authorization_errors: %d\n", len(dump.Errors))
	for _, e := range dump.Errors {
		fmt.Fprintf(w, "  zone=%s prefix=%s code=%s detail=%s\n", e.Zone, dash(e.Prefix), e.Code, e.Detail)
	}
	fmt.Fprintf(w, "bird_routes: %d instances\n", len(dump.BIRD))
	for _, inst := range dump.BIRD {
		fmt.Fprintf(w, "netns %s\n", inst.NetNS)
		fmt.Fprintf(w, "  instance_id: %s\n", dash(inst.InstanceID))
		if inst.State != "" {
			fmt.Fprintf(w, "  state: %s\n", inst.State)
		}
		if inst.Error != "" {
			fmt.Fprintf(w, "  error: %s\n", inst.Error)
		}
		fmt.Fprintf(w, "  routes: %d\n", len(inst.Routes))
		for _, route := range inst.Routes {
			fmt.Fprintf(w, "    %s selected=%t authorized=%t import_allowed=%t",
				route.Prefix, route.Selected, route.Authorized, route.ImportAllowed)
			if len(route.Zones) > 0 {
				fmt.Fprintf(w, " zones=%s", strings.Join(route.Zones, ","))
			}
			if route.Protocol != "" {
				fmt.Fprintf(w, " protocol=%s", route.Protocol)
			}
			if route.Source != "" {
				fmt.Fprintf(w, " source=%s", route.Source)
			}
			if route.Iface != "" {
				fmt.Fprintf(w, " iface=%s", route.Iface)
			}
			if route.Via != "" {
				fmt.Fprintf(w, " via=%s", route.Via)
			}
			if route.From != "" {
				fmt.Fprintf(w, " from=%s", route.From)
			}
			if route.Metric > 0 {
				fmt.Fprintf(w, " metric=%d", route.Metric)
			}
			fmt.Fprintln(w)
		}
	}
	return nil
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
	return writeDebugRoute(w, prefix, dump)
}

func writeDebugRoute(w io.Writer, prefix netip.Prefix, dump *routesDumpResponse) error {
	prefixStr := prefix.String()
	fmt.Fprintf(w, "prefix: %s\n", prefixStr)

	localExport := false
	for _, p := range dump.ExportSet {
		if p == prefixStr {
			localExport = true
			break
		}
	}
	fmt.Fprintf(w, "local_export: %t\n", localExport)

	authorized := false
	zones := make([]string, 0)
	for z, prefixes := range dump.Authorized {
		for _, p := range prefixes {
			if p == prefixStr {
				authorized = true
				zones = append(zones, z)
				break
			}
		}
	}
	sort.Strings(zones)
	fmt.Fprintf(w, "authorized: %t\n", authorized)
	if len(zones) == 0 {
		fmt.Fprintln(w, "announcing_zones: -")
	} else {
		fmt.Fprintf(w, "announcing_zones: %s\n", strings.Join(zones, ", "))
	}

	matchedAssignment := routeAssignmentInfo{}
	matchedBits := -1
	for assignPrefixStr, assignment := range dump.Assignments {
		assignPrefix, err := netip.ParsePrefix(assignPrefixStr)
		if err != nil {
			continue
		}
		if assignPrefix.Bits() > prefix.Bits() {
			continue
		}
		if assignPrefix.Contains(prefix.Masked().Addr()) {
			if matchedBits == -1 || assignPrefix.Bits() > matchedBits {
				matchedAssignment = assignment
				matchedBits = assignPrefix.Bits()
			}
		}
	}
	if matchedBits != -1 {
		fmt.Fprintf(w, "assignment_source: %s\n", matchedAssignment.Source)
		fmt.Fprintf(w, "assignment_assigned_to: %s\n", matchedAssignment.AssignedTo)
	} else {
		fmt.Fprintln(w, "assignment_source: -")
		fmt.Fprintln(w, "assignment_assigned_to: -")
	}

	prefixErrors := make([]routeAuthorizationErrorJSON, 0)
	for _, e := range dump.Errors {
		if e.Prefix == prefixStr {
			prefixErrors = append(prefixErrors, e)
		}
	}
	fmt.Fprintf(w, "authorization_errors: %d\n", len(prefixErrors))
	for _, e := range prefixErrors {
		fmt.Fprintf(w, "  zone=%s code=%s detail=%s\n", e.Zone, e.Code, e.Detail)
	}
	matches := birdRoutesMatchingPrefix(dump, prefixStr)
	fmt.Fprintf(w, "bird_routes: %d\n", len(matches))
	for _, match := range matches {
		fmt.Fprintf(w, "  netns=%s instance=%s selected=%t authorized=%t import_allowed=%t",
			match.NetNS, dash(match.InstanceID), match.Route.Selected, match.Route.Authorized, match.Route.ImportAllowed)
		if match.Route.Protocol != "" {
			fmt.Fprintf(w, " protocol=%s", match.Route.Protocol)
		}
		if match.Route.Iface != "" {
			fmt.Fprintf(w, " iface=%s", match.Route.Iface)
		}
		if match.Route.Metric > 0 {
			fmt.Fprintf(w, " metric=%d", match.Route.Metric)
		}
		fmt.Fprintln(w)
	}
	return nil
}

type birdRoutePrefixMatch struct {
	NetNS      string
	InstanceID string
	Route      birdRouteView
}

func birdRoutesMatchingPrefix(dump *routesDumpResponse, prefix string) []birdRoutePrefixMatch {
	if dump == nil {
		return nil
	}
	matches := make([]birdRoutePrefixMatch, 0)
	for _, inst := range dump.BIRD {
		for _, route := range inst.Routes {
			if route.Prefix != prefix {
				continue
			}
			matches = append(matches, birdRoutePrefixMatch{
				NetNS:      inst.NetNS,
				InstanceID: inst.InstanceID,
				Route:      route,
			})
		}
	}
	sort.Slice(matches, func(i, j int) bool {
		if matches[i].NetNS != matches[j].NetNS {
			return matches[i].NetNS < matches[j].NetNS
		}
		if matches[i].InstanceID != matches[j].InstanceID {
			return matches[i].InstanceID < matches[j].InstanceID
		}
		return matches[i].Route.Iface < matches[j].Route.Iface
	})
	return matches
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
