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
	return nil
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
