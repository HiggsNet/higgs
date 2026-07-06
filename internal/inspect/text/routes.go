package text

import (
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strings"

	inspecthttp "github.com/Catofes/higgs/internal/inspect/http"
)

func WriteRoutesDebug(w io.Writer, dump *inspecthttp.RoutesResponse) error {
	if dump == nil {
		dump = &inspecthttp.RoutesResponse{}
	}
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

func WriteRouteDebug(w io.Writer, prefix netip.Prefix, dump *inspecthttp.RoutesResponse) error {
	if dump == nil {
		dump = &inspecthttp.RoutesResponse{}
	}
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

	matchedAssignment := inspecthttp.RouteAssignment{}
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

	prefixErrors := make([]inspecthttp.RouteAuthorizationError, 0)
	for _, e := range dump.Errors {
		if e.Prefix == prefixStr {
			prefixErrors = append(prefixErrors, e)
		}
	}
	fmt.Fprintf(w, "authorization_errors: %d\n", len(prefixErrors))
	for _, e := range prefixErrors {
		fmt.Fprintf(w, "  zone=%s code=%s detail=%s\n", e.Zone, e.Code, e.Detail)
	}
	matches := BirdRoutesMatchingPrefix(dump, prefixStr)
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

type BirdRoutePrefixMatch struct {
	NetNS      string
	InstanceID string
	Route      inspecthttp.BirdRouteView
}

func BirdRoutesMatchingPrefix(dump *inspecthttp.RoutesResponse, prefix string) []BirdRoutePrefixMatch {
	if dump == nil {
		return nil
	}
	matches := make([]BirdRoutePrefixMatch, 0)
	for _, inst := range dump.BIRD {
		for _, route := range inst.Routes {
			if route.Prefix != prefix {
				continue
			}
			matches = append(matches, BirdRoutePrefixMatch{
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
