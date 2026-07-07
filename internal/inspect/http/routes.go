package http

import (
	"net/netip"
	"sort"

	"github.com/Catofes/higgs/pkg/core/zone"
	"github.com/Catofes/higgs/pkg/routing"
	"github.com/Catofes/higgs/pkg/routing/bird"
)

type RoutesResponse struct {
	LocalZone       zone.ZonePath              `json:"local_zone"`
	ExportSet       []string                   `json:"export_set"`
	Authorized      map[string][]string        `json:"authorized"`
	Assignments     map[string]RouteAssignment `json:"assignments"`
	IPAMPools       []IPAMPool                 `json:"ipam_pools"`
	IPAMAssignments []IPAMAssignment           `json:"ipam_assignments"`
	Errors          []RouteAuthorizationError  `json:"errors"`
	BIRD            []BirdRoutesView           `json:"bird,omitempty"`
}

type RouteAssignment struct {
	Source     string `json:"source"`
	AssignedTo string `json:"assigned_to"`
}

type IPAMPool struct {
	Prefix      string `json:"prefix"`
	Source      string `json:"source"`
	DelegatedTo string `json:"delegated_to"`
}

type IPAMAssignment struct {
	Prefix     string `json:"prefix"`
	Source     string `json:"source"`
	AssignedTo string `json:"assigned_to"`
	Shared     bool   `json:"shared,omitempty"`
}

type RouteAuthorizationError struct {
	Zone   string `json:"zone"`
	Prefix string `json:"prefix,omitempty"`
	Code   string `json:"code"`
	Detail string `json:"detail"`
}

type BirdRoutesView struct {
	NetNS      string          `json:"netns"`
	InstanceID string          `json:"instance_id,omitempty"`
	State      string          `json:"state,omitempty"`
	Error      string          `json:"error,omitempty"`
	Routes     []BirdRouteView `json:"routes,omitempty"`
}

type BirdRouteView struct {
	Prefix        string   `json:"prefix"`
	Protocol      string   `json:"protocol,omitempty"`
	Source        string   `json:"source,omitempty"`
	Iface         string   `json:"iface,omitempty"`
	From          string   `json:"from,omitempty"`
	Via           string   `json:"via,omitempty"`
	Metric        uint32   `json:"metric,omitempty"`
	Selected      bool     `json:"selected"`
	Authorized    bool     `json:"authorized"`
	ImportAllowed bool     `json:"import_allowed"`
	Zones         []string `json:"zones,omitempty"`
}

func RoutesFromAuthorizedSet(managedZone zone.ZonePath, ars *routing.AuthorizedRouteSet) *RoutesResponse {
	if ars == nil {
		return &RoutesResponse{LocalZone: managedZone}
	}
	exportSet := make([]string, 0)
	for p := range ars.Announced[managedZone] {
		exportSet = append(exportSet, p.String())
	}
	sortPrefixStrings(exportSet)

	authorized := make(map[string][]string, len(ars.Announced))
	for z, prefixes := range ars.Announced {
		ps := make([]string, 0, len(prefixes))
		for p := range prefixes {
			ps = append(ps, p.String())
		}
		sortPrefixStrings(ps)
		authorized[string(z)] = ps
	}

	assignments := make(map[string]RouteAssignment, len(ars.Assignments))
	for p, entry := range ars.Assignments {
		assignments[p.String()] = RouteAssignment{
			Source:     string(entry.Source),
			AssignedTo: string(entry.AssignedTo),
		}
	}

	ipamPools := make([]IPAMPool, 0, len(ars.AllPools))
	for _, entry := range ars.AllPools {
		if entry == nil {
			continue
		}
		ipamPools = append(ipamPools, IPAMPool{
			Prefix:      entry.Prefix.String(),
			Source:      string(entry.Source),
			DelegatedTo: string(entry.DelegatedTo),
		})
	}
	sort.Slice(ipamPools, func(i, j int) bool {
		if cmp := comparePrefixStrings(ipamPools[i].Prefix, ipamPools[j].Prefix); cmp != 0 {
			return cmp < 0
		}
		if ipamPools[i].Source != ipamPools[j].Source {
			return ipamPools[i].Source < ipamPools[j].Source
		}
		return ipamPools[i].DelegatedTo < ipamPools[j].DelegatedTo
	})

	ipamAssignments := make([]IPAMAssignment, 0, len(ars.AllAssignments))
	if len(ars.AllAssignments) > 0 {
		for _, entry := range ars.AllAssignments {
			if entry == nil {
				continue
			}
			ipamAssignments = append(ipamAssignments, IPAMAssignment{
				Prefix:     entry.Prefix.String(),
				Source:     string(entry.Source),
				AssignedTo: string(entry.AssignedTo),
				Shared:     entry.Shared,
			})
		}
	} else {
		for p, entry := range ars.Assignments {
			if entry == nil {
				continue
			}
			ipamAssignments = append(ipamAssignments, IPAMAssignment{
				Prefix:     p.String(),
				Source:     string(entry.Source),
				AssignedTo: string(entry.AssignedTo),
				Shared:     entry.Shared,
			})
		}
	}
	sort.Slice(ipamAssignments, func(i, j int) bool {
		if cmp := comparePrefixStrings(ipamAssignments[i].Prefix, ipamAssignments[j].Prefix); cmp != 0 {
			return cmp < 0
		}
		if ipamAssignments[i].Source != ipamAssignments[j].Source {
			return ipamAssignments[i].Source < ipamAssignments[j].Source
		}
		return ipamAssignments[i].AssignedTo < ipamAssignments[j].AssignedTo
	})

	errors := make([]RouteAuthorizationError, 0, len(ars.Errors))
	for _, e := range ars.Errors {
		prefix := ""
		if e.Prefix.IsValid() {
			prefix = e.Prefix.String()
		}
		errors = append(errors, RouteAuthorizationError{
			Zone:   string(e.Zone),
			Prefix: prefix,
			Code:   e.Code,
			Detail: e.Detail,
		})
	}

	return &RoutesResponse{
		LocalZone:       managedZone,
		ExportSet:       exportSet,
		Authorized:      authorized,
		Assignments:     assignments,
		IPAMPools:       ipamPools,
		IPAMAssignments: ipamAssignments,
		Errors:          errors,
	}
}

func BuildBirdRouteViews(dump *RoutesResponse, routes []bird.BirdRoute) []BirdRouteView {
	out := make([]BirdRouteView, 0, len(routes))
	for _, route := range routes {
		if !route.Prefix.IsValid() {
			continue
		}
		prefix := route.Prefix.String()
		zones := authorizedZonesForPrefix(dump, prefix)
		out = append(out, BirdRouteView{
			Prefix:        prefix,
			Protocol:      route.Protocol,
			Source:        route.Source,
			Iface:         route.Iface,
			From:          addrString(route.From),
			Via:           addrString(route.Via),
			Metric:        route.Metric,
			Selected:      route.Selected,
			Authorized:    len(zones) > 0,
			ImportAllowed: routeWithinAssignedPrefix(dump, route.Prefix),
			Zones:         zones,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Prefix != out[j].Prefix {
			return comparePrefixStrings(out[i].Prefix, out[j].Prefix) < 0
		}
		if out[i].Selected != out[j].Selected {
			return out[i].Selected
		}
		if out[i].Protocol != out[j].Protocol {
			return out[i].Protocol < out[j].Protocol
		}
		return out[i].Iface < out[j].Iface
	})
	return out
}

func authorizedZonesForPrefix(dump *RoutesResponse, prefix string) []string {
	if dump == nil {
		return nil
	}
	zones := make([]string, 0)
	for z, prefixes := range dump.Authorized {
		for _, p := range prefixes {
			if p == prefix {
				zones = append(zones, z)
				break
			}
		}
	}
	sort.Strings(zones)
	return zones
}

func routeWithinAssignedPrefix(dump *RoutesResponse, prefix netip.Prefix) bool {
	if dump == nil || !prefix.IsValid() {
		return false
	}
	addr := prefix.Masked().Addr()
	for assignPrefixStr := range dump.Assignments {
		assignPrefix, err := netip.ParsePrefix(assignPrefixStr)
		if err != nil {
			continue
		}
		if assignPrefix.Bits() <= prefix.Bits() && assignPrefix.Contains(addr) {
			return true
		}
	}
	return false
}

func addrString(addr netip.Addr) string {
	if !addr.IsValid() {
		return ""
	}
	return addr.String()
}

func sortPrefixStrings(prefixes []string) {
	sort.Slice(prefixes, func(i, j int) bool {
		return comparePrefixStrings(prefixes[i], prefixes[j]) < 0
	})
}

func comparePrefixStrings(a, b string) int {
	ap, aerr := netip.ParsePrefix(a)
	bp, berr := netip.ParsePrefix(b)
	if aerr != nil || berr != nil {
		if a < b {
			return -1
		}
		if a > b {
			return 1
		}
		return 0
	}
	if ap.Addr().Less(bp.Addr()) {
		return -1
	}
	if bp.Addr().Less(ap.Addr()) {
		return 1
	}
	if ap.Bits() < bp.Bits() {
		return -1
	}
	if ap.Bits() > bp.Bits() {
		return 1
	}
	return 0
}
