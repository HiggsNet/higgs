package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/Catofes/photon/internal/inspect"
	"github.com/Catofes/photon/pkg/core/zone"
	"github.com/Catofes/photon/pkg/routing"
)

type routeMutationRequest struct {
	Zone   zone.ZonePath `json:"zone"`
	Prefix string        `json:"prefix"`
	Active bool          `json:"active"`
	DryRun bool          `json:"dry_run,omitempty"`
}

type routeShowReport struct {
	ManagedZone   string         `json:"managed_zone"`
	Announcements []routeShowRow `json:"announcements"`
}

type routeShowRow struct {
	Zone       string `json:"zone"`
	Prefix     string `json:"prefix"`
	Active     bool   `json:"active"`
	Controller string `json:"controller,omitempty"`
	Authorized bool   `json:"authorized"`
	Version    uint64 `json:"version"`
	Key        string `json:"key"`
}

func announceRoute(path zone.ZonePath, prefix string, direct bool) error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	rt.DisableControl = direct
	return mutateRouteWithRuntime(rt, path, prefix, true)
}

func withdrawRoute(path zone.ZonePath, prefix string, direct bool) error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	rt.DisableControl = direct
	return mutateRouteWithRuntime(rt, path, prefix, false)
}

func showRoutes(filter string, includeAll bool, verbose bool) error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	report, err := buildRouteShowReport(rt, "", includeAll)
	if err != nil {
		return err
	}
	return printRouteShowReport(os.Stdout, report, includeAll, filter, verbose)
}

func mutateRouteWithRuntime(rt *Runtime, path zone.ZonePath, prefix string, active bool) error {
	request := routeMutationRequest{Zone: path, Prefix: prefix, Active: active}
	if version, ok, err := mutateRouteViaControl(rt, request); ok {
		if err != nil {
			return err
		}
		fmt.Printf("%s route %s version %d via daemon\n", routeOpVerb(request.Active), request.Prefix, version)
		return nil
	}
	state, err := rt.LoadState()
	if err != nil {
		return err
	}
	result, err := applyRouteMutation(state, request, rt.Now())
	if err != nil {
		return err
	}
	if !result.DryRun {
		if err := rt.SaveState(state); err != nil {
			return err
		}
	}
	fmt.Printf("%s route %s/%s version %d\n", routeOpVerb(request.Active), result.Zone, result.Key, result.Version)
	return nil
}

func applyRouteMutation(state *stateFile, request routeMutationRequest, now time.Time) (*recordMutationResult, error) {
	if state == nil || state.Network == nil {
		return nil, errors.New("state is nil")
	}
	if !request.Zone.Valid() {
		return nil, fmt.Errorf("invalid route zone: %s", request.Zone)
	}
	canonical, key, value, err := prepareRouteRecord(request.Prefix, request.Active)
	if err != nil {
		return nil, err
	}
	if !request.Active {
		if err := checkWithdrawAllowed(state, request.Zone, key, canonical); err != nil {
			return nil, err
		}
	}
	record, err := buildSignedRecordAt(state, request.Zone, key, value, routing.RecordTypeRouteAnnouncement, now)
	if err != nil {
		return nil, err
	}
	if request.Active {
		if err := validateRouteCandidate(state, record, canonical, now); err != nil {
			return nil, err
		}
	}
	result := &recordMutationResult{Zone: request.Zone, Key: key, Version: record.Version, DryRun: request.DryRun}
	if request.DryRun {
		return result, nil
	}
	if err := state.Network.Put(record); err != nil {
		return nil, err
	}
	return result, nil
}

func validateRouteCandidate(state *stateFile, record *zone.Record, canonical string, now time.Time) error {
	path := record.Zone
	ns := cloneNetworkStateForCandidateValidation(state.Network, path)
	zs := ns.Zones[path]
	if zs == nil {
		return fmt.Errorf("%w: %s", zone.ErrZoneNotFound, path)
	}
	if err := ns.Put(record); err != nil {
		return err
	}
	ars, err := routing.BuildAuthorizedRouteSet(ns, now)
	if err != nil {
		return fmt.Errorf("build route authorization: %w", err)
	}
	for prefix := range ars.Announced[path] {
		if prefix.String() == canonical {
			return nil
		}
	}
	for _, authErr := range ars.Errors {
		if authErr.Zone == path && authErr.Prefix.String() == canonical {
			return fmt.Errorf("%s: %s", authErr.Code, authErr.Detail)
		}
	}
	return fmt.Errorf("route_unauthorized_no_assignment: no matching assignment for %s in %s", canonical, path)
}

func buildRouteShowReport(rt *Runtime, filterZone zone.ZonePath, includeAll bool) (*routeShowReport, error) {
	state, err := rt.LoadState()
	if err != nil {
		return nil, err
	}
	report := &routeShowReport{
		ManagedZone:   string(state.ManagedZone),
		Announcements: []routeShowRow{},
	}
	if state.Network == nil {
		return report, nil
	}
	authorized := map[string]map[string]struct{}{}
	if ars, err := routing.BuildAuthorizedRouteSet(state.Network, rt.Now()); err == nil && ars != nil {
		for z, prefixes := range ars.Announced {
			key := string(z)
			if authorized[key] == nil {
				authorized[key] = map[string]struct{}{}
			}
			for prefix := range prefixes {
				authorized[key][prefix.String()] = struct{}{}
			}
		}
	}

	zones := make([]zone.ZonePath, 0, len(state.Network.Zones))
	for path := range state.Network.Zones {
		if filterZone != "" && path != filterZone {
			continue
		}
		zones = append(zones, path)
	}
	inspect.SortZonePaths(zones)

	for _, path := range zones {
		zs := state.Network.Zones[path]
		if zs == nil {
			continue
		}
		keys := make([]string, 0, len(zs.Records))
		for key := range zs.Records {
			if strings.HasPrefix(key, routing.RecordKeyPrefixRoutes) {
				keys = append(keys, key)
			}
		}
		sort.Strings(keys)
		for _, key := range keys {
			rec := zs.Records[key]
			ann, err := routing.ParseRouteAnnouncementRecord(rec)
			if err != nil {
				continue
			}
			if !includeAll && !ann.Active {
				continue
			}
			prefix := ann.Prefix
			if p, err := netip.ParsePrefix(prefix); err == nil {
				prefix = p.Masked().String()
			}
			_, isAuthorized := authorized[string(path)][prefix]
			report.Announcements = append(report.Announcements, routeShowRow{
				Zone:       string(path),
				Prefix:     prefix,
				Active:     ann.Active,
				Controller: ann.Controller,
				Authorized: isAuthorized,
				Version:    rec.Version,
				Key:        key,
			})
		}
	}
	sort.Slice(report.Announcements, func(i, j int) bool {
		a := report.Announcements[i]
		b := report.Announcements[j]
		if a.Zone != b.Zone {
			return inspect.ZonePathLess(a.Zone, b.Zone)
		}
		if cmp := comparePrefixStrings(a.Prefix, b.Prefix); cmp != 0 {
			return cmp < 0
		}
		return a.Key < b.Key
	})
	return report, nil
}

func printRouteShowReport(w io.Writer, report *routeShowReport, includeAll bool, filter string, verbose bool) error {
	if report == nil {
		report = &routeShowReport{}
	}
	filter = strings.ToLower(strings.TrimSpace(filter))
	rows := make([]routeShowRow, 0, len(report.Announcements))
	for _, row := range report.Announcements {
		state := "active"
		if !row.Active {
			state = "withdrawn"
		}
		authorization := "unauthorized"
		if row.Authorized {
			authorization = "authorized"
		}
		searchable := strings.Join([]string{
			row.Prefix,
			row.Zone,
			state,
			row.Controller,
			authorization,
			row.Key,
		}, " ")
		if filter == "" || strings.Contains(strings.ToLower(searchable), filter) {
			rows = append(rows, row)
		}
	}

	table := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintf(table, "managed_zone: %s\n", report.ManagedZone)
	if filter == "" {
		fmt.Fprintf(table, "announcements: %d\n", len(rows))
	} else {
		fmt.Fprintf(table, "announcements: %d/%d\n", len(rows), len(report.Announcements))
	}
	if verbose {
		fmt.Fprintln(table, "PREFIX\tZONE\tSTATE\tAUTHORIZATION\tCONTROLLER\tVERSION\tRECORD")
	} else {
		fmt.Fprintln(table, "PREFIX\tZONE\tSTATE\tAUTHORIZATION")
	}
	for _, row := range rows {
		state := "active"
		if !row.Active {
			state = "withdrawn"
		}
		authorized := "unauthorized"
		if row.Authorized {
			authorized = "authorized"
		}
		controller := "explicit"
		if row.Controller != "" {
			controller = row.Controller
		}
		if verbose {
			fmt.Fprintf(table, "%s\t%s\t%s\t%s\t%s\t%d\t%s\n",
				row.Prefix, row.Zone, state, authorized, controller, row.Version, row.Key)
		} else {
			fmt.Fprintf(table, "%s\t%s\t%s\t%s\n", row.Prefix, row.Zone, state, authorized)
		}
	}
	if len(rows) == 0 && !includeAll {
		fmt.Fprintln(table, "hint: use --all to include withdrawn announcements")
	}
	return table.Flush()
}

func prepareRouteRecord(prefix string, active bool) (canonical, key string, value []byte, err error) {
	canonical, err = routing.CanonicalizePrefix(prefix)
	if err != nil {
		return "", "", nil, fmt.Errorf("invalid prefix %q: %w", prefix, err)
	}
	key, err = routing.NormalizeRouteAnnouncementKey(prefix)
	if err != nil {
		return "", "", nil, fmt.Errorf("normalize route key for %q: %w", prefix, err)
	}
	record := routing.RouteAnnouncementRecord{Version: 1, Prefix: canonical, Active: active}
	value, err = json.Marshal(record)
	if err != nil {
		return "", "", nil, fmt.Errorf("marshal route announcement record: %w", err)
	}
	return canonical, key, value, nil
}

func routeOpVerb(active bool) string {
	if active {
		return "announced"
	}
	return "withdrew"
}

func checkWithdrawAllowed(state *stateFile, path zone.ZonePath, key, canonical string) error {
	if state == nil || state.Network == nil {
		return fmt.Errorf("state is nil")
	}
	zs := state.Network.Zones[path]
	if zs == nil {
		return fmt.Errorf("%w: %s", zone.ErrZoneNotFound, path)
	}
	current := zs.Records[key]
	if current == nil {
		return fmt.Errorf("no active route announcement for %s in %s", canonical, path)
	}
	ann, err := routing.ParseRouteAnnouncementRecord(current)
	if err != nil {
		return fmt.Errorf("current route record for %s is invalid: %w", canonical, err)
	}
	if !ann.Active {
		return fmt.Errorf("route %s in %s is already withdrawn", canonical, path)
	}
	return nil
}
