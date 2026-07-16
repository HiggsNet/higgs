package main

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strings"

	"github.com/Catofes/higgs/pkg/core/zone"
	"github.com/Catofes/higgs/pkg/routing"
)

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
	return announceRouteWithRuntime(rt, path, prefix)
}

func withdrawRoute(path zone.ZonePath, prefix string, direct bool) error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	rt.DisableControl = direct
	return withdrawRouteWithRuntime(rt, path, prefix)
}

func showRoutes(filterZone zone.ZonePath, includeAll bool, jsonOut bool) error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	report, err := buildRouteShowReport(rt, filterZone, includeAll)
	if err != nil {
		return err
	}
	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	}
	printRouteShowReport(report, includeAll)
	return nil
}

func announceRouteWithRuntime(rt *Runtime, path zone.ZonePath, prefix string) error {
	canonical, key, value, err := prepareRouteRecord(prefix, true)
	if err != nil {
		return err
	}
	return submitRouteRecord(rt, path, key, value, canonical, true)
}

func withdrawRouteWithRuntime(rt *Runtime, path zone.ZonePath, prefix string) error {
	canonical, key, value, err := prepareRouteRecord(prefix, false)
	if err != nil {
		return err
	}
	return submitRouteRecord(rt, path, key, value, canonical, false)
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
	sort.Slice(zones, func(i, j int) bool { return zones[i] < zones[j] })

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
			return a.Zone < b.Zone
		}
		if cmp := comparePrefixStrings(a.Prefix, b.Prefix); cmp != 0 {
			return cmp < 0
		}
		return a.Key < b.Key
	})
	return report, nil
}

func printRouteShowReport(report *routeShowReport, includeAll bool) {
	if report == nil {
		report = &routeShowReport{}
	}
	fmt.Fprintf(os.Stdout, "managed_zone: %s\n", report.ManagedZone)
	fmt.Fprintf(os.Stdout, "announcements: %d\n", len(report.Announcements))
	if len(report.Announcements) == 0 {
		if includeAll {
			fmt.Fprintln(os.Stdout, "  -")
		} else {
			fmt.Fprintln(os.Stdout, "  - (use --all to include withdrawn announcements)")
		}
		return
	}
	for _, row := range report.Announcements {
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
		fmt.Fprintf(os.Stdout, "  %s  zone=%s  state=%s  controller=%s  %s  version=%d\n", row.Prefix, row.Zone, state, controller, authorized, row.Version)
	}
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

func submitRouteRecord(rt *Runtime, path zone.ZonePath, key string, value []byte, canonical string, active bool) error {
	state, err := rt.LoadState()
	if err != nil {
		return err
	}
	if !active {
		if err := checkWithdrawAllowed(state, path, key, canonical); err != nil {
			return err
		}
	}

	if version, ok, err := putRecordViaControl(rt, path, key, value, routing.RecordTypeRouteAnnouncement); ok {
		if err != nil {
			return err
		}
		fmt.Printf("%s route %s/%s version %d via daemon\n", routeOpVerb(active), path, key, version)
		return nil
	}
	if !rt.DisableControl {
		logControlFallback("route_submit")
	}
	return putRouteRecordDirect(rt, path, key, value, active, state)
}

func putRouteRecordDirect(rt *Runtime, path zone.ZonePath, key string, value []byte, active bool, state *stateFile) error {
	if state == nil {
		var err error
		state, err = rt.LoadState()
		if err != nil {
			return err
		}
	}
	record, err := buildSignedRecordAt(state, path, key, value, routing.RecordTypeRouteAnnouncement, rt.Now())
	if err != nil {
		return err
	}
	if err := state.Network.Put(record); err != nil {
		return err
	}
	if err := rt.SaveState(state); err != nil {
		return err
	}
	fmt.Printf("%s route %s/%s version %d\n", routeOpVerb(active), path, key, record.Version)
	return nil
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
