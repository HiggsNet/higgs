package main

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Catofes/higgs/pkg/core/zone"
	"github.com/Catofes/higgs/pkg/routing"
)

func announceRoute(path zone.ZonePath, prefix string) error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	return announceRouteWithRuntime(rt, path, prefix)
}

func withdrawRoute(path zone.ZonePath, prefix string) error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	return withdrawRouteWithRuntime(rt, path, prefix)
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
	if err := checkRouteWriteCapability(state, path, key); err != nil {
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
	logControlFallback("route_submit")
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

func checkRouteWriteCapability(state *stateFile, path zone.ZonePath, key string) error {
	if state == nil || state.Network == nil {
		return fmt.Errorf("state is nil")
	}
	zs := state.Network.Zones[path]
	if zs == nil || zs.Authority == nil {
		return fmt.Errorf("%w: %s", zone.ErrZoneNotFound, path)
	}
	for _, authorizedKey := range zs.Authority.Keys {
		for _, capability := range authorizedKey.Capabilities {
			if capability.KeyPrefix != "" && !strings.HasPrefix(key, capability.KeyPrefix) {
				continue
			}
			for _, permission := range capability.Permissions {
				if permission == zone.PermWriteRoute {
					return nil
				}
			}
		}
	}
	return fmt.Errorf("zone %s authority lacks write:route capability for key %s", path, key)
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
