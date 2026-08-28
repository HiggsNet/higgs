package main

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
	inspecttext "github.com/HiggsNet/photon/internal/inspect/text"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

func debugZone(path zone.ZonePath, jsonOutput, includeHistory bool) error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	history := 0
	if includeHistory {
		history = 1
	}
	if view, ok, err := readCanonicalViewViaControl[inspect.ZoneInspectionView](rt, controlRequest{Method: "zone_debug", Zone: path.String(), History: history}); err != nil {
		return err
	} else if ok {
		if jsonOutput {
			return inspecttext.WriteJSON(os.Stdout, view.Detail)
		}
		return inspecttext.WriteZoneDebug(os.Stdout, view.Debug)
	}
	common, _, err := loadOfflineOwnerViews(rt)
	if err != nil {
		return err
	}
	if common.State == nil || common.State.Network == nil {
		return fmt.Errorf("common state is not initialized")
	}
	network := common.State.Network
	view, err := buildZoneInspectionView(network, path, rt.Now(), includeHistory)
	if err != nil {
		return err
	}
	if jsonOutput {
		return inspecttext.WriteJSON(os.Stdout, view.Detail)
	}
	return inspecttext.WriteZoneDebug(os.Stdout, view.Debug)
}

func buildZoneInspectionView(network *zone.NetworkState, path zone.ZonePath, now time.Time, includeHistory bool) (inspect.ZoneInspectionView, error) {
	debug, err := buildDebugZoneView(network, path, now)
	if err != nil {
		return inspect.ZoneInspectionView{}, err
	}
	return inspect.ZoneInspectionView{
		Debug: debug,
		Detail: inspect.BuildZoneDetail(inspect.ZoneDetailInput{
			Path: path, State: network.Zones[path], Network: network, Now: now, IncludeHistory: includeHistory,
		}),
	}, nil
}

func buildDebugZoneView(network *zone.NetworkState, path zone.ZonePath, now time.Time) (inspect.ZoneDebugView, error) {
	if network == nil {
		return inspect.ZoneDebugView{}, fmt.Errorf("network is nil")
	}
	configureValidation(network)
	view, ok := inspect.BuildZoneDebug(inspect.ZoneDebugInput{
		Network: network,
		Path:    path,
		Now:     now,
	})
	if !ok {
		return inspect.ZoneDebugView{}, fmt.Errorf("%w: %s", zone.ErrZoneNotFound, path)
	}
	return view, nil
}

func debugRecords(path zone.ZonePath, prefix string, values bool) error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	if view, ok, err := readCanonicalViewViaControl[inspect.RecordsDebugView](rt, controlRequest{Method: "records_view", Zone: path.String(), Key: prefix}); err != nil {
		return err
	} else if ok {
		return inspecttext.WriteRecordsDebug(os.Stdout, view, values)
	}
	common, _, err := loadOfflineOwnerViews(rt)
	if err != nil {
		return err
	}
	if common.State == nil {
		return fmt.Errorf("common state is not initialized")
	}
	return writeDebugRecords(os.Stdout, common.State.Network, path, prefix, values)
}

func writeDebugRecords(w io.Writer, network *zone.NetworkState, path zone.ZonePath, prefix string, values bool) error {
	view, err := buildRecordsInspection(network, path, prefix)
	if err != nil {
		return err
	}
	return inspecttext.WriteRecordsDebug(w, view, values)
}

func buildRecordsInspection(network *zone.NetworkState, path zone.ZonePath, prefix string) (inspect.RecordsDebugView, error) {
	if network == nil {
		return inspect.RecordsDebugView{}, fmt.Errorf("network is nil")
	}
	if path.Valid() && network.Zones[path] == nil {
		return inspect.RecordsDebugView{}, fmt.Errorf("%w: %s", zone.ErrZoneNotFound, path)
	}
	return inspect.BuildRecordsDebug(inspect.RecordsDebugInput{
		Network: network,
		Path:    path,
		Prefix:  prefix,
	}), nil
}
