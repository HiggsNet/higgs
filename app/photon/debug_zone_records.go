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
	if response, ok, err := readViewViaControl(rt, controlRequest{Method: "zone_debug", Zone: path.String(), History: history}); err != nil {
		return err
	} else if ok {
		if jsonOutput {
			if response.ZoneDetail == nil {
				return fmt.Errorf("daemon zone detail response is empty")
			}
			return inspecttext.WriteJSON(os.Stdout, *response.ZoneDetail)
		}
		if response.ZoneDebug == nil {
			return fmt.Errorf("daemon zone debug response is empty")
		}
		return inspecttext.WriteZoneDebug(os.Stdout, *response.ZoneDebug)
	}
	state, err := rt.LoadState()
	if err != nil {
		return err
	}
	view, err := buildDebugZoneView(state, path, rt.Now())
	if err != nil {
		return err
	}
	if jsonOutput {
		detail := inspect.BuildZoneDetail(inspect.ZoneDetailInput{
			Path:           path,
			State:          state.Network.Zones[path],
			Network:        state.Network,
			Now:            rt.Now(),
			IncludeHistory: includeHistory,
		})
		return inspecttext.WriteJSON(os.Stdout, detail)
	}
	return inspecttext.WriteZoneDebug(os.Stdout, view)
}

func buildDebugZoneView(state *stateFile, path zone.ZonePath, now time.Time) (inspect.ZoneDebugView, error) {
	if state == nil || state.Network == nil {
		return inspect.ZoneDebugView{}, fmt.Errorf("state is nil")
	}
	configureValidation(state.Network)
	view, ok := inspect.BuildZoneDebug(inspect.ZoneDebugInput{
		Network: state.Network,
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
	state, err := rt.LoadState()
	if err != nil {
		return err
	}
	return writeDebugRecords(os.Stdout, state, path, prefix, values)
}

func writeDebugRecords(w io.Writer, state *stateFile, path zone.ZonePath, prefix string, values bool) error {
	if state == nil || state.Network == nil {
		return fmt.Errorf("state is nil")
	}
	if path.Valid() && state.Network.Zones[path] == nil {
		return fmt.Errorf("%w: %s", zone.ErrZoneNotFound, path)
	}
	return inspecttext.WriteRecordsDebug(w, inspect.BuildRecordsDebug(inspect.RecordsDebugInput{
		Network: state.Network,
		Path:    path,
		Prefix:  prefix,
	}), values)
}
