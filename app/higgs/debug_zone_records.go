package main

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/Catofes/higgs/internal/inspect"
	inspecttext "github.com/Catofes/higgs/internal/inspect/text"
	"github.com/Catofes/higgs/pkg/core/zone"
)

func debugZone(path zone.ZonePath) error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	state, err := rt.LoadState()
	if err != nil {
		return err
	}
	view, err := buildDebugZoneView(state, path, rt.Now())
	if err != nil {
		return err
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
