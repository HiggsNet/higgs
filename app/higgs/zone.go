package main

import (
	"fmt"
	"os"

	"github.com/Catofes/higgs/internal/inspect"
	inspecttext "github.com/Catofes/higgs/internal/inspect/text"
	"github.com/Catofes/higgs/pkg/core/zone"
)

func showZone(path zone.ZonePath, filter string, verbose bool) error {
	state, err := loadState()
	if err != nil {
		return err
	}
	zs := state.Network.Zones[path]
	if zs == nil {
		return fmt.Errorf("%w: %s", zone.ErrZoneNotFound, path)
	}
	out := inspect.BuildZoneDetail(inspect.ZoneDetailInput{
		Path:           path,
		State:          zs,
		Network:        state.Network,
		Now:            timeNow(),
		IncludeHistory: false,
	})
	return inspecttext.WriteZone(os.Stdout, out, filter, verbose)
}

func showRecords(path zone.ZonePath, filter string, verbose bool) error {
	state, err := loadState()
	if err != nil {
		return err
	}
	if path.Valid() && state.Network.Zones[path] == nil {
		return fmt.Errorf("%w: %s", zone.ErrZoneNotFound, path)
	}
	view := inspect.BuildRecordsDebug(inspect.RecordsDebugInput{
		Network: state.Network,
		Path:    path,
	})
	return inspecttext.WriteRecords(os.Stdout, view, filter, verbose)
}
