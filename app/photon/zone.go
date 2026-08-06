package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/HiggsNet/photon/internal/inspect"
	inspecttext "github.com/HiggsNet/photon/internal/inspect/text"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

func showZones(filter string, verbose bool) error {
	state, err := loadState()
	if err != nil {
		return err
	}
	if state.Network == nil {
		return inspecttext.WriteZones(os.Stdout, nil, filter, verbose)
	}
	filter = strings.TrimSpace(filter)
	if filter != "" {
		path := zone.ZonePath(filter)
		if zs := state.Network.Zones[path]; zs != nil {
			detail := inspect.BuildZoneDetail(inspect.ZoneDetailInput{
				Path:           path,
				State:          zs,
				Network:        state.Network,
				Now:            timeNow(),
				IncludeHistory: false,
			})
			return inspecttext.WriteZone(os.Stdout, detail, "", verbose)
		}
	}
	paths := make([]zone.ZonePath, 0, len(state.Network.Zones))
	for path := range state.Network.Zones {
		paths = append(paths, path)
	}
	inspect.SortZonePaths(paths)
	details := make([]inspect.ZoneDetail, 0, len(paths))
	for _, path := range paths {
		zs := state.Network.Zones[path]
		if zs == nil {
			continue
		}
		details = append(details, inspect.BuildZoneDetail(inspect.ZoneDetailInput{
			Path:           path,
			State:          zs,
			Network:        state.Network,
			Now:            timeNow(),
			IncludeHistory: false,
		}))
	}
	return inspecttext.WriteZones(os.Stdout, details, filter, verbose)
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
