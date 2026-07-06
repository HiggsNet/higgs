package main

import (
	"fmt"
	"os"

	"github.com/Catofes/higgs/internal/inspect"
	inspecttext "github.com/Catofes/higgs/internal/inspect/text"
	"github.com/Catofes/higgs/pkg/core/zone"
)

func showZone(path zone.ZonePath, includeHistory bool) error {
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
		IncludeHistory: includeHistory,
	})
	return inspecttext.WriteJSON(os.Stdout, out)
}
