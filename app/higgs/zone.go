package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/Catofes/higgs/pkg/core/zone"
)

func showZone(path zone.ZonePath) error {
	state, err := loadState()
	if err != nil {
		return err
	}
	zs := state.Network.Zones[path]
	if zs == nil {
		return fmt.Errorf("%w: %s", zone.ErrZoneNotFound, path)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(zs)
}
