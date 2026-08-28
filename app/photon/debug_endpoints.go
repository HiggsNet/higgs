package main

import (
	"os"

	"github.com/HiggsNet/photon/internal/inspect"
	inspecttext "github.com/HiggsNet/photon/internal/inspect/text"
)

func debugEndpoints() error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	if view, ok, err := readCanonicalViewViaControl[inspect.EndpointDebugView](rt, controlRequest{Method: "endpoints_view"}); err != nil {
		return err
	} else if ok {
		return inspecttext.WriteEndpointsDebug(os.Stdout, view)
	}
	common, _, err := loadOfflineOwnerViews(rt)
	if err != nil {
		return err
	}
	if common.State == nil {
		return nil
	}
	view := inspect.BuildEndpointDebug(common.State, rt.Now())
	return inspecttext.WriteEndpointsDebug(os.Stdout, view)
}
