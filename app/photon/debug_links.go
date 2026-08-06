package main

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/Catofes/photon/internal/inspect"
	inspecttext "github.com/Catofes/photon/internal/inspect/text"
	photonstate "github.com/Catofes/photon/internal/state"
)

func debugLinks(filter string) error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	if response, ok, err := linksStatusViaControl(rt); err != nil {
		return err
	} else if ok {
		if response.Links == nil {
			return errors.New("daemon links_status response missing links")
		}
		fmt.Printf("daemon: online peer_id=%s link_instances=%d desired_links=%d last_link_error=%s\n",
			response.PeerID,
			response.Links.Inspection.Summary.LinkInstances,
			response.Links.Inspection.Summary.DesiredLinks,
			dash(response.Links.Inspection.Summary.LastError),
		)
		return writeDebugLinksFromBuild(os.Stdout, linkInspectionBuildFromControl(response.Links), filter)
	}
	state, err := rt.LoadState()
	if err != nil {
		return err
	}
	return writeDebugLinks(os.Stdout, rt, state, filter)
}

func showLinks(filter string, verbose bool) error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	if response, ok, err := linksStatusViaControl(rt); err != nil {
		return err
	} else if ok {
		if response.Links == nil {
			return errors.New("daemon links_status response missing links")
		}
		return inspecttext.WriteLinks(os.Stdout, linkInspectionBuildFromControl(response.Links).Inspection, filter, verbose)
	}
	state, err := rt.LoadState()
	if err != nil {
		return err
	}
	return inspecttext.WriteLinks(os.Stdout, buildLinkInspection(rt, state, nil).Inspection, filter, verbose)
}

func writeDebugLinks(w io.Writer, rt *Runtime, state *stateFile, filter string) error {
	build := buildLinkInspection(rt, state, nil)
	return writeDebugLinksFromBuild(w, build, filter)
}

func linkInspectionBuildFromControl(in *linkInspectionControl) linkInspectionBuild {
	if in == nil {
		return linkInspectionBuild{}
	}
	return linkInspectionBuild{
		Inspection:        in.Inspection,
		Outputs:           append([]photonstate.LinkOutput(nil), in.Outputs...),
		ReplannedDesired:  in.ReplannedDesired,
		ReplanIgnored:     in.ReplanIgnored,
		LastDesiredLinks:  in.LastDesiredLinks,
		DesiredPlanSource: in.DesiredPlanSource,
	}
}

func writeDebugLinksFromBuild(w io.Writer, build linkInspectionBuild, filter string) error {
	return inspecttext.WriteLinksDebug(w, inspect.LinksDebugView{
		Inspection:        build.Inspection,
		PlannedSpecs:      build.PlannedSpecs,
		ReplannedDesired:  build.ReplannedDesired,
		ReplanIgnored:     build.ReplanIgnored,
		LastDesiredLinks:  build.LastDesiredLinks,
		DesiredPlanSource: build.DesiredPlanSource,
		Filter:            filter,
	})
}

func debugLinkRoutingState(rt *Runtime, birdInstances map[string]*BirdInstanceState, groupID string) (state, neighborCount, bestRouteCount string) {
	state = "-"
	neighborCount = "-"
	bestRouteCount = "-"
	if rt == nil || rt.Config == nil || groupID == "" {
		return
	}
	// In the per-netns model, routing is configured at the netns level.
	// Map the overlay groupID to netns name and look up the BIRD instance by netns.
	netnsName := routingNetnsNameForLinkInstance(rt, groupID)
	if netnsName == "" {
		return
	}
	hasRoutingInstance := false
	for _, inst := range rt.Config.Routing.Instances {
		if inst.NetNS == netnsName && inst.Enabled {
			hasRoutingInstance = true
			break
		}
	}
	if !hasRoutingInstance {
		return
	}
	state = "pending"
	if birdInstances != nil {
		if inst := birdInstances[netnsName]; inst != nil {
			state = inst.State
			if state == "" {
				state = "pending"
			}
		}
	}
	return
}

func desiredByInstanceID(items []desiredLinkState) map[string]desiredLinkState {
	out := map[string]desiredLinkState{}
	for _, item := range items {
		if item.InstanceID != "" {
			out[item.InstanceID] = item
		}
	}
	return out
}
