package main

import (
	"errors"
	"os"

	"github.com/HiggsNet/photon/internal/inspect"
	inspecttext "github.com/HiggsNet/photon/internal/inspect/text"
)

func showStatus() error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	state, err := rt.LoadState()
	if err != nil {
		return err
	}

	input := statusInputFromState(rt, state)
	if _, online, err := daemonStatusViaControl(rt); err != nil {
		return err
	} else if online {
		input.DaemonOnline = true
		if response, ok, err := admissionStatusViaControl(rt); err != nil {
			return err
		} else if ok && response != nil && response.Admission != nil {
			input.Admission = *response.Admission
		}
		if response, ok, err := peersStatusViaControl(rt); err != nil {
			return err
		} else if ok && response != nil {
			input.Peers = response.PeerStatuses
		}
		if response, ok, err := linksStatusViaControl(rt); err != nil {
			return err
		} else if ok && (response == nil || response.Links == nil) {
			return errors.New("daemon links_status response missing links")
		} else if ok {
			input.Links = response.Links.Inspection
		}
	}

	return inspecttext.WriteStatus(os.Stdout, inspect.BuildStatus(input))
}

func statusInputFromState(rt *Runtime, state *stateFile) inspect.StatusInput {
	if state == nil {
		return inspect.StatusInput{}
	}
	input := inspect.StatusInput{
		ManagedZone: state.ManagedZone,
		Admission:   diagnoseAutoJoinAdmission(state, rt.Now()),
		Links:       buildLinkInspection(rt, state, nil).Inspection,
	}
	cfg := inspect.PeerLifecycleConfig{}
	hasOverlay := false
	if rt != nil && rt.Config != nil {
		cfg = rt.Config.PeerLifecycle
		hasOverlay = len(rt.Config.IPsec.LinkGroups) > 0
	}
	input.Peers = derivePeerStatuses(state, rt.Now(), cfg, hasOverlay)
	return input
}
