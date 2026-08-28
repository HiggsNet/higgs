package main

import (
	"os"

	"github.com/HiggsNet/photon/internal/inspect"
	inspecttext "github.com/HiggsNet/photon/internal/inspect/text"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
)

func showStatus() error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	if view, online, err := readCanonicalViewViaControl[inspect.StatusView](rt, controlRequest{Method: "status_view"}); err != nil {
		return err
	} else if online {
		return inspecttext.WriteStatus(os.Stdout, view)
	}
	common, runtime, err := loadOfflineOwnerViews(rt)
	if err != nil {
		return err
	}
	return inspecttext.WriteStatus(os.Stdout, statusViewFromOwners(rt, common, runtime, nil, false))
}

func statusViewFromOwners(rt *Runtime, common corestate.View, runtime *linuxRuntimeState, health []healthLinkJSON, daemonOnline bool) inspect.StatusView {
	if common.State == nil || runtime == nil {
		return inspect.BuildStatus(inspect.StatusInput{DaemonOnline: daemonOnline})
	}
	verified := common.State
	peers := syncPeerReadView(common.Gossip)
	input := inspect.StatusInput{
		DaemonOnline:   daemonOnline,
		GossipSource:   "checkpoint",
		PlatformSource: "unavailable",
		ManagedZone:    verified.ManagedZone,
		Admission:      diagnoseAutoJoinAdmission(verified, runtime.Admission, rt.Now()),
	}
	if daemonOnline {
		input.GossipSource = "runtime"
		input.PlatformSource = "runtime"
		input.Links = buildStoredLinkInspection(rt, runtime.LinkInstances, runtime.IPsecReconcile, runtime.BirdInstances, health).Inspection
	}
	cfg := inspect.PeerLifecycleConfig{}
	hasOverlay := false
	if rt != nil && rt.Config != nil {
		cfg = rt.Config.PeerLifecycle
		hasOverlay = len(rt.Config.IPsec.LinkGroups) > 0
	}
	input.Peers = derivePeerStatuses(verified.ManagedZone, verified.Network, peers, runtime.PeerCleanups, runtime.LinkInstances, runtime.IPsecReconcile, rt.Now(), cfg, hasOverlay)
	return inspect.BuildStatus(input)
}
