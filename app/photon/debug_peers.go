package main

import (
	"context"
	"fmt"
	"os"

	"github.com/HiggsNet/photon/internal/inspect"
	inspecttext "github.com/HiggsNet/photon/internal/inspect/text"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

// debugPeers implements `photon debug peers`: it prints the derived lifecycle
// status of every known peer, including state, reason, last sync, link counts
// and cleanup timers. It prioritizes daemon committed state when available.
func debugPeers(_ context.Context) error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	if status, ok, err := daemonStatusViaControl(rt); err != nil {
		return err
	} else if ok {
		fmt.Printf("daemon: online peer_id=%s link_instances=%d desired_links=%d\n",
			status.PeerID,
			status.LinkInstances,
			status.DesiredLinks,
		)
		view, peersOnline, err := readCanonicalViewViaControl[inspect.PeerLifecycleDebugView](rt, controlRequest{Method: "peer_lifecycle_view"})
		if err != nil {
			return err
		}
		if peersOnline {
			return inspecttext.WritePeerLifecycleDebug(os.Stdout, view)
		}
	}
	common, runtime, err := loadOfflineOwnerViews(rt)
	if err != nil {
		return err
	}
	if common.State == nil || runtime == nil {
		return nil
	}
	view := buildPeerLifecycleDebugView(rt, common.State.ManagedZone, common.State.Network, syncPeerReadView(common.Gossip), runtime)
	return inspecttext.WritePeerLifecycleDebug(os.Stdout, view)
}

func showPeers(filter string, verbose bool) error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	if peers, ok, err := readCanonicalViewViaControl[[]inspect.PeerDebugView](rt, controlRequest{Method: "gossip_peers_view"}); err != nil {
		return err
	} else if ok {
		return inspecttext.WriteGossipPeers(os.Stdout, peers, filter, verbose)
	}
	common, _, err := loadOfflineOwnerViews(rt)
	if err != nil {
		return err
	}
	if common.State == nil {
		return nil
	}
	config := syncConfigFromAppConfig(rt.Config, common.State)
	return inspecttext.WriteGossipPeers(os.Stdout, buildGossipPeerViews(common.State.ManagedZone, common.State.Network, syncPeerReadView(common.Gossip), config, rt.Now()), filter, verbose)
}

func buildPeerLifecycleDebugView(rt *Runtime, managedZone zone.ZonePath, network *zone.NetworkState, peers map[string]syncPeerState, runtime *linuxRuntimeState) inspect.PeerLifecycleDebugView {
	if network == nil || runtime == nil {
		return inspect.PeerLifecycleDebugView{}
	}
	now := rt.Now()
	cfg := inspect.PeerLifecycleConfig{}
	if rt != nil && rt.Config != nil {
		cfg = rt.Config.PeerLifecycle
	}
	hasOverlay := rt != nil && rt.Config != nil && len(rt.Config.IPsec.LinkGroups) > 0

	statuses := derivePeerStatuses(managedZone, network, peers, runtime.PeerCleanups, runtime.LinkInstances, runtime.IPsecReconcile, now, cfg, hasOverlay)
	return inspect.BuildPeerLifecycleDebug(inspect.PeerLifecycleDebugInput{
		Config: cfg,
		Peers:  statuses,
	})
}

// peerStatusSnapshotForControl returns the peer status list for a daemon
// control API response. It is called from the control handler when the
// `peers_status` method is invoked.
func (d *DaemonService) peerStatusSnapshotForControl() ([]inspect.PeerStatusInfo, daemonStateStoreMeta, bool) {
	if d == nil || d.Sync == nil || d.StateStore == nil || d.StateStore.common == nil {
		return nil, daemonStateStoreMeta{}, false
	}
	now := d.Sync.now()
	cfg := inspect.PeerLifecycleConfig{}
	if d.Sync.App != nil && d.Sync.App.Config != nil {
		cfg = d.Sync.App.Config.PeerLifecycle
	}
	hasOverlay := d.Sync.App != nil && d.Sync.App.Config != nil && len(d.Sync.App.Config.IPsec.LinkGroups) > 0
	d.StateStore.writeMu.Lock()
	view := d.StateStore.common.ReadView()
	peers := syncPeerReadView(view.Gossip)
	d.StateStore.mu.RLock()
	meta := d.StateStore.metaLocked()
	if view.State == nil || d.StateStore.runtime == nil {
		d.StateStore.mu.RUnlock()
		d.StateStore.writeMu.Unlock()
		return nil, meta, false
	}
	statuses := derivePeerStatuses(view.State.ManagedZone, view.State.Network, peers, d.StateStore.runtime.PeerCleanups, d.StateStore.runtime.LinkInstances, d.StateStore.runtime.IPsecReconcile, now, cfg, hasOverlay)
	d.StateStore.mu.RUnlock()
	d.StateStore.writeMu.Unlock()
	return statuses, meta, true
}

func (d *DaemonService) gossipPeerSnapshotForControl() []inspect.PeerDebugView {
	if d == nil || d.Sync == nil || d.StateStore == nil || d.StateStore.common == nil {
		return nil
	}
	view := d.StateStore.common.ReadView()
	if view.State == nil {
		return nil
	}
	return buildGossipPeerViews(view.State.ManagedZone, view.State.Network, syncPeerReadView(view.Gossip), d.Sync.Config, d.Sync.now())
}
