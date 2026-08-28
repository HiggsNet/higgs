package main

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/HiggsNet/photon/internal/inspect"
	inspecttext "github.com/HiggsNet/photon/internal/inspect/text"
)

// debugPeers implements `photon debug peers`: it prints the derived lifecycle
// status of every known peer, including state, reason, last sync, link counts
// and cleanup timers. It prioritizes daemon committed state when available.
func debugPeers(_ context.Context) error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	if response, ok, err := daemonStatusViaControl(rt); err != nil {
		return err
	} else if ok {
		fmt.Printf("daemon: online peer_id=%s link_instances=%d desired_links=%d\n",
			response.PeerID,
			response.LinkInstances,
			response.DesiredLinks,
		)
	}
	state, err := rt.LoadState()
	if err != nil {
		return err
	}
	return writeDebugPeers(os.Stdout, rt, state)
}

func showPeers(filter string, verbose bool) error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	state, err := rt.LoadState()
	if err != nil {
		return err
	}
	config, err := rt.SyncConfig(state)
	if err != nil {
		return err
	}
	return inspecttext.WriteGossipPeers(os.Stdout, buildGossipPeerViews(state, config, rt.Now()), filter, verbose)
}

// writeDebugPeers writes the peer status table to w. It is separated from
// debugPeers for testability.
func writeDebugPeers(w io.Writer, rt *Runtime, state *stateFile) error {
	if state == nil {
		return nil
	}
	return inspecttext.WritePeerLifecycleDebug(w, buildPeerLifecycleDebugView(rt, state))
}

func buildPeerLifecycleDebugView(rt *Runtime, state *stateFile) inspect.PeerLifecycleDebugView {
	if state == nil {
		return inspect.PeerLifecycleDebugView{}
	}
	now := rt.Now()
	cfg := inspect.PeerLifecycleConfig{}
	if rt != nil && rt.Config != nil {
		cfg = rt.Config.PeerLifecycle
	}
	hasOverlay := rt != nil && rt.Config != nil && len(rt.Config.IPsec.LinkGroups) > 0

	peers := derivePeerStatuses(state.ManagedZone, state.Network, state.SyncPeers, state.PeerCleanups, state.LinkInstances, state.IPsecReconcile, now, cfg, hasOverlay)
	return inspect.BuildPeerLifecycleDebug(inspect.PeerLifecycleDebugInput{
		Config: cfg,
		Peers:  peers,
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
