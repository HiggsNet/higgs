package main

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/Catofes/higgs/internal/inspect"
	inspecttext "github.com/Catofes/higgs/internal/inspect/text"
)

// debugPeers implements `higgs debug peers`: it prints the derived lifecycle
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
	return inspecttext.WritePeers(os.Stdout, buildPeerLifecycleDebugView(rt, state), filter, verbose)
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

	peers := derivePeerStatuses(state, now, cfg, hasOverlay)
	return inspect.BuildPeerLifecycleDebug(inspect.PeerLifecycleDebugInput{
		Config: cfg,
		Peers:  peers,
	})
}

// peerStatusSnapshotForControl returns the peer status list for a daemon
// control API response. It is called from the control handler when the
// `peers_status` method is invoked.
func (d *DaemonService) peerStatusSnapshotForControl() ([]inspect.PeerStatusInfo, daemonStateStoreMeta) {
	if d == nil || d.Sync == nil {
		return nil, daemonStateStoreMeta{}
	}
	state, _, meta := d.snapshotState()
	if state == nil {
		return nil, meta
	}
	now := d.Sync.now()
	cfg := inspect.PeerLifecycleConfig{}
	if d.Sync.App != nil && d.Sync.App.Config != nil {
		cfg = d.Sync.App.Config.PeerLifecycle
	}
	hasOverlay := d.Sync.App != nil && d.Sync.App.Config != nil && len(d.Sync.App.Config.IPsec.LinkGroups) > 0
	return derivePeerStatuses(state, now, cfg, hasOverlay), meta
}
