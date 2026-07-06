package main

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"strings"

	"github.com/Catofes/higgs/internal/inspect"
	inspecttext "github.com/Catofes/higgs/internal/inspect/text"
	"github.com/Catofes/higgs/pkg/health"
	"github.com/Catofes/higgs/pkg/transport/ipsec"
)

// newHealthManager creates a health.Manager from app config. Returns nil when
// health probing is disabled. The prober is injected by the daemon based on
// capabilities.
func newHealthManager(cfg healthConfig, prober health.Prober) *health.Manager {
	if !cfg.Enabled {
		return nil
	}
	return health.NewManager(cfg.probeConfig(), cfg.hysteresisConfig(), prober)
}

// healthTargetsFromState derives ProbeTargets from the current desired link
// snapshot and persisted LinkInstances. Only links with a valid peer tunnel
// address and probeable state are returned.
func healthTargetsFromState(state *stateFile, localZone string, _ []ipsec.LinkGroupSpec) []health.ProbeTarget {
	if state == nil || state.IPsecReconcile == nil {
		return nil
	}
	instanceMap := map[string]linkInstanceState{}
	if state.LinkInstances != nil {
		for id, inst := range state.LinkInstances {
			instanceMap[id] = inst
		}
	}
	var targets []health.ProbeTarget
	for _, d := range state.IPsecReconcile.Desired {
		inst := instanceMap[d.InstanceID]
		base := health.ProbeTarget{
			InstanceID:    d.InstanceID,
			GroupID:       d.GroupID,
			PeerZone:      string(d.PeerZone),
			LocalZone:     localZone,
			Overlay:       d.GroupID,
			NetNS:         scopedNetNS(d.PeerTunnelAddr),
			InterfaceName: firstNonEmpty(inst.InterfaceName, d.InterfaceName),
			Generation:    inst.RemoteGeneration,
			ProbeRole:     "active",
			State:         inst.ActualState,
		}
		if base.NetNS == "" {
			base.NetNS = scopedNetNS(d.LocalTunnelAddr)
		}
		if addr, err := netip.ParseAddr(stripScope(d.PeerTunnelAddr)); err == nil {
			base.PeerTunnelAddr = addr
		}
		if addr, err := netip.ParseAddr(stripScope(d.LocalTunnelAddr)); err == nil {
			base.LocalTunnelAddr = addr
		}
		applyStateTunnelAddrs(&base, inst.LocalTunnelAddr, inst.PeerTunnelAddr)
		if shouldProbeStagedInterface(inst) {
			oldTarget := health.ProbeTarget{
				InstanceID:    d.InstanceID,
				GroupID:       d.GroupID,
				PeerZone:      string(d.PeerZone),
				LocalZone:     localZone,
				Overlay:       d.GroupID,
				NetNS:         base.NetNS,
				ProbeID:       healthProbeID(d.InstanceID, "old"),
				ProbeRole:     "old",
				InterfaceName: firstNonEmpty(inst.InterfaceName, d.InterfaceName),
				Generation:    inst.RemoteGeneration,
				State:         inst.ActualState,
			}
			if applyStateTunnelAddrs(&oldTarget, inst.LocalTunnelAddr, inst.PeerTunnelAddr) && probeTargetHasTunnelAddrs(oldTarget) {
				targets = append(targets, oldTarget)
			}

			stagedTarget := health.ProbeTarget{
				InstanceID:    d.InstanceID,
				GroupID:       d.GroupID,
				PeerZone:      string(d.PeerZone),
				LocalZone:     localZone,
				Overlay:       d.GroupID,
				NetNS:         base.NetNS,
				ProbeID:       healthProbeID(d.InstanceID, "staged"),
				ProbeRole:     "staged",
				InterfaceName: inst.StagedInterfaceName,
				Generation:    inst.StagedGeneration,
				State:         inst.ActualState,
				Staged:        true,
			}
			if applyStateTunnelAddrs(&stagedTarget, inst.StagedLocalTunnelAddr, inst.StagedPeerTunnelAddr) && probeTargetHasTunnelAddrs(stagedTarget) {
				targets = append(targets, stagedTarget)
			}
			continue
		}
		if probeTargetHasTunnelAddrs(base) {
			targets = append(targets, base)
		}
	}
	return targets
}

func applyStateTunnelAddrs(target *health.ProbeTarget, localAddr, peerAddr string) bool {
	if target == nil {
		return false
	}
	updated := false
	if local, err := netip.ParseAddr(stripScope(localAddr)); err == nil {
		target.LocalTunnelAddr = local
		updated = true
	}
	if peer, err := netip.ParseAddr(stripScope(peerAddr)); err == nil {
		target.PeerTunnelAddr = peer
		updated = true
	}
	return updated
}

func probeTargetHasTunnelAddrs(target health.ProbeTarget) bool {
	return target.LocalTunnelAddr.IsValid() && target.PeerTunnelAddr.IsValid()
}

func shouldProbeStagedInterface(inst linkInstanceState) bool {
	if inst.StagedGeneration != 0 && inst.StagedInterfaceName != "" {
		switch inst.RotatePhase {
		case "preparing", "testing_new", "dual_running", "cutover":
			return true
		}
	}
	return false
}

func healthProbeID(instanceID, role string) string {
	if role == "" || role == "active" {
		return instanceID
	}
	return instanceID + "#" + role
}

// stripScope removes the %iface and netns=... suffixes from a scoped tunnel
// address string before parsing.
func stripScope(s string) string {
	if i := strings.Index(s, "%"); i >= 0 {
		return s[:i]
	}
	if i := strings.Index(s, " "); i >= 0 {
		return s[:i]
	}
	return s
}

func scopedNetNS(s string) string {
	for _, field := range strings.Fields(s) {
		if netns, ok := strings.CutPrefix(field, "netns="); ok {
			return strings.TrimSpace(netns)
		}
	}
	return ""
}

// reconcileHealth updates the health manager with the current link targets,
// ticks any due probes, and returns the number of probes dispatched. It is
// meant to be called from the daemon event loop after IPsec reconcile.
func (d *DaemonService) reconcileHealth(ctx context.Context) int {
	if d == nil || d.health == nil {
		return 0
	}
	if d.Sync == nil || d.Sync.State == nil {
		return 0
	}
	localZone := ""
	if d.Sync.State != nil {
		localZone = string(d.Sync.State.ManagedZone)
	}
	var groups []ipsec.LinkGroupSpec
	if d.Sync.App != nil && d.Sync.App.Config != nil {
		groups = d.Sync.App.Config.IPsec.LinkGroups
	}
	targets := healthTargetsFromState(d.Sync.State, localZone, groups)
	now := d.Sync.now()
	d.health.SetTargets(targets, now)
	dispatched := d.health.Tick(ctx, now)
	if dispatched > 0 {
		if err := d.appendHealthSpool(now, d.healthStatusResponse()); err != nil && !errors.Is(err, errHealthSpoolNotConfigured) {
			d.logWarn("health", "spool_write_failed", map[string]any{"error": err})
		}
	}
	return dispatched
}

// healthStatusResponse builds the control API response for `health_status`.
func (d *DaemonService) healthStatusResponse() []healthLinkJSON {
	if d == nil || d.health == nil {
		return nil
	}
	now := d.Sync.now()
	snapshot := d.health.Snapshot(now)
	out := make([]healthLinkJSON, 0, len(snapshot))
	for _, h := range snapshot {
		view := healthLinkHealthView{
			ProbeID:         h.ProbeID,
			InstanceID:      h.InstanceID,
			ProbeRole:       h.ProbeRole,
			InterfaceName:   h.InterfaceName,
			State:           h.State,
			ProbeType:       h.ProbeType,
			Sent:            h.Sent,
			Received:        h.Received,
			Lost:            h.Lost,
			LossRatio:       h.LossRatio,
			LastRTT:         h.LastRTT,
			EWMARTT:         h.EWMARTT,
			P50RTT:          h.P50RTT,
			P95RTT:          h.P95RTT,
			P99RTT:          h.P99RTT,
			Jitter:          h.Jitter,
			ConsecutiveFail: h.ConsecutiveFail,
			LastError:       h.LastError,
			NextProbeUnix:   h.NextProbeAt.Unix(),
			CutoverBlocking: h.CutoverBlocking,
		}
		out = append(out, healthLinkJSONFromHealth(view))
	}
	return out
}

// debugHealth prints the current link health state to stdout.
func debugHealth() error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	state, err := rt.LoadState()
	if err != nil {
		return err
	}
	if state == nil {
		_, _ = os.Stdout.WriteString("no state loaded\n")
		return nil
	}
	// Reconstruct targets and print from state.
	localZone := string(state.ManagedZone)
	rtConfig := rt.Config
	var groups []ipsec.LinkGroupSpec
	if rtConfig != nil {
		groups = rtConfig.IPsec.LinkGroups
	}
	targets := inspectHealthProbeTargets(healthTargetsFromState(state, localZone, groups))
	view := inspect.HealthDebugView{Targets: targets}
	// Health manager output (when daemon live).
	if links := liveDaemonHealthSnapshot(rt); links != nil {
		view.Live = inspectHealthLiveLinks(links)
	}
	return inspecttext.WriteHealthDebug(os.Stdout, view)
}

func inspectHealthProbeTargets(targets []health.ProbeTarget) []inspect.HealthProbeTargetView {
	out := make([]inspect.HealthProbeTargetView, 0, len(targets))
	for _, target := range targets {
		out = append(out, inspect.HealthProbeTargetView{
			ProbeID:         target.ProbeID,
			InstanceID:      target.InstanceID,
			PeerZone:        target.PeerZone,
			Overlay:         target.Overlay,
			InterfaceName:   target.InterfaceName,
			LocalTunnelAddr: target.LocalTunnelAddr.String(),
			PeerTunnelAddr:  target.PeerTunnelAddr.String(),
			ProbeRole:       target.ProbeRole,
			State:           target.State,
			Staged:          target.Staged,
		})
	}
	return out
}

func inspectHealthLiveLinks(links []healthLinkJSON) []inspect.HealthLiveView {
	out := make([]inspect.HealthLiveView, 0, len(links))
	for _, link := range links {
		out = append(out, inspect.HealthLiveView{
			ProbeID:         link.ProbeID,
			InstanceID:      link.InstanceID,
			ProbeRole:       link.ProbeRole,
			State:           link.State,
			ProbeType:       link.ProbeType,
			Sent:            link.Sent,
			Received:        link.Received,
			Lost:            link.Lost,
			LossRatio:       link.LossRatio,
			LastRTTMs:       link.LastRTTMs,
			EWMARTTMs:       link.EWMARTTMs,
			P50RTTMs:        link.P50RTTMs,
			P95RTTMs:        link.P95RTTMs,
			P99RTTMs:        link.P99RTTMs,
			JitterMs:        link.JitterMs,
			ConsecutiveFail: link.ConsecutiveFail,
			LastError:       link.LastError,
			CutoverBlocking: link.CutoverBlocking,
		})
	}
	return out
}

// liveDaemonHealthSnapshot reads health state from a running daemon via the
// control socket. Returns nil if the daemon is not running.
func liveDaemonHealthSnapshot(rt *Runtime) []healthLinkJSON {
	path := controlSocketPath(rt.Config)
	resp, err := sendControlRequest(path, controlRequest{Method: "health_status"})
	if err != nil && isControlSocketUnavailable(err) {
		return nil
	}
	if err != nil {
		return nil
	}
	return resp.Health
}
