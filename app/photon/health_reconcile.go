package main

import (
	"context"
	"errors"
	"os"
	"strings"
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
	inspecttext "github.com/HiggsNet/photon/internal/inspect/text"
	"github.com/HiggsNet/photon/internal/observability/healthspool"
	photonstate "github.com/HiggsNet/photon/internal/state"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/health"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
	"github.com/urfave/cli/v3"
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

// healthTargets derives probe targets from Linux link runtime state. Only
// links with valid peer tunnel addresses and probeable state are returned.
func healthTargets(instances map[string]linkInstanceState, reconcile *ipsecReconcileState, localZone string) []health.ProbeTarget {
	var targets []health.ProbeTarget
	outputs := buildLinkOutputs(instances, reconcile)
	for _, output := range outputs {
		if !output.LocalAddr.IsValid() || !output.PeerAddr.IsValid() {
			continue
		}
		role := output.RuntimeRole
		probeRole := role
		if role == photonstate.LinkRuntimeActive {
			probeRole = "active"
			if hasStagedLinkOutput(outputs, output.ID) {
				probeRole = "old"
			}
		}
		target := health.ProbeTarget{
			InstanceID:      output.ID,
			GroupID:         output.GroupID,
			PeerZone:        string(output.PeerZone),
			LocalZone:       localZone,
			Overlay:         output.GroupID,
			NetNS:           output.NetNS,
			InterfaceName:   output.InterfaceName,
			UnderlayFamily:  underlayFamilyFromPathKey(output.PathKey),
			Generation:      output.Generation,
			ProbeRole:       probeRole,
			State:           output.State,
			LocalTunnelAddr: output.LocalAddr,
			PeerTunnelAddr:  output.PeerAddr,
		}
		if probeRole != "active" {
			target.ProbeID = healthProbeID(output.ID, probeRole)
		}
		if role == photonstate.LinkRuntimeStaged {
			target.InstanceID = strings.TrimSuffix(output.ID, "#"+photonstate.LinkRuntimeStaged)
			target.ProbeID = healthProbeID(target.InstanceID, "staged")
			target.Staged = true
		}
		targets = append(targets, target)
	}
	return targets
}

func underlayFamilyFromPathKey(pathKey string) string {
	family, ok := strings.CutPrefix(pathKey, "family:")
	if !ok || (family != ipsec.FamilyIPv4 && family != ipsec.FamilyIPv6) {
		return ""
	}
	return family
}

func hasStagedLinkOutput(outputs []photonstate.LinkOutput, linkID string) bool {
	for _, output := range outputs {
		if output.ID == runtimeLinkOutputID(linkID, photonstate.LinkRuntimeStaged) {
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
	if before, _, ok := strings.Cut(s, "%"); ok {
		return before
	}
	if before, _, ok := strings.Cut(s, " "); ok {
		return before
	}
	return s
}

func scopedNetNS(s string) string {
	for field := range strings.FieldsSeq(s) {
		if netns, ok := strings.CutPrefix(field, "netns="); ok {
			return strings.TrimSpace(netns)
		}
	}
	return ""
}

// reconcileHealth updates the health manager with the current link targets.
// In a running daemon, the independent health scheduler picks up due probes;
// the synchronous fallback supports one-shot callers and tests.
func (d *DaemonService) reconcileHealth(ctx context.Context) int {
	if d == nil || d.health == nil {
		return 0
	}
	if d.Sync == nil {
		return 0
	}
	d.StateStore.writeMu.Lock()
	view := d.StateStore.common.ReadView()
	d.StateStore.mu.RLock()
	localZone := ""
	if view.State != nil {
		localZone = view.State.ManagedZone.String()
	}
	targets := healthTargets(d.StateStore.runtime.LinkInstances, d.StateStore.runtime.IPsecReconcile, localZone)
	d.StateStore.mu.RUnlock()
	d.StateStore.writeMu.Unlock()
	now := d.Sync.now()
	d.health.SetTargets(targets, now)
	return d.tickHealth(ctx, now)
}

// tickHealth runs due probes without rebuilding the target set. Keeping this
// separate from reconcileHealth lets the daemon honor health.interval even
// when IPsec reconciliation is infrequent.
func (d *DaemonService) tickHealth(ctx context.Context, now time.Time) int {
	if d == nil || d.health == nil {
		return 0
	}
	if d.healthUpdates != nil {
		return 0
	}
	dispatched := d.health.Tick(ctx, now)
	if dispatched > 0 {
		d.handleHealthUpdate(now)
	}
	return dispatched
}

// startHealthProbeLoop owns periodic probe dispatch for a running daemon.
// Target changes remain synchronized through Manager's lock, while command
// execution stays in its bounded worker pool. A one-second cadence preserves
// the health scheduler's intended timer resolution without waking the daemon's
// primary event loop.
func (d *DaemonService) startHealthProbeLoop(ctx context.Context) <-chan struct{} {
	if d == nil || d.health == nil {
		return nil
	}
	updates := d.health.StartAsync(ctx)
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			d.health.TickAsync(ctx, d.Sync.now())
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	return updates
}

// drainHealthUpdates coalesces completed async probes before the daemon
// computes its next deadline. The channel is intentionally best-effort: a
// single snapshot represents every completion received in this drain.
func (d *DaemonService) drainHealthUpdates() bool {
	if d == nil || d.healthUpdates == nil {
		return false
	}
	updated := false
	for {
		select {
		case <-d.healthUpdates:
			updated = true
		default:
			return updated
		}
	}
}

func (d *DaemonService) handleHealthUpdate(now time.Time) {
	if d == nil || d.health == nil {
		return
	}
	if err := d.healthSpool.Append(now, healthSpoolSamples(d.healthStatusResponse())); err != nil && !errors.Is(err, healthspool.ErrNotConfigured) {
		d.logWarn("health", "spool_write_failed", map[string]any{"error": err})
	}
	d.notifyObserver("health_updated", d.observerHealthLinkIDsPayload())
}

func healthSpoolSamples(links []healthLinkJSON) []healthspool.Sample {
	samples := make([]healthspool.Sample, 0, len(links))
	for _, link := range links {
		samples = append(samples, healthspool.Sample{
			ProbeID:       link.ProbeID,
			InstanceID:    link.InstanceID,
			ProbeRole:     link.ProbeRole,
			InterfaceName: link.InterfaceName,
			State:         link.State,
			ProbeType:     link.ProbeType,
			RTTMs:         link.LastRTTMs,
			LossRatioPct:  link.LossRatio,
			JitterMs:      link.JitterMs,
			Sent:          link.Sent,
			Received:      link.Received,
			Lost:          link.Lost,
		})
	}
	return samples
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

// showHealth prints the current link health state to stdout.
func showHealth(sortBy string, verbose bool) error {
	sortBy = strings.ToLower(strings.TrimSpace(sortBy))
	if sortBy != inspect.HealthSortPeer && sortBy != inspect.HealthSortRTT {
		return cli.Exit("--sort must be peer or rtt", 1)
	}
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	view, online, err := readCanonicalViewViaControl[inspect.HealthDebugView](rt, controlRequest{Method: "health_status"})
	if err != nil {
		return err
	}
	if !online {
		common, runtime, err := loadOfflineOwnerViews(rt)
		if err != nil {
			return err
		}
		if common.State == nil || runtime == nil {
			_, _ = os.Stdout.WriteString("no state loaded\n")
			return nil
		}
		view = healthViewFromOwners(common, runtime, nil)
	}
	return inspecttext.WriteHealth(os.Stdout, view, sortBy, verbose)
}

func healthViewFromOwners(common corestate.View, runtime *linuxRuntimeState, live []healthLinkJSON) inspect.HealthDebugView {
	view := inspect.HealthDebugView{Live: inspectHealthLiveLinks(live)}
	if common.State == nil || runtime == nil {
		return view
	}
	view.Targets = inspectHealthProbeTargets(healthTargets(runtime.LinkInstances, runtime.IPsecReconcile, string(common.State.ManagedZone)))
	return view
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
			UnderlayFamily:  target.UnderlayFamily,
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
