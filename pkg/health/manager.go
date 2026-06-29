package health

import (
	"context"
	"math/rand"
	"sort"
	"sync"
	"time"
)

// Manager owns the per-link rolling windows, state machine, scheduler, and
// produces coalesced health results. It is safe for concurrent use.
//
// The daemon event loop drives the Manager:
//   - SetTargets / RemoveTarget on link create/update/remove
//   - Tick periodically dispatches due probes
//   - Snapshot / HealthFor reads the current state
//
// Probe dispatch is bounded by MaxConcurrent to avoid amplification.
type Manager struct {
	mu sync.Mutex

	cfg         ProbeConfig
	hysteresis  HysteresisConfig
	prober      Prober
	windows     map[string]*RollingWindow
	states      *StateMachine
	targets     map[string]ProbeTarget
	lastReason  map[string]string
	nextProbe   map[string]time.Time
	errorsTotal map[string]int
	babelObs    map[string]BabelObservation

	// inFlight tracks concurrent probe dispatch.
	inFlight    int
	maxInflight int
}

// NewManager creates a Manager. The Prober may be nil, in which case a no-op
// prober is used (all probes report probe_error).
func NewManager(cfg ProbeConfig, hyst HysteresisConfig, prober Prober) *Manager {
	if prober == nil {
		prober = nopProber{}
	}
	max := cfg.MaxConcurrent
	if max <= 0 {
		max = 8
	}
	return &Manager{
		cfg:         cfg,
		hysteresis:  hyst,
		prober:      prober,
		windows:     map[string]*RollingWindow{},
		states:      NewStateMachine(hyst),
		targets:     map[string]ProbeTarget{},
		lastReason:  map[string]string{},
		nextProbe:   map[string]time.Time{},
		errorsTotal: map[string]int{},
		babelObs:    map[string]BabelObservation{},
		maxInflight: max,
	}
}

// SetTargets replaces the full set of probe targets. Targets not present in
// the new set are removed (their state is reset).
func (m *Manager) SetTargets(targets []ProbeTarget, now time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	newMap := map[string]ProbeTarget{}
	for _, t := range targets {
		if !t.ShouldProbe() {
			continue
		}
		id := targetKey(t)
		newMap[id] = t
		if _, ok := m.targets[id]; !ok {
			m.windows[id] = NewRollingWindow(m.lossWindow())
			m.nextProbe[id] = now.Add(m.jitteredInterval())
		}
	}
	for id := range m.targets {
		if _, ok := newMap[id]; !ok {
			delete(m.targets, id)
			delete(m.windows, id)
			delete(m.nextProbe, id)
			delete(m.lastReason, id)
			delete(m.errorsTotal, id)
			delete(m.babelObs, id)
			m.states.Reset(id)
		}
	}
	m.targets = newMap
}

// UpsertTarget adds or updates a single target.
func (m *Manager) UpsertTarget(t ProbeTarget, now time.Time) {
	if !t.ShouldProbe() {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	id := targetKey(t)
	if _, ok := m.targets[id]; !ok {
		m.windows[id] = NewRollingWindow(m.lossWindow())
		m.nextProbe[id] = now.Add(m.jitteredInterval())
	}
	m.targets[id] = t
}

// RemoveTarget removes a target by probe ID and resets its state.
func (m *Manager) RemoveTarget(instanceID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.targets, instanceID)
	delete(m.windows, instanceID)
	delete(m.nextProbe, instanceID)
	delete(m.lastReason, instanceID)
	delete(m.errorsTotal, instanceID)
	delete(m.babelObs, instanceID)
	m.states.Reset(instanceID)
}

// SetBabelObservation stores passive Babel data for a link.
func (m *Manager) SetBabelObservation(obs BabelObservation) {
	if obs.InstanceID == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.babelObs[obs.InstanceID] = obs
}

// Tick dispatches any probes that are due and returns the number of probes
// dispatched in this tick. It is meant to be called from the daemon event loop
// on a short timer (e.g. 1s).
func (m *Manager) Tick(ctx context.Context, now time.Time) int {
	m.mu.Lock()
	if len(m.targets) == 0 {
		m.mu.Unlock()
		return 0
	}
	due := make([]string, 0, len(m.targets))
	for id, next := range m.nextProbe {
		if !next.IsZero() && !now.Before(next) && m.inFlight < m.maxInflight {
			due = append(due, id)
		}
	}
	sort.Strings(due)
	m.inFlight += len(due)
	pending := map[string]ProbeTarget{}
	for _, id := range due {
		pending[id] = m.targets[id]
	}
	m.mu.Unlock()

	if len(due) == 0 {
		return 0
	}

	dispatched := 0
	for id, t := range pending {
		dispatched++
		result := m.prober.Probe(ctx, t, m.cfg)
		m.applyResult(id, result, now)
	}

	m.mu.Lock()
	m.inFlight -= len(due)
	if m.inFlight < 0 {
		m.inFlight = 0
	}
	// Schedule next probe.
	for _, id := range due {
		m.nextProbe[id] = now.Add(m.jitteredInterval())
	}
	m.mu.Unlock()
	return dispatched
}

// NextDue returns the earliest next probe time across all targets, or the zero
// value if there are none. Used by the daemon to compute the next wake.
func (m *Manager) NextDue(now time.Time) (time.Time, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var earliest time.Time
	for _, next := range m.nextProbe {
		if next.IsZero() {
			continue
		}
		if earliest.IsZero() || next.Before(earliest) {
			earliest = next
		}
	}
	return earliest, !earliest.IsZero()
}

func (m *Manager) applyResult(instanceID string, result ProbeResult, now time.Time) {
	m.mu.Lock()
	window, ok := m.windows[instanceID]
	target, tok := m.targets[instanceID]
	m.mu.Unlock()
	if !ok || !tok {
		return
	}
	if result.Error != "" {
		m.mu.Lock()
		m.errorsTotal[instanceID]++
		m.lastReason[instanceID] = result.Error
		m.mu.Unlock()
	}
	window.Record(now, result.RTT, result.Success)

	snap := window.Snapshot()
	state, reason := m.states.Evaluate(instanceID, snap, m.lastErr(instanceID), now)
	if reason != "" {
		m.mu.Lock()
		m.lastReason[instanceID] = reason
		m.mu.Unlock()
	}
	_ = state
	_ = target
}

func (m *Manager) lastErr(instanceID string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastReason[instanceID]
}

// Snapshot returns the current health of all links.
func (m *Manager) Snapshot(now time.Time) []LinkHealth {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]LinkHealth, 0, len(m.targets))
	for id, t := range m.targets {
		window := m.windows[id]
		var snap WindowSnapshot
		if window != nil {
			snap = window.Snapshot()
		}
		labels := MetricsLabels{
			LocalZone:  t.LocalZone,
			PeerZone:   t.PeerZone,
			Overlay:    t.Overlay,
			ProbeID:    id,
			InstanceID: t.InstanceID,
			NetNS:      t.NetNS,
			Generation: generationLabel(t.Generation),
			ProbeRole:  t.ProbeRole,
			ProbeType:  m.prober.Type(),
			Reason:     m.lastReason[id],
		}
		next := m.nextProbe[id]
		h := LinkHealth{
			ProbeID:         id,
			InstanceID:      t.InstanceID,
			ProbeRole:       t.ProbeRole,
			InterfaceName:   t.InterfaceName,
			State:           m.states.State(id),
			ProbeType:       m.prober.Type(),
			Sent:            snap.Sent,
			Received:        snap.Received,
			Lost:            snap.Lost,
			LossRatio:       snap.LossRatio,
			LastRTT:         snap.LastRTT,
			EWMARTT:         snap.EWMARTT,
			MinRTT:          snap.MinRTT,
			MaxRTT:          snap.MaxRTT,
			P50RTT:          snap.P50RTT,
			P95RTT:          snap.P95RTT,
			P99RTT:          snap.P99RTT,
			Jitter:          snap.Jitter,
			ConsecutiveFail: snap.ConsecutiveFails,
			LastSuccess:     snap.LastSuccess,
			LastError:       m.lastReason[id],
			NextProbeAt:     next,
			CutoverBlocking: t.Staged && m.cutoverBlockingLocked(id),
			Labels:          labels,
		}
		out = append(out, h)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].InstanceID != out[j].InstanceID {
			return out[i].InstanceID < out[j].InstanceID
		}
		return out[i].ProbeID < out[j].ProbeID
	})
	return out
}

// HealthFor returns the health for a single instance.
func (m *Manager) HealthFor(instanceID string, now time.Time) (LinkHealth, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.targets[instanceID]
	if !ok {
		return LinkHealth{}, false
	}
	window := m.windows[instanceID]
	var snap WindowSnapshot
	if window != nil {
		snap = window.Snapshot()
	}
	labels := MetricsLabels{
		LocalZone:  t.LocalZone,
		PeerZone:   t.PeerZone,
		Overlay:    t.Overlay,
		ProbeID:    instanceID,
		InstanceID: t.InstanceID,
		NetNS:      t.NetNS,
		Generation: generationLabel(t.Generation),
		ProbeRole:  t.ProbeRole,
		ProbeType:  m.prober.Type(),
		Reason:     m.lastReason[instanceID],
	}
	return LinkHealth{
		ProbeID:         instanceID,
		InstanceID:      t.InstanceID,
		ProbeRole:       t.ProbeRole,
		InterfaceName:   t.InterfaceName,
		State:           m.states.State(instanceID),
		ProbeType:       m.prober.Type(),
		Sent:            snap.Sent,
		Received:        snap.Received,
		Lost:            snap.Lost,
		LossRatio:       snap.LossRatio,
		LastRTT:         snap.LastRTT,
		EWMARTT:         snap.EWMARTT,
		MinRTT:          snap.MinRTT,
		MaxRTT:          snap.MaxRTT,
		P50RTT:          snap.P50RTT,
		P95RTT:          snap.P95RTT,
		P99RTT:          snap.P99RTT,
		Jitter:          snap.Jitter,
		ConsecutiveFail: snap.ConsecutiveFails,
		LastSuccess:     snap.LastSuccess,
		LastError:       m.lastReason[instanceID],
		NextProbeAt:     m.nextProbe[instanceID],
		CutoverBlocking: t.Staged && m.cutoverBlockingLocked(instanceID),
		Labels:          labels,
	}, true
}

// CutoverBlocking reports whether the health state for a staged/rotating link
// blocks IPsec rotate cutover (6.6.4). A link blocks cutover when its health is
// not healthy and not better-than-old.
func (m *Manager) CutoverBlocking(instanceID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	found := false
	for id, target := range m.targets {
		if target.InstanceID != instanceID || !target.Staged {
			continue
		}
		found = true
		if m.cutoverBlockingLocked(id) {
			return true
		}
	}
	return !found
}

// RotateCutoverReadiness returns a map suitable for ipsec.ReconcileInputs.RotateCutoverReady.
func (m *Manager) RotateCutoverReadiness() map[string]bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]bool{}
	for id := range m.targets {
		t := m.targets[id]
		if !t.Staged {
			continue
		}
		out[t.InstanceID] = !m.cutoverBlockingLocked(id)
	}
	return out
}

func (m *Manager) cutoverBlockingLocked(instanceID string) bool {
	state := m.states.State(instanceID)
	switch state {
	case HealthStateHealthy, HealthStateDegraded:
		return false
	default:
		return true
	}
}

// ErrorsTotal returns the total probe errors counter for an instance.
func (m *Manager) ErrorsTotal(instanceID string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.errorsTotal[instanceID]
}

func (m *Manager) lossWindow() int {
	w := m.cfg.LossWindow
	if w <= 0 {
		w = 20
	}
	return w
}

func (m *Manager) jitteredInterval() time.Duration {
	if m.cfg.Jitter <= 0 {
		return m.cfg.Interval
	}
	delta := time.Duration(rand.Int63n(int64(m.cfg.Jitter*2))) - m.cfg.Jitter
	return m.cfg.Interval + delta
}

func generationLabel(g uint64) string {
	if g == 0 {
		return ""
	}
	return uint64ToString(g)
}

func uint64ToString(n uint64) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

func targetKey(t ProbeTarget) string {
	if t.ProbeID != "" {
		return t.ProbeID
	}
	return t.InstanceID
}
