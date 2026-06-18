package health

import "time"

// StateMachine evaluates rolling-window snapshots with hysteresis to derive
// the local LinkHealth state. It distinguishes failure reasons.
type StateMachine struct {
	cfg HysteresisConfig

	// current state per instance
	state         map[string]string
	consec        map[string]int
	consecRecover map[string]int
}

// NewStateMachine returns a state machine using the given config.
func NewStateMachine(cfg HysteresisConfig) *StateMachine {
	if cfg.FailThresholdConsecutive <= 0 {
		cfg.FailThresholdConsecutive = 3
	}
	if cfg.LossThreshold <= 0 {
		cfg.LossThreshold = 0.2
	}
	if cfg.DownLossThreshold <= 0 {
		cfg.DownLossThreshold = 0.6
	}
	if cfg.RecoverConsecutive <= 0 {
		cfg.RecoverConsecutive = 5
	}
	return &StateMachine{
		cfg:           cfg,
		state:         map[string]string{},
		consec:        map[string]int{},
		consecRecover: map[string]int{},
	}
}

// Evaluate applies a window snapshot and returns the new health state and a
// failure reason (if the state is degraded/down/probe_error). now is the
// evaluation time (usually the probe time).
func (m *StateMachine) Evaluate(instanceID string, snap WindowSnapshot, lastReason string, now time.Time) (state string, reason string) {
	prev := m.state[instanceID]
	if prev == "" {
		prev = HealthStateUnknown
	}

	// probe_error is sticky: it's set by the scheduler when probes fail to
	// dispatch (permission/netns/interface missing). Recovery requires
	// consecutive successes.
	if lastReason != "" && (prev == HealthStateProbeError || snap.ConsecutiveFails >= m.cfg.FailThresholdConsecutive) {
		state, reason = HealthStateProbeError, lastReason
	} else if snap.ConsecutiveFails >= m.cfg.FailThresholdConsecutive || snap.LossRatio >= m.cfg.DownLossThreshold {
		if snap.LossRatio >= m.cfg.DownLossThreshold || snap.ConsecutiveFails >= m.cfg.FailThresholdConsecutive*2 {
			state, reason = HealthStateDown, classifyFailReason(lastReason, snap)
		} else {
			state, reason = HealthStateDegraded, classifyFailReason(lastReason, snap)
		}
	} else if snap.LossRatio >= m.cfg.LossThreshold {
		state, reason = HealthStateDegraded, classifyFailReason(lastReason, snap)
	} else if snap.Sent > 0 && snap.Lost == 0 {
		state, reason = HealthStateHealthy, ""
	} else {
		state, reason = HealthStateUnknown, ""
	}

	// Hysteresis for recovery.
	if (prev == HealthStateDegraded || prev == HealthStateDown || prev == HealthStateProbeError) && state == HealthStateHealthy {
		m.consecRecover[instanceID]++
		if m.consecRecover[instanceID] < m.cfg.RecoverConsecutive {
			// Stay degraded until stable recovery.
			state = prev
			reason = "recovering"
		} else {
			m.consecRecover[instanceID] = 0
		}
	} else {
		m.consecRecover[instanceID] = 0
	}

	// Hysteresis for degradation: only flip once thresholds crossed.
	if (prev == HealthStateHealthy || prev == HealthStateUnknown) && (state == HealthStateDegraded || state == HealthStateDown) {
		m.consec[instanceID]++
		if m.consec[instanceID] < m.cfg.FailThresholdConsecutive {
			state = prev
			reason = "hysteresis_pending"
		} else {
			m.consec[instanceID] = 0
		}
	} else {
		m.consec[instanceID] = 0
	}

	m.state[instanceID] = state
	return state, reason
}

// State returns the current health state for an instance.
func (m *StateMachine) State(instanceID string) string {
	s := m.state[instanceID]
	if s == "" {
		return HealthStateUnknown
	}
	return s
}

// SetProbeError marks an instance in probe_error due to dispatch failure.
func (m *StateMachine) SetProbeError(instanceID string, reason string) {
	m.state[instanceID] = HealthStateProbeError
}

// Reset clears state for an instance (used when link is removed).
func (m *StateMachine) Reset(instanceID string) {
	delete(m.state, instanceID)
	delete(m.consec, instanceID)
	delete(m.consecRecover, instanceID)
}

// classifyFailReason maps a raw error into a stable reason category.
func classifyFailReason(raw string, snap WindowSnapshot) string {
	switch {
	case contains(raw, "permission"):
		return "permission_denied"
	case contains(raw, "netns") || contains(raw, "interface") || contains(raw, "missing"):
		return "netns_interface_missing"
	case contains(raw, "address"):
		return "peer_address_missing"
	case contains(raw, "firewall"):
		return "firewall_denied"
	case raw == "" && snap.Sent > 0 && snap.Received == 0:
		return "probe_timeout"
	default:
		return "probe_failure"
	}
}

func contains(s, sub string) bool {
	if len(sub) == 0 {
		return false
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
