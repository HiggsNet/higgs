package health

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

func TestRollingWindowBasic(t *testing.T) {
	w := NewRollingWindow(5)
	now := time.Now()
	w.Record(now, 10*time.Millisecond, true)
	w.Record(now, 0, false)
	w.Record(now, 20*time.Millisecond, true)
	snap := w.Snapshot()
	if snap.Sent != 3 {
		t.Fatalf("sent = %d, want 3", snap.Sent)
	}
	if snap.Received != 2 {
		t.Fatalf("received = %d, want 2", snap.Received)
	}
	if snap.Lost != 1 {
		t.Fatalf("lost = %d, want 1", snap.Lost)
	}
	if snap.LossRatio < 0.33 || snap.LossRatio > 0.34 {
		t.Fatalf("loss ratio = %f, want ~0.333", snap.LossRatio)
	}
	if snap.MaxRTT != 20*time.Millisecond {
		t.Fatalf("max rtt = %v, want 20ms", snap.MaxRTT)
	}
	if snap.MinRTT != 10*time.Millisecond {
		t.Fatalf("min rtt = %v, want 10ms", snap.MinRTT)
	}
}

func TestRollingWindowEvicts(t *testing.T) {
	w := NewRollingWindow(3)
	now := time.Now()
	// Fill with 3 samples.
	w.Record(now, 10*time.Millisecond, true)
	w.Record(now, 20*time.Millisecond, true)
	w.Record(now, 30*time.Millisecond, true)
	// Add a 4th; the oldest should be evicted.
	w.Record(now, 40*time.Millisecond, true)
	snap := w.Snapshot()
	if snap.Sent != 3 {
		t.Fatalf("sent = %d, want 3 after eviction", snap.Sent)
	}
	if snap.MinRTT != 20*time.Millisecond {
		t.Fatalf("min rtt = %v, want 20ms (oldest evicted)", snap.MinRTT)
	}
	if snap.MaxRTT != 40*time.Millisecond {
		t.Fatalf("max rtt = %v, want 40ms", snap.MaxRTT)
	}
}

func TestRollingWindowJitter(t *testing.T) {
	w := NewRollingWindow(10)
	now := time.Now()
	w.Record(now, 10*time.Millisecond, true)
	w.Record(now, 20*time.Millisecond, true)
	w.Record(now, 15*time.Millisecond, true)
	snap := w.Snapshot()
	// Jitter is mean abs deviation of consecutive samples: |20-10| + |15-20| = 15ms / 2 = 7.5ms
	if snap.Jitter <= 0 {
		t.Fatalf("jitter = %v, want > 0", snap.Jitter)
	}
}

func TestStateMachineHealthyToDegraded(t *testing.T) {
	cfg := HysteresisConfig{
		FailThresholdConsecutive: 3,
		LossThreshold:            0.2,
		DownLossThreshold:        0.6,
		RecoverConsecutive:       2,
	}
	m := NewStateMachine(cfg)
	now := time.Now()
	// Start healthy.
	for i := 0; i < 5; i++ {
		m.Evaluate("link1", WindowSnapshot{Sent: 5, Received: 5, Lost: 0}, "", now)
	}
	if state := m.State("link1"); state != HealthStateHealthy {
		t.Fatalf("state = %s, want healthy", state)
	}
	// Inject consecutive failures.
	for i := 0; i < 3; i++ {
		m.Evaluate("link1", WindowSnapshot{Sent: 5, Received: 0, Lost: 5, LossRatio: 1.0, ConsecutiveFails: i + 1}, "", now)
	}
	if state := m.State("link1"); state != HealthStateDown {
		t.Fatalf("state = %s, want down after consecutive failures", state)
	}
}

func TestStateMachineHysteresisRecovery(t *testing.T) {
	cfg := HysteresisConfig{
		FailThresholdConsecutive: 2,
		LossThreshold:            0.2,
		DownLossThreshold:        0.6,
		RecoverConsecutive:       3,
	}
	m := NewStateMachine(cfg)
	now := time.Now()
	// Force into degraded state.
	for i := 0; i < 3; i++ {
		m.Evaluate("link1", WindowSnapshot{Sent: 5, Received: 0, Lost: 5, LossRatio: 1.0, ConsecutiveFails: i + 1}, "", now)
	}
	if state := m.State("link1"); state != HealthStateDown {
		t.Fatalf("state = %s, want down", state)
	}
	// One success should not immediately recover (hysteresis).
	m.Evaluate("link1", WindowSnapshot{Sent: 1, Received: 1, Lost: 0}, "", now)
	if state := m.State("link1"); state == HealthStateHealthy {
		t.Fatalf("state = %s, should not be healthy after single success (hysteresis)", state)
	}
	// After enough consecutive successes, recover.
	for i := 0; i < 4; i++ {
		m.Evaluate("link1", WindowSnapshot{Sent: 1, Received: 1, Lost: 0}, "", now)
	}
	if state := m.State("link1"); state != HealthStateHealthy {
		t.Fatalf("state = %s, want healthy after recovery window", state)
	}
}

func TestManagerTickAndSnapshot(t *testing.T) {
	cfg := ProbeConfig{Interval: time.Second, Timeout: 100 * time.Millisecond, Burst: 1, LossWindow: 5, MaxConcurrent: 2}
	hyst := DefaultHysteresisConfig()
	prober := &fakeProber{rtt: 5 * time.Millisecond, success: true}
	m := NewManager(cfg, hyst, prober)
	now := time.Now()
	target := ProbeTarget{
		InstanceID:     "link1",
		PeerZone:       "peer.",
		Overlay:        "group1",
		InterfaceName:  "hgs1",
		PeerTunnelAddr: netip.MustParseAddr("10.0.0.2"),
		State:          "up",
	}
	m.UpsertTarget(target, now)
	// Force a probe by setting nextProbe to the past.
	m.mu.Lock()
	m.nextProbe["link1"] = now.Add(-time.Second)
	m.mu.Unlock()
	dispatched := m.Tick(context.Background(), now)
	if dispatched != 1 {
		t.Fatalf("dispatched = %d, want 1", dispatched)
	}
	snapshot := m.Snapshot(now)
	if len(snapshot) != 1 {
		t.Fatalf("snapshot len = %d, want 1", len(snapshot))
	}
	if snapshot[0].Sent != 1 {
		t.Fatalf("sent = %d, want 1", snapshot[0].Sent)
	}
	if snapshot[0].Received != 1 {
		t.Fatalf("received = %d, want 1", snapshot[0].Received)
	}
}

func TestManagerRotateCutoverReadiness(t *testing.T) {
	cfg := ProbeConfig{Interval: time.Second, Timeout: 100 * time.Millisecond, Burst: 1, LossWindow: 5, MaxConcurrent: 2}
	hyst := DefaultHysteresisConfig()
	prober := &fakeProber{rtt: 5 * time.Millisecond, success: true}
	m := NewManager(cfg, hyst, prober)
	now := time.Now()
	// A staged link should be tracked for cutover readiness.
	target := ProbeTarget{
		InstanceID:     "staged-link",
		PeerZone:       "peer.",
		Overlay:        "group1",
		InterfaceName:  "hgs2",
		PeerTunnelAddr: netip.MustParseAddr("10.0.0.3"),
		State:          "staged",
		Staged:         true,
	}
	m.UpsertTarget(target, now)
	m.mu.Lock()
	m.nextProbe["staged-link"] = now.Add(-time.Second)
	m.mu.Unlock()
	m.Tick(context.Background(), now)
	// After a successful probe, cutover should not be blocking for staged.
	readiness := m.RotateCutoverReadiness()
	ready, ok := readiness["staged-link"]
	if !ok {
		t.Fatalf("staged link not in readiness map")
	}
	if !ready {
		t.Fatalf("staged link cutover should be ready after successful probe")
	}
}

func TestManagerRemoveTarget(t *testing.T) {
	cfg := DefaultProbeConfig()
	hyst := DefaultHysteresisConfig()
	m := NewManager(cfg, hyst, nil)
	now := time.Now()
	target := ProbeTarget{
		InstanceID:     "link1",
		PeerZone:       "peer.",
		Overlay:        "group1",
		InterfaceName:  "hgs1",
		PeerTunnelAddr: netip.MustParseAddr("10.0.0.2"),
		State:          "up",
	}
	m.UpsertTarget(target, now)
	m.RemoveTarget("link1")
	snapshot := m.Snapshot(now)
	if len(snapshot) != 0 {
		t.Fatalf("snapshot len = %d, want 0 after remove", len(snapshot))
	}
}

func TestProbeTargetShouldProbe(t *testing.T) {
	tests := []struct {
		state string
		want  bool
	}{
		{"up", true},
		{"connecting", true},
		{"degraded", true},
		{"staged", true},
		{"removing", false},
		{"down", false},
		{"", false},
	}
	for _, tt := range tests {
		target := ProbeTarget{State: tt.state}
		if got := target.ShouldProbe(); got != tt.want {
			t.Errorf("ShouldProbe(state=%q) = %v, want %v", tt.state, got, tt.want)
		}
	}
}

func TestCollectMetricsAndRender(t *testing.T) {
	healths := []LinkHealth{
		{
			InstanceID: "link1",
			State:      HealthStateHealthy,
			ProbeType:  ProbeTypeICMP,
			Sent:       10,
			Received:   9,
			Lost:       1,
			LossRatio:  0.1,
			LastRTT:    5 * time.Millisecond,
			Jitter:     1 * time.Millisecond,
			Labels:     MetricsLabels{LocalZone: "a.", PeerZone: "b.", Overlay: "g1", InstanceID: "link1", ProbeType: "icmp"},
		},
	}
	snap := CollectMetrics(healths, time.Now())
	if len(snap.Samples) == 0 {
		t.Fatalf("no metric samples collected")
	}
	// Verify rendering doesn't panic.
	var buf stringBuilder
	RenderOpenMetrics(&buf, snap, map[string]int{"link1": 2})
	output := buf.String()
	if output == "" {
		t.Fatalf("rendered output is empty")
	}
	if !contains(output, "higgs_link_probe_rtt_seconds") {
		t.Fatalf("output missing rtt metric:\n%s", output)
	}
	if !contains(output, "higgs_link_health_state") {
		t.Fatalf("output missing health state metric:\n%s", output)
	}
}

type fakeProber struct {
	rtt     time.Duration
	success bool
}

func (p *fakeProber) Probe(ctx context.Context, target ProbeTarget, cfg ProbeConfig) ProbeResult {
	return ProbeResult{InstanceID: target.InstanceID, RTT: p.rtt, Success: p.success}
}

func (p *fakeProber) Type() string { return ProbeTypeICMP }

type stringBuilder struct {
	data []byte
}

func (s *stringBuilder) Write(p []byte) (int, error) {
	s.data = append(s.data, p...)
	return len(p), nil
}

func (s *stringBuilder) String() string {
	return string(s.data)
}
