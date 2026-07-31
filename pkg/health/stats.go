package health

import (
	"slices"
	"sync"
	"time"
)

// ewmaAlpha is the smoothing factor for EWMA RTT computation.
const ewmaAlpha = 0.3

// sample is a single probe result stored in the rolling window.
type sample struct {
	at      time.Time
	rtt     time.Duration
	success bool
}

// RollingWindow keeps a bounded ring buffer of probe results and computes
// derived statistics (loss ratio, RTT percentiles, jitter, EWMA).
type RollingWindow struct {
	mu      sync.Mutex
	samples []sample
	head    int
	count   int
	cap     int
	ewma    time.Duration
	consec  int // consecutive failures
	lastOK  time.Time
}

// NewRollingWindow returns a rolling window with the given capacity.
func NewRollingWindow(capacity int) *RollingWindow {
	if capacity < 1 {
		capacity = 1
	}
	return &RollingWindow{
		samples: make([]sample, capacity),
		cap:     capacity,
	}
}

// Record inserts a probe result into the window.
func (w *RollingWindow) Record(at time.Time, rtt time.Duration, success bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.samples[w.head] = sample{at: at, rtt: rtt, success: success}
	w.head = (w.head + 1) % w.cap
	if w.count < w.cap {
		w.count++
	}
	if success {
		w.consec = 0
		w.lastOK = at
		if rtt > 0 {
			if w.ewma == 0 {
				w.ewma = rtt
			} else {
				w.ewma = time.Duration(float64(w.ewma)*(1-ewmaAlpha) + float64(rtt)*ewmaAlpha)
			}
		}
	} else {
		w.consec++
	}
}

// Snapshot computes the current aggregate statistics.
func (w *RollingWindow) Snapshot() WindowSnapshot {
	w.mu.Lock()
	defer w.mu.Unlock()
	snap := WindowSnapshot{
		Sent:             w.count,
		ConsecutiveFails: w.consec,
		EWMARTT:          w.ewma,
		LastSuccess:      w.lastOK,
	}
	if w.count == 0 {
		return snap
	}
	rtts := make([]time.Duration, 0, w.count)
	idx := (w.head - w.count + w.cap) % w.cap
	for i := 0; i < w.count; i++ {
		s := w.samples[(idx+i)%w.cap]
		if s.success {
			snap.Received++
			if i == w.count-1 || snap.LastRTT == 0 {
				snap.LastRTT = s.rtt
			}
			rtts = append(rtts, s.rtt)
		} else {
			snap.Lost++
		}
	}
	// LastRTT should be the most recent sample's RTT (success or not).
	last := w.samples[(w.head-1+w.cap)%w.cap]
	if last.success {
		snap.LastRTT = last.rtt
	} else {
		snap.LastRTT = 0
	}
	snap.LossRatio = float64(snap.Lost) / float64(snap.Sent)
	if len(rtts) > 0 {
		slices.Sort(rtts)
		snap.MinRTT = rtts[0]
		snap.MaxRTT = rtts[len(rtts)-1]
		snap.P50RTT = percentile(rtts, 50)
		snap.P95RTT = percentile(rtts, 95)
		snap.P99RTT = percentile(rtts, 99)
		snap.Jitter = computeJitter(rtts)
	}
	return snap
}

// WindowSnapshot is the aggregate view of a RollingWindow.
type WindowSnapshot struct {
	Sent             int
	Received         int
	Lost             int
	LossRatio        float64
	LastRTT          time.Duration
	EWMARTT          time.Duration
	MinRTT           time.Duration
	MaxRTT           time.Duration
	P50RTT           time.Duration
	P95RTT           time.Duration
	P99RTT           time.Duration
	Jitter           time.Duration
	ConsecutiveFails int
	LastSuccess      time.Time
}

// Reset clears the window.
func (w *RollingWindow) Reset() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.head = 0
	w.count = 0
	w.ewma = 0
	w.consec = 0
	w.lastOK = time.Time{}
}

func percentile(sorted []time.Duration, pct int) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	idx := (len(sorted) - 1) * pct / 100
	return sorted[idx]
}

func computeJitter(sorted []time.Duration) time.Duration {
	if len(sorted) < 2 {
		return 0
	}
	// Mean absolute deviation of consecutive RTT samples.
	var sum time.Duration
	prev := sorted[0]
	for i := 1; i < len(sorted); i++ {
		d := sorted[i] - prev
		if d < 0 {
			d = -d
		}
		sum += d
		prev = sorted[i]
	}
	return sum / time.Duration(len(sorted)-1)
}
