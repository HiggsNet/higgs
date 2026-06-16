package main

import (
	"sync"
	"time"
)

// Clock abstracts time for testability. The real implementation uses the
// standard time package; tests can use fakeClock to advance time deterministically.
type Clock interface {
	Now() time.Time
	NewTimer(d time.Duration) Timer
}

// Timer is the subset of *time.Timer used by TimerManager.
type Timer interface {
	C() <-chan time.Time
	Stop() bool
	Reset(d time.Duration) bool
}

// realClock is the production clock backed by time.Now and time.NewTimer.
type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

func (realClock) NewTimer(d time.Duration) Timer {
	return &realTimer{Timer: time.NewTimer(d)}
}

type realTimer struct{ *time.Timer }

func (t *realTimer) C() <-chan time.Time { return t.Timer.C }
func (t *realTimer) Stop() bool          { return t.Timer.Stop() }
func (t *realTimer) Reset(d time.Duration) bool {
	return t.Timer.Reset(d)
}

// NewRealClock returns a Clock backed by the system clock.
func NewRealClock() Clock { return realClock{} }

// fakeClock is a deterministic clock for tests. Advance time to fire timers.
type fakeClock struct {
	mu     sync.Mutex
	now    time.Time
	timers []*fakeTimer
}

// newFakeClock creates a fake clock starting at now.
func newFakeClock(now time.Time) *fakeClock {
	return &fakeClock{now: now}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) NewTimer(d time.Duration) Timer {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := &fakeTimer{
		clock: c,
		when:  c.now.Add(d),
		c:     make(chan time.Time, 1),
	}
	c.timers = append(c.timers, t)
	return t
}

// Advance moves the clock forward by d and fires any timers whose deadline has
// been reached. It must be called from the test goroutine.
func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	var fired []*fakeTimer
	var remaining []*fakeTimer
	for _, t := range c.timers {
		if !t.when.After(c.now) && !t.stopped {
			fired = append(fired, t)
		} else {
			remaining = append(remaining, t)
		}
	}
	c.timers = remaining
	c.mu.Unlock()

	for _, t := range fired {
		select {
		case t.c <- c.now:
		default:
		}
	}
}

type fakeTimer struct {
	clock   *fakeClock
	when    time.Time
	c       chan time.Time
	stopped bool
}

func (t *fakeTimer) C() <-chan time.Time { return t.c }

func (t *fakeTimer) Stop() bool {
	t.clock.mu.Lock()
	defer t.clock.mu.Unlock()
	if t.stopped {
		return false
	}
	t.stopped = true
	return true
}

func (t *fakeTimer) Reset(d time.Duration) bool {
	t.clock.mu.Lock()
	defer t.clock.mu.Unlock()
	wasActive := !t.stopped
	t.stopped = false
	t.when = t.clock.now.Add(d)
	return wasActive
}

// TimerManager owns per-peer timers and posts timer events back to the event
// loop via the events channel. It never executes callbacks in the timer
// goroutine that mutate sync state.
type TimerManager struct {
	clock  Clock
	events chan<- SyncEvent
	mu     sync.Mutex
	timers map[timerKey]Timer
}

type timerKey struct {
	peerID string
	kind   string
}

// NewTimerManager creates a timer manager. If clock is nil it uses the real
// system clock.
func NewTimerManager(clock Clock, events chan<- SyncEvent) *TimerManager {
	if clock == nil {
		clock = NewRealClock()
	}
	return &TimerManager{
		clock:  clock,
		events: events,
		timers: make(map[timerKey]Timer),
	}
}

// Start arms a timer. It replaces any existing timer for (peerID, kind).
func (tm *TimerManager) Start(peerID, kind string, deadline time.Time) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	key := timerKey{peerID: peerID, kind: kind}
	if old, ok := tm.timers[key]; ok {
		old.Stop()
	}

	d := deadline.Sub(tm.clock.Now())
	if d < 0 {
		d = 0
	}
	timer := tm.clock.NewTimer(d)
	tm.timers[key] = timer

	go tm.waitAndPost(key, timer, peerID, kind)
}

// Cancel stops the timer for (peerID, kind) if it exists.
func (tm *TimerManager) Cancel(peerID, kind string) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	if old, ok := tm.timers[timerKey{peerID: peerID, kind: kind}]; ok {
		old.Stop()
		delete(tm.timers, timerKey{peerID: peerID, kind: kind})
	}
}

// CancelAll stops all timers for a peer.
func (tm *TimerManager) CancelAll(peerID string) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	for key, t := range tm.timers {
		if key.peerID == peerID {
			t.Stop()
			delete(tm.timers, key)
		}
	}
}

func (tm *TimerManager) waitAndPost(key timerKey, timer Timer, peerID, kind string) {
	firedAt := <-timer.C()
	tm.mu.Lock()
	// Only post if this timer is still the current one for the key.
	if cur, ok := tm.timers[key]; ok && cur == timer {
		delete(tm.timers, key)
	}
	tm.mu.Unlock()

	var ev SyncEvent
	switch kind {
	case "round":
		ev = &RoundTimeoutEvent{PeerID: peerID}
	case "packet_quiet":
		ev = &PacketQuietTimeoutEvent{PeerID: peerID}
	default:
		return
	}
	// Use non-blocking send so a stale timer cannot block shutdown.
	select {
	case tm.events <- ev:
	case <-time.After(5 * time.Second):
		// Event loop may have stopped; drop.
		_ = firedAt
	}

}
