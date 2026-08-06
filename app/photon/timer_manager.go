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

// TimerManager owns per-peer timers and posts timer events back to the event
// loop via the events channel. It never executes callbacks in the timer
// goroutine that mutate sync state.
type TimerManager struct {
	clock    Clock
	events   chan<- SyncEvent
	mu       sync.Mutex
	timers   map[timerKey]*managedTimer
	stopped  bool
	done     chan struct{}
	stopDone chan struct{}
	waiters  sync.WaitGroup
}

type timerKey struct {
	peerID string
	kind   string
}

type managedTimer struct {
	timer  Timer
	cancel chan struct{}
}

// NewTimerManager creates a timer manager. If clock is nil it uses the real
// system clock.
func NewTimerManager(clock Clock, events chan<- SyncEvent) *TimerManager {
	if clock == nil {
		clock = NewRealClock()
	}
	return &TimerManager{
		clock:    clock,
		events:   events,
		timers:   make(map[timerKey]*managedTimer),
		done:     make(chan struct{}),
		stopDone: make(chan struct{}),
	}
}

// Start arms a timer. It replaces any existing timer for (peerID, kind).
func (tm *TimerManager) Start(peerID, kind string, deadline time.Time) {
	tm.mu.Lock()
	if tm.stopped {
		tm.mu.Unlock()
		return
	}

	key := timerKey{peerID: peerID, kind: kind}
	if old, ok := tm.timers[key]; ok {
		old.timer.Stop()
		close(old.cancel)
	}

	d := max(deadline.Sub(tm.clock.Now()), 0)
	entry := &managedTimer{
		timer:  tm.clock.NewTimer(d),
		cancel: make(chan struct{}),
	}
	tm.timers[key] = entry
	tm.waiters.Add(1)
	tm.mu.Unlock()

	go tm.waitAndPost(key, entry, peerID, kind)
}

// Cancel stops the timer for (peerID, kind) if it exists.
func (tm *TimerManager) Cancel(peerID, kind string) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	if old, ok := tm.timers[timerKey{peerID: peerID, kind: kind}]; ok {
		old.timer.Stop()
		close(old.cancel)
		delete(tm.timers, timerKey{peerID: peerID, kind: kind})
	}
}

// CancelAll stops all timers for a peer.
func (tm *TimerManager) CancelAll(peerID string) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	for key, t := range tm.timers {
		if key.peerID == peerID {
			t.timer.Stop()
			close(t.cancel)
			delete(tm.timers, key)
		}
	}
}

// Stop cancels every timer and waits for all timer goroutines to exit. Start is
// a no-op after Stop begins. Stop is safe to call more than once.
func (tm *TimerManager) Stop() {
	tm.mu.Lock()
	if tm.stopped {
		stopDone := tm.stopDone
		tm.mu.Unlock()
		<-stopDone
		return
	}
	tm.stopped = true
	close(tm.done)
	for key, entry := range tm.timers {
		entry.timer.Stop()
		close(entry.cancel)
		delete(tm.timers, key)
	}
	tm.mu.Unlock()

	tm.waiters.Wait()
	close(tm.stopDone)
}

func (tm *TimerManager) waitAndPost(key timerKey, entry *managedTimer, peerID, kind string) {
	defer tm.waiters.Done()

	select {
	case <-entry.timer.C():
	case <-entry.cancel:
		return
	case <-tm.done:
		return
	}

	tm.mu.Lock()
	// A canceled or replaced timer must not post a stale timeout event.
	cur, ok := tm.timers[key]
	if !ok || cur != entry || tm.stopped {
		tm.mu.Unlock()
		return
	}
	delete(tm.timers, key)
	tm.mu.Unlock()

	var ev SyncEvent
	switch kind {
	case "round":
		ev = &RoundTimeoutEvent{PeerID: peerID}
	case "catalog_page":
		ev = &CatalogPageTimeoutEvent{PeerID: peerID}
	default:
		return
	}
	// Bound delivery and let manager shutdown interrupt a full event queue.
	select {
	case tm.events <- ev:
	case <-tm.done:
	case <-time.After(5 * time.Second):
		// Event loop may have stopped; drop.
	}
}
