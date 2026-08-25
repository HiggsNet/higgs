package gossip

import (
	"sync"
	"time"
)

const (
	TimerKindRound       = "round"
	TimerKindCatalogPage = "catalog_page"
)

// EventTimer is the subset of a timer needed by gossip event scheduling.
type EventTimer interface {
	C() <-chan time.Time
	Stop() bool
	Reset(time.Duration) bool
}

// TimerClock makes gossip deadlines deterministic in tests and portable
// runtimes.
type TimerClock interface {
	Now() time.Time
	NewTimer(time.Duration) EventTimer
}

type systemTimerClock struct {
	now func() time.Time
}

// NewTimerClock returns a clock backed by standard timers. If now is nil it
// uses time.Now.
func NewTimerClock(now func() time.Time) TimerClock {
	if now == nil {
		now = time.Now
	}
	return &systemTimerClock{now: now}
}

func (clock *systemTimerClock) Now() time.Time { return clock.now() }

func (*systemTimerClock) NewTimer(after time.Duration) EventTimer {
	return &systemEventTimer{Timer: time.NewTimer(after)}
}

type systemEventTimer struct{ *time.Timer }

func (timer *systemEventTimer) C() <-chan time.Time { return timer.Timer.C }

// TimerManager owns per-peer timers and posts timeout events to one bounded
// event queue. It never mutates a SyncSession from timer goroutines.
type TimerManager struct {
	clock    TimerClock
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
	timer  EventTimer
	cancel chan struct{}
}

func NewTimerManager(clock TimerClock, events chan<- SyncEvent) *TimerManager {
	if clock == nil {
		clock = NewTimerClock(nil)
	}
	return &TimerManager{
		clock:    clock,
		events:   events,
		timers:   make(map[timerKey]*managedTimer),
		done:     make(chan struct{}),
		stopDone: make(chan struct{}),
	}
}

func (manager *TimerManager) Start(peerID, kind string, deadline time.Time) {
	manager.mu.Lock()
	if manager.stopped {
		manager.mu.Unlock()
		return
	}
	key := timerKey{peerID: peerID, kind: kind}
	if old, ok := manager.timers[key]; ok {
		old.timer.Stop()
		close(old.cancel)
	}
	entry := &managedTimer{
		timer:  manager.clock.NewTimer(max(deadline.Sub(manager.clock.Now()), 0)),
		cancel: make(chan struct{}),
	}
	manager.timers[key] = entry
	manager.waiters.Add(1)
	manager.mu.Unlock()
	go manager.waitAndPost(key, entry)
}

func (manager *TimerManager) Cancel(peerID, kind string) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	key := timerKey{peerID: peerID, kind: kind}
	if old, ok := manager.timers[key]; ok {
		old.timer.Stop()
		close(old.cancel)
		delete(manager.timers, key)
	}
}

func (manager *TimerManager) CancelAll(peerID string) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	for key, timer := range manager.timers {
		if key.peerID == peerID {
			timer.timer.Stop()
			close(timer.cancel)
			delete(manager.timers, key)
		}
	}
}

// Stop cancels all timers and waits for timer goroutines. It is idempotent.
func (manager *TimerManager) Stop() {
	manager.mu.Lock()
	if manager.stopped {
		stopDone := manager.stopDone
		manager.mu.Unlock()
		<-stopDone
		return
	}
	manager.stopped = true
	close(manager.done)
	for key, entry := range manager.timers {
		entry.timer.Stop()
		close(entry.cancel)
		delete(manager.timers, key)
	}
	manager.mu.Unlock()
	manager.waiters.Wait()
	close(manager.stopDone)
}

func (manager *TimerManager) waitAndPost(key timerKey, entry *managedTimer) {
	defer manager.waiters.Done()
	select {
	case <-entry.timer.C():
	case <-entry.cancel:
		return
	case <-manager.done:
		return
	}

	manager.mu.Lock()
	current, ok := manager.timers[key]
	if !ok || current != entry || manager.stopped {
		manager.mu.Unlock()
		return
	}
	delete(manager.timers, key)
	manager.mu.Unlock()

	var event SyncEvent
	switch key.kind {
	case TimerKindRound:
		event = &RoundTimeoutEvent{PeerID: key.peerID}
	case TimerKindCatalogPage:
		event = &CatalogPageTimeoutEvent{PeerID: key.peerID}
	default:
		return
	}
	select {
	case manager.events <- event:
	case <-manager.done:
	case <-time.After(5 * time.Second):
	}
}
