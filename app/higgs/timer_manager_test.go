package main

import (
	"sync"
	"testing"
	"time"
)

type fakeClock struct {
	mu     sync.Mutex
	now    time.Time
	timers []*fakeTimer
}

func newFakeClock(now time.Time) *fakeClock { return &fakeClock{now: now} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) NewTimer(d time.Duration) Timer {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := &fakeTimer{clock: c, when: c.now.Add(d), c: make(chan time.Time, 1)}
	c.timers = append(c.timers, t)
	return t
}

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

type channelTimer struct {
	c chan time.Time
}

func newChannelTimer() *channelTimer {
	return &channelTimer{c: make(chan time.Time, 1)}
}

func (t *channelTimer) C() <-chan time.Time      { return t.c }
func (t *channelTimer) Stop() bool               { return false }
func (t *channelTimer) Reset(time.Duration) bool { return false }

func requireTimerManagerStops(t *testing.T, tm *TimerManager) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		tm.Stop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("TimerManager.Stop did not wait for timer goroutines to exit")
	}
}

func TestTimerManagerPostsRoundTimeout(t *testing.T) {
	clock := newFakeClock(time.Unix(1000, 0))
	events := make(chan SyncEvent, 1)
	tm := NewTimerManager(clock, events)

	tm.Start("peer-a", "round", clock.Now().Add(5*time.Second))
	clock.Advance(5 * time.Second)

	select {
	case ev := <-events:
		rt, ok := ev.(*RoundTimeoutEvent)
		if !ok {
			t.Fatalf("expected RoundTimeoutEvent, got %T", ev)
		}
		if rt.PeerID != "peer-a" {
			t.Fatalf("unexpected peer id: %s", rt.PeerID)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for round timeout event")
	}
	requireTimerManagerStops(t, tm)
}

func TestTimerManagerPostsCatalogPageTimeout(t *testing.T) {
	clock := newFakeClock(time.Unix(1000, 0))
	events := make(chan SyncEvent, 1)
	tm := NewTimerManager(clock, events)

	tm.Start("peer-a", "catalog_page", clock.Now().Add(250*time.Millisecond))
	clock.Advance(250 * time.Millisecond)

	select {
	case ev := <-events:
		qt, ok := ev.(*CatalogPageTimeoutEvent)
		if !ok {
			t.Fatalf("expected CatalogPageTimeoutEvent, got %T", ev)
		}
		if qt.PeerID != "peer-a" {
			t.Fatalf("unexpected peer id: %s", qt.PeerID)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for catalog page timeout event")
	}
	requireTimerManagerStops(t, tm)
}

func TestTimerManagerCancelPreventsEvent(t *testing.T) {
	clock := newFakeClock(time.Unix(1000, 0))
	events := make(chan SyncEvent, 1)
	tm := NewTimerManager(clock, events)

	tm.Start("peer-a", "round", clock.Now().Add(5*time.Second))
	tm.Cancel("peer-a", "round")
	clock.Advance(5 * time.Second)

	select {
	case ev := <-events:
		t.Fatalf("expected no event after cancel, got %T", ev)
	case <-time.After(50 * time.Millisecond):
	}
	requireTimerManagerStops(t, tm)
}

func TestTimerManagerStartReplacesExistingTimer(t *testing.T) {
	clock := newFakeClock(time.Unix(1000, 0))
	events := make(chan SyncEvent, 1)
	tm := NewTimerManager(clock, events)

	tm.Start("peer-a", "round", clock.Now().Add(10*time.Second))
	tm.Start("peer-a", "round", clock.Now().Add(2*time.Second))
	clock.Advance(2 * time.Second)

	select {
	case <-events:
		// ok
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for replaced timer")
	}

	clock.Advance(10 * time.Second)
	select {
	case ev := <-events:
		t.Fatalf("old timer should not fire, got %T", ev)
	case <-time.After(50 * time.Millisecond):
	}
	requireTimerManagerStops(t, tm)
}

func TestTimerManagerCancelAllForPeer(t *testing.T) {
	clock := newFakeClock(time.Unix(1000, 0))
	events := make(chan SyncEvent, 1)
	tm := NewTimerManager(clock, events)

	tm.Start("peer-a", "round", clock.Now().Add(5*time.Second))
	tm.Start("peer-a", "catalog_page", clock.Now().Add(250*time.Millisecond))
	tm.CancelAll("peer-a")
	clock.Advance(10 * time.Second)

	select {
	case ev := <-events:
		t.Fatalf("expected no events after CancelAll, got %T", ev)
	case <-time.After(50 * time.Millisecond):
	}
	requireTimerManagerStops(t, tm)
}

func TestTimerManagerStopCancelsAllWaiters(t *testing.T) {
	clock := newFakeClock(time.Unix(1000, 0))
	events := make(chan SyncEvent, 2)
	tm := NewTimerManager(clock, events)

	tm.Start("peer-a", "round", clock.Now().Add(time.Hour))
	tm.Start("peer-b", "catalog_page", clock.Now().Add(time.Hour))
	requireTimerManagerStops(t, tm)

	clock.Advance(2 * time.Hour)
	select {
	case ev := <-events:
		t.Fatalf("expected no event after Stop, got %T", ev)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestTimerManagerStaleFiredTimerDoesNotPost(t *testing.T) {
	clock := newFakeClock(time.Unix(1000, 0))
	events := make(chan SyncEvent, 1)
	tm := NewTimerManager(clock, events)
	key := timerKey{peerID: "peer-a", kind: "round"}
	staleTimer := newChannelTimer()
	stale := &managedTimer{timer: staleTimer, cancel: make(chan struct{})}
	current := &managedTimer{timer: newChannelTimer(), cancel: make(chan struct{})}

	tm.mu.Lock()
	tm.timers[key] = current
	tm.waiters.Add(1)
	tm.mu.Unlock()
	staleTimer.c <- clock.Now()
	go tm.waitAndPost(key, stale, key.peerID, key.kind)

	select {
	case ev := <-events:
		t.Fatalf("stale timer posted event %T", ev)
	case <-time.After(50 * time.Millisecond):
	}
	requireTimerManagerStops(t, tm)
}

func TestTimerManagerStopIsIdempotent(t *testing.T) {
	tm := NewTimerManager(newFakeClock(time.Unix(1000, 0)), make(chan SyncEvent, 1))
	requireTimerManagerStops(t, tm)
	requireTimerManagerStops(t, tm)
}

func TestTimerManagerRepeatedCancelDoesNotRetainWaiters(t *testing.T) {
	clock := newFakeClock(time.Unix(1000, 0))
	tm := NewTimerManager(clock, make(chan SyncEvent, 1))

	for i := 0; i < 2500; i++ {
		tm.Start("peer-a", "round", clock.Now().Add(time.Hour))
		tm.Cancel("peer-a", "round")
	}
	requireTimerManagerStops(t, tm)
}
