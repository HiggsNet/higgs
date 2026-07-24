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
}
