// Package testkit provides deterministic platform adapters for photonclient
// tests. These types never create operating-system network resources.
package testkit

import (
	"sync"
	"time"

	"github.com/HiggsNet/photon/internal/photonclient"
)

// ManualClock advances only when Advance is called.
type ManualClock struct {
	mu     sync.Mutex
	now    time.Time
	timers map[*manualTimer]struct{}
}

func NewManualClock(now time.Time) *ManualClock {
	return &ManualClock{now: now, timers: make(map[*manualTimer]struct{})}
}

func (c *ManualClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *ManualClock) NewTimer(after time.Duration) photonclient.Timer {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := &manualTimer{
		clock:  c,
		ch:     make(chan time.Time, 1),
		due:    c.now.Add(after),
		active: true,
	}
	c.timers[t] = struct{}{}
	c.fireDueLocked()
	return t
}

// Advance moves time forward and fires every timer due at or before the new
// instant. A negative duration panics because backward time hides timer bugs.
func (c *ManualClock) Advance(by time.Duration) {
	if by < 0 {
		panic("manual clock cannot move backwards")
	}
	c.mu.Lock()
	c.now = c.now.Add(by)
	c.fireDueLocked()
	c.mu.Unlock()
}

func (c *ManualClock) fireDueLocked() {
	for timer := range c.timers {
		if !timer.active || timer.due.After(c.now) {
			continue
		}
		timer.active = false
		select {
		case timer.ch <- c.now:
		default:
		}
	}
}

type manualTimer struct {
	clock  *ManualClock
	ch     chan time.Time
	due    time.Time
	active bool
}

func (t *manualTimer) C() <-chan time.Time { return t.ch }

func (t *manualTimer) Reset(after time.Duration) bool {
	t.clock.mu.Lock()
	defer t.clock.mu.Unlock()
	wasActive := t.active
	select {
	case <-t.ch:
	default:
	}
	t.due = t.clock.now.Add(after)
	t.active = true
	t.clock.fireDueLocked()
	return wasActive
}

func (t *manualTimer) Stop() bool {
	t.clock.mu.Lock()
	defer t.clock.mu.Unlock()
	wasActive := t.active
	t.active = false
	return wasActive
}
