package main

import (
	"testing"
	"time"
)

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

func TestTimerManagerPostsPacketQuietTimeout(t *testing.T) {
	clock := newFakeClock(time.Unix(1000, 0))
	events := make(chan SyncEvent, 1)
	tm := NewTimerManager(clock, events)

	tm.Start("peer-a", "packet_quiet", clock.Now().Add(250*time.Millisecond))
	clock.Advance(250 * time.Millisecond)

	select {
	case ev := <-events:
		qt, ok := ev.(*PacketQuietTimeoutEvent)
		if !ok {
			t.Fatalf("expected PacketQuietTimeoutEvent, got %T", ev)
		}
		if qt.PeerID != "peer-a" {
			t.Fatalf("unexpected peer id: %s", qt.PeerID)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for packet quiet timeout event")
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
	tm.Start("peer-a", "packet_quiet", clock.Now().Add(250*time.Millisecond))
	tm.CancelAll("peer-a")
	clock.Advance(10 * time.Second)

	select {
	case ev := <-events:
		t.Fatalf("expected no events after CancelAll, got %T", ev)
	case <-time.After(50 * time.Millisecond):
	}
}
