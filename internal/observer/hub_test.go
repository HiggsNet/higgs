package observer

import (
	"testing"
	"time"
)

func TestSSEHubSubscribeBroadcast(t *testing.T) {
	hub := NewHub()
	ch, unsubscribe := hub.Subscribe()
	defer unsubscribe()
	if hub.SubscriberCount() != 1 {
		t.Errorf("subscriber count = %d, want 1", hub.SubscriberCount())
	}
	event := Event{Type: "test", Payload: map[string]any{"key": "value"}}
	hub.Broadcast(event)
	select {
	case received := <-ch:
		if received.Type != "test" {
			t.Errorf("received type = %q, want test", received.Type)
		}
	default:
		t.Error("event not received")
	}
}

func TestSSEHubUnsubscribe(t *testing.T) {
	hub := NewHub()
	_, unsubscribe := hub.Subscribe()
	if hub.SubscriberCount() != 1 {
		t.Errorf("count = %d, want 1", hub.SubscriberCount())
	}
	unsubscribe()
	if hub.SubscriberCount() != 0 {
		t.Errorf("count after unsubscribe = %d, want 0", hub.SubscriberCount())
	}
}

func TestSSEHubBroadcastNoSubscribers(t *testing.T) {
	hub := NewHub()
	hub.Broadcast(Event{Type: "test"})
}

func TestSSEHubBroadcastFillsTimestamp(t *testing.T) {
	hub := NewHub()
	ch, unsubscribe := hub.Subscribe()
	defer unsubscribe()
	hub.Broadcast(Event{Type: "auto"})
	received := <-ch
	if received.Time == 0 {
		t.Error("Broadcast should fill the event timestamp")
	}
	hub.Broadcast(Event{Type: "preset", Time: 1234})
	received = <-ch
	if received.Time != 1234 {
		t.Errorf("caller-set timestamp = %d, want 1234 (preserved)", received.Time)
	}
}

func TestSSEHubBufferDisabledByDefault(t *testing.T) {
	hub := NewHub()
	hub.Broadcast(Event{Type: "test"})
	if got := hub.Recent(); got == nil || len(got) != 0 {
		t.Errorf("Recent() = %v, want empty non-nil slice with buffer disabled", got)
	}
}

func TestSSEHubBufferPrunesByTimeWindow(t *testing.T) {
	hub := NewHubWithBuffer(60)
	current := time.Unix(1000, 0)
	hub.now = func() time.Time { return current }
	hub.Broadcast(Event{Type: "old"})
	current = current.Add(30 * time.Second)
	hub.Broadcast(Event{Type: "kept"})
	current = current.Add(31 * time.Second) // now-1000 = 61s > 60s window
	hub.Broadcast(Event{Type: "new"})
	recent := hub.Recent()
	if len(recent) != 2 {
		t.Fatalf("Recent() len = %d, want 2 (oldest pruned)", len(recent))
	}
	if recent[0].Type != "kept" || recent[1].Type != "new" {
		t.Errorf("Recent() types = %q,%q, want kept,new", recent[0].Type, recent[1].Type)
	}
}

func TestSSEHubBufferHardCap(t *testing.T) {
	hub := NewHubWithBuffer(3600)
	for i := 0; i < maxBufferedEvents+10; i++ {
		hub.Broadcast(Event{Type: "flood"})
	}
	if got := len(hub.Recent()); got != maxBufferedEvents {
		t.Errorf("Recent() len = %d, want cap %d", got, maxBufferedEvents)
	}
}

func TestSSEHubRecentOrderAndCopySemantics(t *testing.T) {
	hub := NewHubWithBuffer(60)
	current := time.Unix(1000, 0)
	hub.now = func() time.Time { return current }
	hub.Broadcast(Event{Type: "first"})
	current = current.Add(time.Second)
	hub.Broadcast(Event{Type: "second"})
	recent := hub.Recent()
	if len(recent) != 2 || recent[0].Type != "first" || recent[1].Type != "second" {
		t.Fatalf("Recent() = %+v, want ascending time order", recent)
	}
	recent[0].Type = "mutated"
	if again := hub.Recent(); again[0].Type != "first" {
		t.Errorf("Recent() must return a copy; internal buffer was mutated to %q", again[0].Type)
	}
}
