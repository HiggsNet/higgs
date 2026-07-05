package main

import (
	"github.com/Catofes/higgs/internal/observer"
	"testing"
)

func TestSSEHubSubscribeBroadcast(t *testing.T) {
	hub := observer.NewHub()
	ch, unsubscribe := hub.Subscribe()
	defer unsubscribe()
	if hub.SubscriberCount() != 1 {
		t.Errorf("subscriber count = %d, want 1", hub.SubscriberCount())
	}
	event := observer.Event{Type: "test", Payload: map[string]any{"key": "value"}}
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
	hub := observer.NewHub()
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
	hub := observer.NewHub()
	hub.Broadcast(observer.Event{Type: "test"}) // should not panic
}
