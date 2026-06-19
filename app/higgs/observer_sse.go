package main

import (
	"sync"
)

// sseEvent is a lightweight notification pushed to SSE subscribers. It only
// carries the event type and a small payload; detail data is fetched by the
// client via the REST snapshot APIs after receiving the notification.
type sseEvent struct {
	Type    string `json:"type"`
	Payload any    `json:"payload,omitempty"`
}

// sseHub maintains a set of SSE subscriber channels and broadcasts lightweight
// events to all of them. Slow clients that cannot keep up have their events
// dropped (non-blocking send), and the frontend falls back to polling.
type sseHub struct {
	mu          sync.Mutex
	subscribers map[chan sseEvent]struct{}
}

func newSSEHub() *sseHub {
	return &sseHub{
		subscribers: make(map[chan sseEvent]struct{}),
	}
}

// subscribe registers a new subscriber and returns its event channel.
// The caller must call the returned unsubscribe function when done.
func (h *sseHub) subscribe() (<-chan sseEvent, func()) {
	ch := make(chan sseEvent, 16)
	h.mu.Lock()
	h.subscribers[ch] = struct{}{}
	h.mu.Unlock()
	return ch, func() {
		h.mu.Lock()
		delete(h.subscribers, ch)
		close(ch)
		h.mu.Unlock()
	}
}

// broadcast sends an event to all subscribers. Non-blocking: subscribers with
// full queues are skipped (their frontends must poll to recover).
func (h *sseHub) broadcast(event sseEvent) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subscribers {
		select {
		case ch <- event:
		default:
			// Slow client; drop event. Frontend will use polling fallback.
		}
	}
}

// subscriberCount returns the current number of active subscribers.
func (h *sseHub) subscriberCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.subscribers)
}
