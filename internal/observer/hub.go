package observer

import "sync"

// Event is a lightweight notification pushed to SSE subscribers. It only
// carries the event type and a small payload; detail data is fetched by the
// client via REST snapshot APIs after receiving the notification.
type Event struct {
	Type    string `json:"type"`
	Payload any    `json:"payload,omitempty"`
}

// Hub maintains a set of SSE subscriber channels and broadcasts lightweight
// events to all of them. Slow clients that cannot keep up have their events
// dropped (non-blocking send), and the frontend falls back to polling.
type Hub struct {
	mu          sync.Mutex
	subscribers map[chan Event]struct{}
}

// NewHub returns an empty SSE hub.
func NewHub() *Hub {
	return &Hub{subscribers: make(map[chan Event]struct{})}
}

// Subscribe registers a new subscriber and returns its event channel. The
// caller must call the returned unsubscribe function when done.
func (h *Hub) Subscribe() (<-chan Event, func()) {
	ch := make(chan Event, 16)
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

// Broadcast sends an event to all subscribers. Non-blocking: subscribers with
// full queues are skipped (their frontends must poll to recover).
func (h *Hub) Broadcast(event Event) {
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

// SubscriberCount returns the current number of active subscribers.
func (h *Hub) SubscriberCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.subscribers)
}
