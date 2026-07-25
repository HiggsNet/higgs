package observer

import (
	"sync"
	"time"
)

// maxBufferedEvents caps the replay buffer so a long-lived hub cannot grow
// without bound even when events arrive faster than the time-window prune.
const maxBufferedEvents = 1024

// Event is a lightweight notification pushed to SSE subscribers. It carries
// the event type, a unix-second timestamp, and a small payload (ids only, no
// diffs); detail data is fetched by the client via REST snapshot APIs after
// receiving the notification.
type Event struct {
	Type    string `json:"type"`
	Time    int64  `json:"time"`
	Payload any    `json:"payload,omitempty"`
}

// Hub maintains a set of SSE subscriber channels and broadcasts lightweight
// events to all of them. Slow clients that cannot keep up have their events
// dropped (non-blocking send), and the frontend falls back to polling.
//
// When bufferSeconds > 0 the hub also keeps a replay buffer of recent events
// (pruned by time window on each Broadcast, hard-capped at maxBufferedEvents)
// which Recent() exposes to the /api/v1/events/recent endpoint.
type Hub struct {
	mu            sync.Mutex
	subscribers   map[chan Event]struct{}
	bufferSeconds int
	buffered      []Event
	now           func() time.Time
}

// NewHub returns an empty SSE hub with the replay buffer disabled.
func NewHub() *Hub {
	return NewHubWithBuffer(0)
}

// NewHubWithBuffer returns an SSE hub that retains broadcast events for
// bufferSeconds seconds. bufferSeconds <= 0 disables the replay buffer.
func NewHubWithBuffer(bufferSeconds int) *Hub {
	if bufferSeconds < 0 {
		bufferSeconds = 0
	}
	return &Hub{
		subscribers:   make(map[chan Event]struct{}),
		bufferSeconds: bufferSeconds,
		now:           time.Now,
	}
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
// full queues are skipped (their frontends must poll to recover). The event
// timestamp is filled in here when the caller did not set one.
func (h *Hub) Broadcast(event Event) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if event.Time == 0 {
		event.Time = h.now().Unix()
	}
	if h.bufferSeconds > 0 {
		cutoff := h.now().Unix() - int64(h.bufferSeconds)
		kept := 0
		for _, buffered := range h.buffered {
			if buffered.Time >= cutoff {
				h.buffered[kept] = buffered
				kept++
			}
		}
		h.buffered = append(h.buffered[:kept], event)
		if len(h.buffered) > maxBufferedEvents {
			h.buffered = h.buffered[len(h.buffered)-maxBufferedEvents:]
		}
	}
	for ch := range h.subscribers {
		select {
		case ch <- event:
		default:
			// Slow client; drop event. Frontend will use polling fallback.
		}
	}
}

// Recent returns a copy of the replay buffer in ascending time order. It
// returns an empty (non-nil) slice when the buffer is disabled or empty.
func (h *Hub) Recent() []Event {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]Event, len(h.buffered))
	copy(out, h.buffered)
	return out
}

// SubscriberCount returns the current number of active subscribers.
func (h *Hub) SubscriberCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.subscribers)
}
