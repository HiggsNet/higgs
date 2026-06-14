package gossip

import (
	"errors"
	"sync"
	"time"
)

var (
	ErrMessageExpired = errors.New("gossip message outside timestamp window")
	ErrReplay         = errors.New("gossip message replayed nonce")
)

type ReplayWindow struct {
	Window    time.Duration
	mu        sync.Mutex
	seen      map[string]map[uint64]int64
	nextPrune time.Time
}

func NewReplayWindow(window time.Duration) *ReplayWindow {
	if window <= 0 {
		window = time.Duration(DefaultWindow) * time.Second
	}
	return &ReplayWindow{
		Window: window,
		seen:   make(map[string]map[uint64]int64),
	}
}

func (rw *ReplayWindow) Check(peerID string, nonce uint64, timestamp int64, now time.Time) error {
	if rw == nil {
		return nil
	}
	if peerID == "" || nonce == 0 {
		return ErrReplay
	}

	messageTime := time.Unix(timestamp, 0)
	if messageTime.Before(now.Add(-rw.Window)) || messageTime.After(now.Add(rw.Window)) {
		return ErrMessageExpired
	}

	rw.mu.Lock()
	defer rw.mu.Unlock()
	rw.pruneExpired(now)
	rw.prune(peerID, now)
	if rw.seen[peerID] == nil {
		rw.seen[peerID] = make(map[uint64]int64)
	}
	if _, ok := rw.seen[peerID][nonce]; ok {
		return ErrReplay
	}
	rw.seen[peerID][nonce] = timestamp
	return nil
}

func (rw *ReplayWindow) pruneExpired(now time.Time) {
	if rw == nil || now.Before(rw.nextPrune) {
		return
	}
	pruneInterval := rw.Window / 2
	if pruneInterval <= 0 {
		pruneInterval = time.Second
	} else if rw.Window >= 2*time.Minute && pruneInterval < time.Minute {
		pruneInterval = time.Minute
	}
	rw.nextPrune = now.Add(pruneInterval)
	cutoff := now.Add(-rw.Window).Unix()
	for peerID, peerSeen := range rw.seen {
		for nonce, timestamp := range peerSeen {
			if timestamp < cutoff {
				delete(peerSeen, nonce)
			}
		}
		if len(peerSeen) == 0 {
			delete(rw.seen, peerID)
		}
	}
}

func (rw *ReplayWindow) prune(peerID string, now time.Time) {
	peerSeen := rw.seen[peerID]
	if len(peerSeen) == 0 {
		return
	}
	cutoff := now.Add(-rw.Window).Unix()
	for nonce, timestamp := range peerSeen {
		if timestamp < cutoff {
			delete(peerSeen, nonce)
		}
	}
	if len(peerSeen) == 0 {
		delete(rw.seen, peerID)
	}
}
