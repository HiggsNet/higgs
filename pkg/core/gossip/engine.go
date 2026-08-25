package gossip

import (
	"errors"
	"time"
)

const DefaultSyncEventBuffer = 64

var ErrSyncEventQueueFull = errors.New("gossip sync event queue full")

// Engine owns the mutable per-peer protocol sessions, pending hints, event
// queue and protocol timers. It is intentionally single-writer: platform event
// loops call its methods serially, while TimerManager only posts events.
type Engine struct {
	sessions     map[string]*SyncSession
	pendingHints map[string]bool
	events       chan SyncEvent
	timers       *TimerManager
}

func NewEngine(clock TimerClock, eventBuffer int) *Engine {
	if eventBuffer <= 0 {
		eventBuffer = DefaultSyncEventBuffer
	}
	engine := &Engine{
		sessions:     make(map[string]*SyncSession),
		pendingHints: make(map[string]bool),
		events:       make(chan SyncEvent, eventBuffer),
	}
	engine.timers = NewTimerManager(clock, engine.events)
	return engine
}

func (engine *Engine) Events() <-chan SyncEvent {
	if engine == nil {
		return nil
	}
	return engine.events
}

func (engine *Engine) PendingEventCount() int {
	if engine == nil {
		return 0
	}
	return len(engine.events)
}

func (engine *Engine) Post(event SyncEvent) error {
	if engine == nil || event == nil {
		return nil
	}
	select {
	case engine.events <- event:
		return nil
	default:
		return ErrSyncEventQueueFull
	}
}

func (engine *Engine) NewSession(peerID string) *SyncSession {
	if engine == nil || peerID == "" {
		return nil
	}
	session := NewSyncSession(peerID)
	engine.sessions[peerID] = session
	return session
}

// SetSession installs a detached session. It supports restored/test sessions;
// normal callers use NewSession.
func (engine *Engine) SetSession(peerID string, session *SyncSession) {
	if engine == nil || peerID == "" {
		return
	}
	if session == nil {
		delete(engine.sessions, peerID)
		return
	}
	engine.sessions[peerID] = session
}

func (engine *Engine) Session(peerID string) *SyncSession {
	if engine == nil {
		return nil
	}
	return engine.sessions[peerID]
}

func (engine *Engine) HasActiveSession(peerID string) bool {
	session := engine.Session(peerID)
	return session != nil && !session.Done()
}

func (engine *Engine) RemoveSession(peerID string) {
	if engine != nil {
		delete(engine.sessions, peerID)
	}
}

func (engine *Engine) PlanInbound(packet *Packet) []InboundAction {
	if engine == nil {
		return PlanInboundPacket(packet, nil)
	}
	return PlanInboundPacket(packet, engine.sessions)
}

type EngineEventResult struct {
	Accepted bool
	PeerID   string
	Session  *SyncSession
	OldState SyncSessionState
	Actions  []SyncAction
	Err      error
}

// HandleEvent advances the owning session and fails it on protocol errors.
// Callers may enrich packet-derived event fields before invoking this method.
func (engine *Engine) HandleEvent(event SyncEvent, now time.Time) EngineEventResult {
	peerID := SyncEventPeerID(event)
	result := EngineEventResult{PeerID: peerID}
	if engine == nil || peerID == "" {
		return result
	}
	session := engine.sessions[peerID]
	if session == nil {
		return result
	}
	result.Accepted = true
	result.Session = session
	result.OldState = session.State
	result.Actions, result.Err = session.OnEvent(event, now)
	if result.Err != nil {
		session.Fail(result.Err)
	}
	return result
}

func (engine *Engine) DeferHint(peerID string) {
	if engine != nil && peerID != "" {
		engine.pendingHints[peerID] = true
	}
}

func (engine *Engine) PendingHint(peerID string) bool {
	return engine != nil && engine.pendingHints[peerID]
}

func (engine *Engine) TakePendingHint(peerID string) bool {
	if engine == nil || !engine.pendingHints[peerID] {
		return false
	}
	delete(engine.pendingHints, peerID)
	return true
}

func (engine *Engine) StartTimer(peerID, kind string, deadline time.Time) {
	if engine != nil && engine.timers != nil {
		engine.timers.Start(peerID, kind, deadline)
	}
}

func (engine *Engine) CancelTimer(peerID, kind string) {
	if engine != nil && engine.timers != nil {
		engine.timers.Cancel(peerID, kind)
	}
}

func (engine *Engine) CancelPeerTimers(peerID string) {
	if engine != nil && engine.timers != nil {
		engine.timers.CancelAll(peerID)
	}
}

func (engine *Engine) ResetTimers(clock TimerClock) {
	if engine == nil {
		return
	}
	if engine.timers != nil {
		engine.timers.Stop()
	}
	engine.timers = NewTimerManager(clock, engine.events)
}

func (engine *Engine) Stop() {
	if engine != nil && engine.timers != nil {
		engine.timers.Stop()
	}
}
