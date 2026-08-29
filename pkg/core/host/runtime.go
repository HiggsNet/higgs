// Package host owns the platform-neutral runtime resources shared by Photon
// hosts. Protocol packages describe policy and actions; Runtime owns the
// bounded queue and scheduling mechanism used to execute those actions.
package host

import (
	"context"
	"encoding/hex"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
)

const (
	DefaultEventBuffer   = 64
	GossipTimerNamespace = "gossip"
)

var (
	ErrEventQueueFull    = errors.New("host event queue full")
	ErrRuntimeStopped    = errors.New("host runtime stopped")
	ErrInvalidCompletion = errors.New("invalid host completion")
)

// Event is delivered to the single-writer HostRuntime event loop.
type Event interface {
	isHostEvent()
}

// GossipEvent carries an externally produced gossip protocol event.
type GossipEvent struct {
	Value gossip.SyncEvent
}

func (GossipEvent) isHostEvent() {}

// GossipPacketReceived carries one packet accepted by the injected datagram
// receiver. Packets and protocol timer/completion events share the same
// bounded runtime queue, preserving one backpressure and ordering boundary.
type GossipPacketReceived struct {
	Packet *gossip.Packet
}

func (GossipPacketReceived) isHostEvent() {}

// Completion wakes the single-writer loop after asynchronous runtime work.
// Namespace/owner/key identify the producer without coupling Runtime to a
// specific controller or protocol result type.
type Completion struct {
	Namespace string
	Owner     string
	Key       string
}

func (Completion) isHostEvent() {}

// Runtime owns the common gossip engine, bounded event queue and scheduler.
// Platform composition roots inject I/O and controllers around this object;
// they do not create a second protocol queue or timer manager.
type Runtime struct {
	Gossip *gossip.Engine

	gossipState  GossipStateStore
	gossipConfig GossipRuntimeConfig

	events chan Event

	mu                       sync.RWMutex
	scheduler                *Scheduler
	objectPullCancel         context.CancelFunc
	objectPullJobs           chan gossip.StartObjectPullAction
	objectPullWG             sync.WaitGroup
	objectPullPending        atomic.Int64
	objectPullServerCancel   context.CancelFunc
	objectPullServerListener net.Listener
	objectPullServerWG       sync.WaitGroup
	gossipChunks             *gossip.ChunkAssemblyStore
	datagramReceiver         DatagramReceiver
	datagramCancel           context.CancelFunc
	datagramWG               sync.WaitGroup
	stopped                  bool
}

func NewRuntime(clock Clock, eventBuffer int, gossipState GossipStateStore, gossipConfig GossipRuntimeConfig) *Runtime {
	if eventBuffer <= 0 {
		eventBuffer = DefaultEventBuffer
	}
	runtime := &Runtime{
		Gossip:       gossip.NewEngine(),
		gossipState:  gossipState,
		gossipConfig: gossipConfig,
		events:       make(chan Event, eventBuffer),
		gossipChunks: gossip.NewChunkAssemblyStore(),
	}
	runtime.scheduler = NewScheduler(clock, runtime.events)
	return runtime
}

func (runtime *Runtime) Events() <-chan Event {
	if runtime == nil {
		return nil
	}
	return runtime.events
}

func (runtime *Runtime) PendingEventCount() int {
	if runtime == nil {
		return 0
	}
	return len(runtime.events)
}

// PostGossip enqueues an external protocol event without blocking. Producers
// receive explicit backpressure; scheduler delivery uses its own blocking,
// shutdown-aware path so timeouts are never silently dropped.
func (runtime *Runtime) PostGossip(event gossip.SyncEvent) error {
	if runtime == nil || event == nil {
		return nil
	}
	runtime.mu.RLock()
	stopped := runtime.stopped
	runtime.mu.RUnlock()
	if stopped {
		return ErrRuntimeStopped
	}
	select {
	case runtime.events <- GossipEvent{Value: event}:
		return nil
	default:
		return ErrEventQueueFull
	}
}

// PostCompletion queues an asynchronous completion at the common runtime
// boundary. It waits for bounded-queue capacity or context cancellation so a
// completed operation is not silently lost under temporary backpressure.
func (runtime *Runtime) PostCompletion(ctx context.Context, completion Completion) error {
	if runtime == nil {
		return ErrRuntimeStopped
	}
	if completion.Namespace == "" || completion.Owner == "" || completion.Key == "" {
		return ErrInvalidCompletion
	}
	runtime.mu.RLock()
	stopped := runtime.stopped
	runtime.mu.RUnlock()
	if stopped {
		return ErrRuntimeStopped
	}
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case runtime.events <- completion:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// GossipSessionEventFor converts a host event into one session-FSM event. Timer
// generations are accepted here, at the single-writer boundary, so a queued
// timeout made stale by cancel/replace cannot advance a session.
func (runtime *Runtime) GossipSessionEventFor(event Event) (gossip.SyncEvent, bool) {
	if runtime == nil || event == nil {
		return nil, false
	}
	switch typed := event.(type) {
	case GossipEvent:
		return typed.Value, typed.Value != nil
	case TimerFired:
		if typed.ID.Namespace != GossipTimerNamespace && typed.ID.Namespace != GossipChunkRepairNamespace {
			return nil, false
		}
		if !runtime.schedulerForRead().Accept(typed) {
			return nil, false
		}
		if typed.ID.Namespace == GossipChunkRepairNamespace {
			transferID, err := hex.DecodeString(typed.ID.Key)
			if err != nil {
				return nil, false
			}
			return &gossip.ChunkRepairTimeoutEvent{PeerID: typed.ID.Owner, TransferID: transferID}, true
		}
		if typed.ID.Namespace != GossipTimerNamespace {
			return nil, false
		}
		switch typed.ID.Key {
		case gossip.TimerKindRound:
			return &gossip.RoundTimeoutEvent{PeerID: typed.ID.Owner}, true
		case gossip.TimerKindCatalogPage:
			return &gossip.CatalogPageTimeoutEvent{PeerID: typed.ID.Owner}, true
		default:
			return nil, false
		}
	default:
		return nil, false
	}
}

// ApplyGossipTimerAction executes the scheduling subset of gossip actions.
// Deadline choice remains in the protocol FSM; only timer resources live here.
func (runtime *Runtime) ApplyGossipTimerAction(action gossip.SyncAction) (bool, error) {
	if runtime == nil {
		return false, ErrRuntimeStopped
	}
	switch typed := action.(type) {
	case gossip.StartTimerAction:
		_, err := runtime.schedulerForRead().Schedule(TimerID{
			Namespace: GossipTimerNamespace,
			Owner:     typed.PeerID,
			Key:       typed.Kind,
		}, typed.Deadline)
		return true, err
	case gossip.CancelTimerAction:
		runtime.schedulerForRead().Cancel(TimerID{
			Namespace: GossipTimerNamespace,
			Owner:     typed.PeerID,
			Key:       typed.Kind,
		})
		return true, nil
	default:
		return false, nil
	}
}

func (runtime *Runtime) CancelGossipTimers(peerID string) {
	if runtime == nil || peerID == "" {
		return
	}
	runtime.schedulerForRead().CancelOwner(GossipTimerNamespace, peerID)
}

// ScheduleTimer registers a protocol or controller deadline in Runtime's one
// scheduler. Callers choose a stable namespace/owner/key and consume the
// resulting TimerFired event through AcceptTimer at the single-writer boundary.
func (runtime *Runtime) ScheduleTimer(id TimerID, deadline time.Time) (uint64, error) {
	if runtime == nil {
		return 0, ErrRuntimeStopped
	}
	return runtime.schedulerForRead().Schedule(id, deadline)
}

func (runtime *Runtime) CancelTimer(id TimerID) {
	if runtime != nil {
		runtime.schedulerForRead().Cancel(id)
	}
}

func (runtime *Runtime) AcceptTimer(fired TimerFired) bool {
	return runtime != nil && runtime.schedulerForRead().Accept(fired)
}

// ResetScheduler replaces only the runtime scheduling resource. It is used by
// deterministic tests before the event loop starts; protocol sessions remain
// owned by the same gossip Engine.
func (runtime *Runtime) ResetScheduler(clock Clock) {
	if runtime == nil {
		return
	}
	runtime.mu.Lock()
	if runtime.stopped {
		runtime.mu.Unlock()
		return
	}
	old := runtime.scheduler
	runtime.scheduler = NewScheduler(clock, runtime.events)
	runtime.mu.Unlock()
	old.Stop()
}

func (runtime *Runtime) Stop() {
	if runtime == nil {
		return
	}
	runtime.mu.Lock()
	if runtime.stopped {
		runtime.mu.Unlock()
		return
	}
	runtime.stopped = true
	scheduler := runtime.scheduler
	objectPullCancel := runtime.objectPullCancel
	objectPullServerCancel := runtime.objectPullServerCancel
	objectPullServerListener := runtime.objectPullServerListener
	datagramCancel := runtime.datagramCancel
	runtime.mu.Unlock()
	if datagramCancel != nil {
		datagramCancel()
	}
	if objectPullCancel != nil {
		objectPullCancel()
	}
	if objectPullServerCancel != nil {
		objectPullServerCancel()
	}
	if objectPullServerListener != nil {
		_ = objectPullServerListener.Close()
	}
	scheduler.Stop()
	runtime.datagramWG.Wait()
	runtime.objectPullWG.Wait()
	runtime.objectPullServerWG.Wait()
	runtime.objectPullPending.Store(0)
	if runtime.gossipChunks != nil {
		runtime.gossipChunks.Close()
	}
}

func (runtime *Runtime) schedulerForRead() *Scheduler {
	runtime.mu.RLock()
	defer runtime.mu.RUnlock()
	return runtime.scheduler
}

// Clock returns the standard runtime clock. A custom now function is useful
// when protocol deadlines and scheduler time must share a deterministic base.
func NewClock(now func() time.Time) Clock {
	if now == nil {
		now = time.Now
	}
	return &systemClock{now: now}
}
