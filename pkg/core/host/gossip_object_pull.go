package host

import (
	"context"
	"errors"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

const (
	DefaultGossipObjectPullWorkers = 4
	DefaultGossipObjectPullBuffer  = 64
)

var (
	ErrGossipObjectPullExecutorRequired = errors.New("gossip object-pull executor is required")
	ErrGossipObjectPullAlreadyStarted   = errors.New("gossip object-pull workers already started")
	ErrGossipObjectPullQueueFull        = errors.New("gossip object-pull queue full")
)

// GossipObjectPullCompletion is the platform-neutral result returned by an
// object-pull controller. Runtime owns its conversion to an FSM event and the
// queue backpressure contract.
type GossipObjectPullCompletion struct {
	PeerID      string
	Zone        zone.ZonePath
	Addr        string
	Bytes       int
	Unreachable bool
	Snapshot    *corestate.ZoneSnapshot
	Err         error
}

// StartGossipObjectPullWorkers starts Runtime's only object-pull worker group.
// Platform composition supplies the TCP I/O capability, not another queue.
func (runtime *Runtime) StartGossipObjectPullWorkers(ctx context.Context, executor *GossipObjectPullExecutor, workers, buffer int) error {
	if runtime == nil {
		return ErrRuntimeStopped
	}
	if executor == nil {
		return ErrGossipObjectPullExecutorRequired
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if workers <= 0 {
		workers = DefaultGossipObjectPullWorkers
	}
	if buffer <= 0 {
		buffer = DefaultGossipObjectPullBuffer
	}
	runtime.mu.Lock()
	if runtime.stopped {
		runtime.mu.Unlock()
		return ErrRuntimeStopped
	}
	if runtime.objectPullJobs != nil {
		runtime.mu.Unlock()
		return ErrGossipObjectPullAlreadyStarted
	}
	workerCtx, cancel := context.WithCancel(ctx)
	runtime.objectPullCancel = cancel
	runtime.objectPullJobs = make(chan gossip.StartObjectPullAction, buffer)
	jobs := runtime.objectPullJobs
	runtime.mu.Unlock()

	for range workers {
		runtime.objectPullWG.Add(1)
		go runtime.runGossipObjectPullWorker(workerCtx, jobs, executor)
	}
	return nil
}

// SubmitGossipObjectPull never blocks the single-writer event loop.
func (runtime *Runtime) SubmitGossipObjectPull(action gossip.StartObjectPullAction) error {
	if runtime == nil {
		return ErrRuntimeStopped
	}
	runtime.mu.RLock()
	stopped := runtime.stopped
	jobs := runtime.objectPullJobs
	runtime.mu.RUnlock()
	if stopped {
		return ErrRuntimeStopped
	}
	if jobs == nil {
		return ErrGossipObjectPullExecutorRequired
	}
	runtime.objectPullPending.Add(1)
	select {
	case jobs <- action:
		return nil
	default:
		runtime.objectPullPending.Add(-1)
		return ErrGossipObjectPullQueueFull
	}
}

func (runtime *Runtime) PendingGossipObjectPullCount() int {
	if runtime == nil {
		return 0
	}
	return int(runtime.objectPullPending.Load())
}

func (runtime *Runtime) runGossipObjectPullWorker(ctx context.Context, jobs <-chan gossip.StartObjectPullAction, executor *GossipObjectPullExecutor) {
	defer runtime.objectPullWG.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case action := <-jobs:
			now := runtime.schedulerForRead().clock.Now()
			runtime.observeObjectPullAttempt(action.PeerID, action.Zone, now)
			runtime.logGossip("debug", "worker_start", action.PeerID, GossipPhaseObjectPull, nil, map[string]any{"zone": action.Zone})
			completion := executor.PullGossipObject(ctx, action)
			if completion.PeerID == "" {
				completion.PeerID = action.PeerID
			}
			if !completion.Zone.Valid() {
				completion.Zone = action.Zone
			}
			runtime.observeObjectPullResult(completion, runtime.schedulerForRead().clock.Now())
			runtime.logGossip("debug", "worker_done", completion.PeerID, GossipPhaseObjectPull, completion.Err, map[string]any{
				"zone": completion.Zone, "bytes": completion.Bytes, "ok": completion.Err == nil,
			})
			event := GossipEvent{Value: &gossip.ObjectPullResultEvent{
				PeerID: completion.PeerID, Zone: completion.Zone,
				Snapshot: completion.Snapshot, Err: completion.Err,
			}}
			select {
			case runtime.events <- event:
				runtime.objectPullPending.Add(-1)
			case <-ctx.Done():
				runtime.objectPullPending.Add(-1)
				return
			}
		}
	}
}
