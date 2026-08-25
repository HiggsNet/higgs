package photonclient

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

// RuntimeState is the externally observable portable runtime lifecycle.
type RuntimeState string

const (
	RuntimeCreated  RuntimeState = "created"
	RuntimeStarting RuntimeState = "starting"
	RuntimeRunning  RuntimeState = "running"
	RuntimeStopping RuntimeState = "stopping"
	RuntimeStopped  RuntimeState = "stopped"
	RuntimeFailed   RuntimeState = "failed"
)

// Workload starts only after Resources validate. Start must return only after
// its critical loops are ready. Stop must quiesce packet ingress and initiate
// protocol cleanup; Wait reports the final loop result.
type Workload interface {
	Start(ctx context.Context, resources Resources) error
	Stop(ctx context.Context) error
	Wait() error
}

// RuntimeStatus is a detached status value suitable for IPC presentation.
type RuntimeStatus struct {
	State RuntimeState
	Error string
}

// Runtime supervises one portable workload. It deliberately does not create
// platform resources itself.
type Runtime struct {
	lifecycleMu sync.Mutex
	mu          sync.Mutex
	state       RuntimeState
	lastError   error

	resources Resources
	workload  Workload
	runCtx    context.Context
	cancel    context.CancelFunc
	done      chan struct{}

	resourceCloseOnce sync.Once
	doneOnce          sync.Once
	closeErr          error
}

func NewRuntime(resources Resources, workload Workload) *Runtime {
	return &Runtime{
		state:     RuntimeCreated,
		resources: resources,
		workload:  workload,
		done:      make(chan struct{}),
	}
}

// Start validates all capabilities and synchronously waits for workload
// readiness. Runtime cannot be restarted after Stop or failure.
func (r *Runtime) Start(parent context.Context) error {
	r.lifecycleMu.Lock()
	defer r.lifecycleMu.Unlock()

	r.mu.Lock()
	if r.state != RuntimeCreated {
		state := r.state
		r.mu.Unlock()
		return fmt.Errorf("photon client runtime cannot start from %s", state)
	}
	r.state = RuntimeStarting
	r.mu.Unlock()

	if r.workload == nil {
		return r.failStart(errors.New("photon client workload is nil"))
	}
	if err := r.resources.Validate(); err != nil {
		return r.failStart(err)
	}

	ctx, cancel := context.WithCancel(parent)
	r.mu.Lock()
	r.runCtx = ctx
	r.cancel = cancel
	r.mu.Unlock()

	if err := r.workload.Start(ctx, r.resources); err != nil {
		cancel()
		return r.failStart(fmt.Errorf("start photon client workload: %w", err))
	}

	r.mu.Lock()
	if r.state != RuntimeStarting {
		state := r.state
		r.mu.Unlock()
		cancel()
		return fmt.Errorf("photon client workload became %s while starting", state)
	}
	r.state = RuntimeRunning
	r.mu.Unlock()

	go func() {
		r.complete(r.workload.Wait())
	}()
	return nil
}

func (r *Runtime) failStart(err error) error {
	r.mu.Lock()
	r.state = RuntimeFailed
	r.lastError = err
	r.mu.Unlock()
	r.closeResources()
	r.doneOnce.Do(func() { close(r.done) })
	return err
}

// Stop requests graceful workload cleanup, closes injected resources, and
// waits for the critical loops to exit or for ctx to expire.
func (r *Runtime) Stop(ctx context.Context) error {
	r.lifecycleMu.Lock()
	defer r.lifecycleMu.Unlock()

	r.mu.Lock()
	switch r.state {
	case RuntimeCreated:
		r.state = RuntimeStopped
		r.mu.Unlock()
		r.closeResources()
		r.doneOnce.Do(func() { close(r.done) })
		return r.closeErr
	case RuntimeStopped, RuntimeFailed:
		done := r.done
		r.mu.Unlock()
		select {
		case <-done:
			return r.closeErr
		case <-ctx.Done():
			return ctx.Err()
		}
	case RuntimeStopping:
		done := r.done
		r.mu.Unlock()
		select {
		case <-done:
			return r.closeErr
		case <-ctx.Done():
			return ctx.Err()
		}
	case RuntimeStarting, RuntimeRunning:
		r.state = RuntimeStopping
		cancel := r.cancel
		r.mu.Unlock()
		if cancel != nil {
			cancel()
		}
	default:
		state := r.state
		r.mu.Unlock()
		return fmt.Errorf("unknown photon client runtime state %q", state)
	}

	stopErr := r.workload.Stop(ctx)
	r.closeResources()

	select {
	case <-r.done:
		if stopErr != nil {
			r.recordFailure(fmt.Errorf("stop photon client workload: %w", stopErr))
		}
		return errors.Join(stopErr, r.closeErr)
	case <-ctx.Done():
		r.recordFailure(fmt.Errorf("stop photon client workload: %w", ctx.Err()))
		return errors.Join(stopErr, r.closeErr, ctx.Err())
	}
}

// Wait blocks until the workload has exited.
func (r *Runtime) Wait(ctx context.Context) error {
	select {
	case <-r.done:
		r.mu.Lock()
		err := r.lastError
		r.mu.Unlock()
		return errors.Join(err, r.closeErr)
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (r *Runtime) Status() RuntimeStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	status := RuntimeStatus{State: r.state}
	if r.lastError != nil {
		status.Error = r.lastError.Error()
	}
	return status
}

func (r *Runtime) complete(err error) {
	r.mu.Lock()
	state := r.state
	wasCanceled := r.runCtx != nil && r.runCtx.Err() != nil
	if err != nil && !(errors.Is(err, context.Canceled) && wasCanceled) {
		r.state = RuntimeFailed
		r.lastError = fmt.Errorf("photon client workload exited: %w", err)
	} else if state == RuntimeRunning && !wasCanceled {
		r.state = RuntimeFailed
		r.lastError = errors.New("photon client workload exited while runtime was running")
	} else {
		r.state = RuntimeStopped
	}
	cancel := r.cancel
	r.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	r.closeResources()
	r.doneOnce.Do(func() { close(r.done) })
}

func (r *Runtime) recordFailure(err error) {
	r.mu.Lock()
	r.state = RuntimeFailed
	r.lastError = errors.Join(r.lastError, err)
	r.mu.Unlock()
}

func (r *Runtime) closeResources() {
	r.resourceCloseOnce.Do(func() {
		// Stop has already asked the workload to remove routes and peer state.
		// Datagram closes before the tunnel; observers close last.
		r.closeErr = errors.Join(
			closeIfSet(r.resources.Datagram),
			closeIfSet(r.resources.Tunnel),
			closeIfSet(r.resources.Networks),
			closeIfSet(r.resources.States),
		)
	})
}

type closer interface {
	Close() error
}

func closeIfSet(value closer) error {
	if value == nil {
		return nil
	}
	return value.Close()
}
