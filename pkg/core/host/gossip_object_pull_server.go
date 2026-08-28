package host

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
)

const (
	DefaultGossipObjectPullServerConnections  = 16
	DefaultGossipObjectPullConnectionDeadline = 10 * time.Second
)

var (
	ErrGossipObjectPullListenerRequired = errors.New("gossip object-pull listener is required")
	ErrGossipObjectPullLookupRequired   = errors.New("gossip object-pull lookup is required")
	ErrGossipObjectPullServerStarted    = errors.New("gossip object-pull server is already started")
)

// StartGossipObjectPullServer transfers listener ownership to Runtime and
// starts its only bounded object-pull accept loop.
func (runtime *Runtime) StartGossipObjectPullServer(
	ctx context.Context,
	listener net.Listener,
	lookup func(*gossip.ObjectPullRequest) *gossip.ObjectPullResponse,
	maxConnections int,
	connectionDeadline time.Duration,
) error {
	if runtime == nil {
		return ErrRuntimeStopped
	}
	if listener == nil {
		return ErrGossipObjectPullListenerRequired
	}
	if lookup == nil {
		return ErrGossipObjectPullLookupRequired
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if maxConnections <= 0 {
		maxConnections = DefaultGossipObjectPullServerConnections
	}
	if connectionDeadline <= 0 {
		connectionDeadline = DefaultGossipObjectPullConnectionDeadline
	}

	serverCtx, cancel := context.WithCancel(ctx)
	runtime.mu.Lock()
	if runtime.stopped {
		runtime.mu.Unlock()
		cancel()
		return ErrRuntimeStopped
	}
	if runtime.objectPullServerListener != nil {
		runtime.mu.Unlock()
		cancel()
		return ErrGossipObjectPullServerStarted
	}
	runtime.objectPullServerCancel = cancel
	runtime.objectPullServerListener = listener
	runtime.objectPullServerWG.Add(1)
	runtime.mu.Unlock()

	go runtime.runGossipObjectPullServer(serverCtx, listener, lookup, maxConnections, connectionDeadline)
	return nil
}

func (runtime *Runtime) runGossipObjectPullServer(
	ctx context.Context,
	listener net.Listener,
	lookup func(*gossip.ObjectPullRequest) *gossip.ObjectPullResponse,
	maxConnections int,
	connectionDeadline time.Duration,
) {
	defer runtime.objectPullServerWG.Done()
	var closeOnce sync.Once
	closeListener := func() { closeOnce.Do(func() { _ = listener.Close() }) }
	stopClose := context.AfterFunc(ctx, closeListener)
	defer stopClose()
	defer closeListener()

	slots := make(chan struct{}, maxConnections)
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		select {
		case slots <- struct{}{}:
		case <-ctx.Done():
			_ = conn.Close()
			return
		default:
			_ = conn.Close()
			continue
		}
		runtime.objectPullServerWG.Add(1)
		go func() {
			defer runtime.objectPullServerWG.Done()
			defer func() { <-slots }()
			defer conn.Close()
			stopClose := context.AfterFunc(ctx, func() { _ = conn.Close() })
			defer stopClose()
			_ = conn.SetDeadline(time.Now().Add(connectionDeadline))
			_ = gossip.ServeObjectPull(conn, lookup)
		}()
	}
}
