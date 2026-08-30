package host

import (
	"context"
	"errors"
	"net"
	"sync"

	"github.com/HiggsNet/photon/pkg/core/gossip"
)

var (
	ErrDatagramReceiverRequired = errors.New("gossip datagram receiver is required")
	ErrDatagramReceiverStarted  = errors.New("gossip datagram receiver is already started")
	ErrGossipTransportRequired  = errors.New("gossip transport is required")
)

// BindGossipTransport installs the common UDP transport used by Runtime for
// send, reply routing and its rebuildable peer address book. Composition may
// replace it before the receive loop starts, for example after config reload.
func (runtime *Runtime) BindGossipTransport(transport *gossip.Transport) error {
	if runtime == nil {
		return ErrRuntimeStopped
	}
	if transport == nil {
		return ErrGossipTransportRequired
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.stopped {
		return ErrRuntimeStopped
	}
	if runtime.datagramReceiver != nil && runtime.gossipTransport != transport {
		return ErrDatagramReceiverStarted
	}
	runtime.gossipTransport = transport
	return nil
}

// StartGossipTransport binds the concrete common transport and starts its
// single runtime-owned receive loop.
func (runtime *Runtime) StartGossipTransport(ctx context.Context, transport *gossip.Transport, onError func(error)) error {
	if err := runtime.BindGossipTransport(transport); err != nil {
		return err
	}
	return runtime.startGossipDatagramReceiver(ctx, transport, onError)
}

func (runtime *Runtime) gossipTransportForRead() *gossip.Transport {
	if runtime == nil {
		return nil
	}
	runtime.mu.RLock()
	defer runtime.mu.RUnlock()
	return runtime.gossipTransport
}

// datagramReceiver is the receive/close capability owned by Runtime.
// Protocol decoding and peer validation may still live in the adapter; the
// common runtime owns the single blocking receive goroutine, event-queue
// backpressure and shutdown ordering.
type datagramReceiver interface {
	Receive() (*gossip.Packet, error)
	Close() error
}

// startGossipDatagramReceiver starts the runtime-owned, bounded receive loop.
// Runtime.Stop cancels the loop, closes the injected receiver to unblock a
// blocking Receive call, and waits for the receive goroutine to exit.
func (runtime *Runtime) startGossipDatagramReceiver(
	ctx context.Context,
	receiver datagramReceiver,
	onError func(error),
) error {
	if runtime == nil {
		return ErrRuntimeStopped
	}
	if receiver == nil {
		return ErrDatagramReceiverRequired
	}
	if ctx == nil {
		ctx = context.Background()
	}
	receiveCtx, cancel := context.WithCancel(ctx)
	runtime.mu.Lock()
	if runtime.stopped {
		runtime.mu.Unlock()
		cancel()
		return ErrRuntimeStopped
	}
	if runtime.datagramReceiver != nil {
		runtime.mu.Unlock()
		cancel()
		return ErrDatagramReceiverStarted
	}
	runtime.datagramReceiver = receiver
	runtime.datagramCancel = cancel
	runtime.datagramWG.Add(1)
	runtime.mu.Unlock()

	go runtime.runGossipDatagramReceiver(receiveCtx, receiver, onError)
	return nil
}

func (runtime *Runtime) runGossipDatagramReceiver(
	ctx context.Context,
	receiver datagramReceiver,
	onError func(error),
) {
	defer runtime.datagramWG.Done()
	var closeOnce sync.Once
	closeReceiver := func() { closeOnce.Do(func() { _ = receiver.Close() }) }
	stopClose := context.AfterFunc(ctx, closeReceiver)
	defer stopClose()
	defer closeReceiver()

	for {
		packet, err := receiver.Receive()
		if err != nil {
			if isRoutineDatagramReceiveError(err) {
				select {
				case <-ctx.Done():
					return
				default:
					continue
				}
			}
			if onError != nil {
				onError(err)
			}
			select {
			case <-ctx.Done():
				return
			default:
				continue
			}
		}
		select {
		case runtime.events <- GossipPacketReceived{Packet: packet}:
		case <-ctx.Done():
			return
		}
	}
}

func isRoutineDatagramReceiveError(err error) bool {
	if errors.Is(err, net.ErrClosed) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}
