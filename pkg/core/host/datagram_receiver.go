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
)

// DatagramReceiver is the injected receive/close capability owned by Runtime.
// Protocol decoding and peer validation may still live in the adapter; the
// common runtime owns the single blocking receive goroutine, event-queue
// backpressure and shutdown ordering.
type DatagramReceiver interface {
	Receive() (*gossip.Packet, error)
	Close() error
}

// StartGossipDatagramReceiver starts the runtime-owned, bounded receive loop.
// Runtime.Stop cancels the loop, closes the injected receiver to unblock a
// blocking Receive call, and waits for the receive goroutine to exit.
func (runtime *Runtime) StartGossipDatagramReceiver(
	ctx context.Context,
	receiver DatagramReceiver,
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
	receiver DatagramReceiver,
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
