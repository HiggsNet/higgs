package gossip

import (
	"context"
	"errors"
	"net"
	"sync"
)

// DefaultPacketReceiveBuffer bounds packets waiting for the platform event
// loop. Backpressure stops further Receive calls instead of spawning work per
// packet or growing an unbounded queue.
const DefaultPacketReceiveBuffer = 64

// PacketReceiver is the transport capability required by the shared gossip
// receive loop. Transport implements it for Linux; other platforms can provide
// their own socket or tunnel-backed implementation.
type PacketReceiver interface {
	Receive() (*Packet, error)
	Close() error
}

var _ PacketReceiver = (*Transport)(nil)

// StartPacketReceiver owns receiver until stop is called. It forwards packets
// through a bounded channel, suppresses routine timeout/close errors, and
// reports other receive errors without terminating the loop.
//
// The caller must call stop. Closing the receiver is what unblocks a Receive
// implementation that cannot observe ctx directly.
func StartPacketReceiver(
	ctx context.Context,
	receiver PacketReceiver,
	buffer int,
	onError func(error),
) (<-chan *Packet, func()) {
	if ctx == nil {
		ctx = context.Background()
	}
	if buffer <= 0 {
		buffer = DefaultPacketReceiveBuffer
	}
	packetCh := make(chan *Packet, buffer)
	done := make(chan struct{})

	go func() {
		defer close(packetCh)
		if receiver == nil {
			if onError != nil {
				onError(errors.New("gossip packet receiver is nil"))
			}
			return
		}
		for {
			packet, err := receiver.Receive()
			if err != nil {
				if isNetworkTimeout(err) || errors.Is(err, net.ErrClosed) {
					select {
					case <-ctx.Done():
						return
					case <-done:
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
				case <-done:
					return
				default:
					continue
				}
			}

			select {
			case packetCh <- packet:
			case <-ctx.Done():
				return
			case <-done:
				return
			}
		}
	}()

	var stopOnce sync.Once
	stop := func() {
		stopOnce.Do(func() {
			close(done)
			if receiver != nil {
				_ = receiver.Close()
			}
		})
	}
	return packetCh, stop
}
