package main

import (
	"context"
	"errors"
	"net"
	"sync"

	"github.com/Catofes/higgs/pkg/core/gossip"
)

// startGossipPacketReceiver starts a goroutine that blocks on
// transport.Receive() and forwards received packets on the returned channel.
//
// The returned stop function must be deferred by the caller. It closes the
// transport, which unblocks the goroutine and causes it to exit cleanly.
func startGossipPacketReceiver(
	ctx context.Context,
	transport *gossip.Transport,
	warnLog func(component, event string, fields map[string]any),
) (<-chan *gossip.Packet, func()) {
	packetCh := make(chan *gossip.Packet, 64)
	done := make(chan struct{})

	go func() {
		defer close(packetCh)
		for {
			packet, err := transport.Receive()
			if err != nil {
				// Timeouts are routine (used to keep the loop responsive before
				// this refactor; kept for compatibility with callers that still
				// set read deadlines). Closing the transport is the normal
				// shutdown path and must not be logged as an error.
				if isReceiveTimeout(err) || errors.Is(err, net.ErrClosed) {
					select {
					case <-ctx.Done():
						return
					case <-done:
						return
					default:
						continue
					}
				}
				if warnLog != nil {
					warnLog("transport", "receive_failed", map[string]any{"error": err})
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
			_ = transport.Close()
		})
	}
	return packetCh, stop
}
