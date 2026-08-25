package main

import (
	"context"

	"github.com/HiggsNet/photon/pkg/core/gossip"
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
	var onError func(error)
	if warnLog != nil {
		onError = func(err error) {
			warnLog("transport", "receive_failed", map[string]any{"error": err})
		}
	}
	return gossip.StartPacketReceiver(ctx, transport, gossip.DefaultPacketReceiveBuffer, onError)
}
