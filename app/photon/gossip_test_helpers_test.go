package main

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	photonlinux "github.com/HiggsNet/photon/internal/photonlinux"
	"github.com/HiggsNet/photon/pkg/core/gossip"
)

type testGossipDatagram struct {
	addr *net.UDPAddr
}

func (*testGossipDatagram) ReadDatagram([]byte) (int, *net.UDPAddr, error) {
	return 0, nil, net.ErrClosed
}
func (*testGossipDatagram) WriteDatagram(payload []byte, _ *net.UDPAddr) (int, error) {
	return len(payload), nil
}
func (datagram *testGossipDatagram) LocalAddr() *net.UDPAddr { return datagram.addr }
func (*testGossipDatagram) SetReadDeadline(time.Time) error  { return nil }
func (*testGossipDatagram) Close() error                     { return nil }

func bindTestHostGossipTransport(t *testing.T, service *DaemonService, peerIDs ...string) *gossip.Transport {
	t.Helper()
	known := make(map[string]*net.UDPAddr, len(peerIDs))
	for _, peerID := range peerIDs {
		known[peerID] = &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 33435}
	}
	transport, err := gossip.NewTransport(gossip.Config{
		PeerID: service.Sync.Config.PeerID, KnownPeers: known,
		MaxMessageBytes: gossip.DefaultDatagramBudget,
	}, &testGossipDatagram{addr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 33434}})
	if err != nil {
		t.Fatal(err)
	}
	setTestGossipTransport(t, service, transport)
	return transport
}

func setTestGossipTransport(t *testing.T, service *DaemonService, transport *gossip.Transport) {
	t.Helper()
	if err := service.hostRuntime.BindGossipTransport(transport); err != nil {
		t.Fatal(err)
	}
	service.Sync.Transport = transport
}

func listenTestGossipTransport(listenAddr string, config gossip.Config) (*gossip.Transport, error) {
	datagram, err := photonlinux.ListenGossipDatagram(listenAddr)
	if err != nil {
		return nil, err
	}
	transport, err := gossip.NewTransport(config, datagram)
	if err != nil {
		_ = datagram.Close()
		return nil, err
	}
	return transport, nil
}

func receiveWithContext(ctx context.Context, transport *gossip.Transport, deadline time.Time) (*gossip.Packet, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	for {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		readDeadline := deadline
		shortDeadline := time.Now().Add(250 * time.Millisecond)
		if shortDeadline.Before(readDeadline) {
			readDeadline = shortDeadline
		}
		packet, err := receiveWithDeadline(transport, readDeadline)
		if err == nil {
			return packet, nil
		}
		if time.Now().After(deadline) || !isReceiveTimeout(err) {
			return nil, err
		}
	}
}

func receiveWithDeadline(transport *gossip.Transport, deadline time.Time) (*gossip.Packet, error) {
	if err := transport.SetReadDeadline(deadline); err != nil {
		return nil, err
	}
	for {
		packet, err := transport.Receive()
		if err == nil {
			return packet, nil
		}
		if time.Now().After(deadline) {
			return nil, errors.New("sync receive timed out")
		}
		if errors.Is(err, gossip.ErrUnknownPeer) || errors.Is(err, gossip.ErrAddrMismatch) || errors.Is(err, gossip.ErrMessageTooLarge) {
			continue
		}
		return nil, err
	}
}

func isReceiveTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout() || strings.Contains(err.Error(), "timed out")
}

func pumpEventLoopSync(ctx context.Context, services []*DaemonService, transports []*gossip.Transport) {
	for {
		processed := false
		for _, service := range services {
			select {
			case hostEvent := <-service.hostRuntime.Events():
				if result, err := service.handleHostRuntimeGossipEvent(ctx, hostEvent); err == nil && result.Handled {
					processed = true
				}
			default:
			}
		}
		for index, transport := range transports {
			packet, err := receiveWithContext(ctx, transport, time.Now().Add(10*time.Millisecond))
			if err == nil {
				services[index].processPacketEvent(packet, ctx)
				processed = true
			}
		}
		if !processed {
			return
		}
	}
}
