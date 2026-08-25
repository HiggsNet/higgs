package testkit

import (
	"context"
	"net/netip"
	"testing"

	"github.com/HiggsNet/photon/internal/photonclient"
)

func TestMemoryTunnelCopiesPacketsInBothDirections(t *testing.T) {
	ctx := context.Background()
	tunnel := NewMemoryTunnel("memory0", 1400)
	outbound := []byte{0x60, 1, 2, 3}
	if err := tunnel.Inject(ctx, outbound); err != nil {
		t.Fatal(err)
	}
	outbound[1] = 99
	buffer := make([]byte, 64)
	sizes := make([]int, 1)
	n, err := tunnel.ReadBatch(ctx, [][]byte{buffer}, sizes)
	if err != nil || n != 1 {
		t.Fatalf("ReadBatch = %d, %v", n, err)
	}
	if got := buffer[:sizes[0]]; got[1] != 1 {
		t.Fatalf("ReadBatch packet was not detached: %v", got)
	}

	inbound := []byte{0x45, 4, 5, 6}
	if n, err := tunnel.WriteBatch(ctx, [][]byte{inbound}); err != nil || n != 1 {
		t.Fatalf("WriteBatch = %d, %v", n, err)
	}
	inbound[1] = 99
	got, err := tunnel.ReceiveWritten(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got[1] != 4 {
		t.Fatalf("WriteBatch packet was not detached: %v", got)
	}
}

func TestMemoryDatagramCopiesPayloadAndTracksRebind(t *testing.T) {
	ctx := context.Background()
	transport := NewMemoryDatagram()
	network := photonclient.NetworkHandle{ID: "wifi", InterfaceIndex: 7}
	if err := transport.Rebind(ctx, network); err != nil {
		t.Fatal(err)
	}
	if got := transport.Network(); got != network {
		t.Fatalf("Network = %#v", got)
	}

	peer := photonclient.PeerEndpoint{Address: netip.MustParseAddrPort("192.0.2.1:4500")}
	payload := []byte{1, 2, 3}
	if err := transport.Send(ctx, peer, [][]byte{payload}); err != nil {
		t.Fatal(err)
	}
	payload[0] = 9
	got, err := transport.ReceiveSent(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got.Payload[0] != 1 || got.Peer != peer {
		t.Fatalf("sent datagram = %#v", got)
	}
}
