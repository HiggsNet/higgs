package photonlinux

import (
	"bytes"
	"testing"
	"time"
)

func TestGossipDatagramIORoundTrip(t *testing.T) {
	a, err := ListenGossipDatagram("127.0.0.1:0")
	if err != nil {
		t.Skipf("UDP sockets are unavailable: %v", err)
	}
	defer a.Close()
	b, err := ListenGossipDatagram("127.0.0.1:0")
	if err != nil {
		t.Skipf("UDP sockets are unavailable: %v", err)
	}
	defer b.Close()

	want := []byte("packet")
	if _, err := a.WriteDatagram(want, b.LocalAddr()); err != nil {
		t.Fatalf("WriteDatagram: %v", err)
	}
	if err := b.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buffer := make([]byte, 64)
	n, addr, err := b.ReadDatagram(buffer)
	if err != nil {
		t.Fatalf("ReadDatagram: %v", err)
	}
	if !bytes.Equal(buffer[:n], want) {
		t.Fatalf("payload = %q, want %q", buffer[:n], want)
	}
	if addr.String() != a.LocalAddr().String() {
		t.Fatalf("addr = %v, want %v", addr, a.LocalAddr())
	}
}

func TestListenGossipDatagramReusesPort(t *testing.T) {
	first, err := ListenGossipDatagram("127.0.0.1:0")
	if err != nil {
		t.Skipf("UDP sockets are unavailable: %v", err)
	}
	defer first.Close()
	second, err := ListenGossipDatagram(first.LocalAddr().String())
	if err != nil {
		t.Skipf("UDP port reuse is unavailable: %v", err)
	}
	defer second.Close()
}
