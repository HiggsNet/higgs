// Package photonclient contains the platform-independent Photon leaf client.
// Platform adapters own operating-system resources and inject them through the
// contracts in this file.
package photonclient

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
)

// TunnelMetadata identifies an injected L3 tunnel without exposing a
// platform-specific handle to the portable core.
type TunnelMetadata struct {
	Name      string
	MTU       int
	NetworkID string
}

// TunnelDevice exchanges complete IPv4 or IPv6 packets with the host stack.
// Ownership transfers to Runtime after a successful Start call.
type TunnelDevice interface {
	Metadata() TunnelMetadata
	ReadBatch(ctx context.Context, buffers [][]byte, sizes []int) (int, error)
	WriteBatch(ctx context.Context, packets [][]byte) (int, error)
	Close() error
}

// NetworkHandle is an opaque platform network identity used when rebinding an
// underlay transport. Portable code must not interpret ID or InterfaceIndex.
type NetworkHandle struct {
	ID             string
	InterfaceIndex uint32
}

// PeerEndpoint is a verified candidate endpoint plus its selected underlay.
type PeerEndpoint struct {
	Address netip.AddrPort
	Network NetworkHandle
}

// Datagram is one received UDP payload and its remote endpoint.
type Datagram struct {
	Peer    PeerEndpoint
	Payload []byte
}

// DatagramTransport owns the shared UDP socket used for both IKE and ESP.
type DatagramTransport interface {
	Send(ctx context.Context, peer PeerEndpoint, packets [][]byte) error
	Receive(ctx context.Context) (Datagram, error)
	Rebind(ctx context.Context, network NetworkHandle) error
	Close() error
}

// NetworkChange describes an underlay change without embedding a Windows or
// Android API object in portable state.
type NetworkChange struct {
	Network NetworkHandle
	MTU     int
	Reason  string
}

// NetworkObserver publishes event-driven underlay changes.
type NetworkObserver interface {
	Current(ctx context.Context) (NetworkChange, error)
	Changes() <-chan NetworkChange
	Close() error
}

// StateSnapshot is detached verified Photon state. Network and all reachable
// mutable fields must not be changed after publication.
type StateSnapshot struct {
	Revision           uint64
	ManagedZone        zone.ZonePath
	Network            *zone.NetworkState
	IdentityPrivateKey ed25519.PrivateKey
}

// StateSource supplies verified state; raw network objects must pass Photon
// verification before appearing here.
type StateSource interface {
	Snapshot(ctx context.Context) (StateSnapshot, error)
	Changes() <-chan uint64
	Close() error
}

// Timer is the subset needed by protocol state machines and manual tests.
type Timer interface {
	C() <-chan time.Time
	Reset(after time.Duration) bool
	Stop() bool
}

// Clock prevents protocol packages from scattering untestable time.Tick calls.
type Clock interface {
	Now() time.Time
	NewTimer(after time.Duration) Timer
}

// Resources is the complete platform capability set for the first runtime.
// A future narrow slice may make a capability optional, but absence must never
// be inferred silently.
type Resources struct {
	Tunnel   TunnelDevice
	Datagram DatagramTransport
	Networks NetworkObserver
	States   StateSource
	Clock    Clock
}

// Validate rejects partial platform wiring before any workload starts.
func (r Resources) Validate() error {
	var missing []string
	if r.Tunnel == nil {
		missing = append(missing, "tunnel")
	}
	if r.Datagram == nil {
		missing = append(missing, "datagram")
	}
	if r.Networks == nil {
		missing = append(missing, "network observer")
	}
	if r.States == nil {
		missing = append(missing, "state source")
	}
	if r.Clock == nil {
		missing = append(missing, "clock")
	}
	if len(missing) != 0 {
		return fmt.Errorf("photon client resources incomplete: %v", missing)
	}
	meta := r.Tunnel.Metadata()
	if meta.Name == "" {
		return errors.New("photon client tunnel name is empty")
	}
	if meta.MTU < 1280 || meta.MTU > 65535 {
		return fmt.Errorf("photon client tunnel MTU %d is outside [1280, 65535]", meta.MTU)
	}
	return nil
}
