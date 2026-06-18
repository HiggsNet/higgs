package health

import (
	"context"
	"net/netip"
	"time"
)

// ProbeResult is the outcome of a single probe attempt.
type ProbeResult struct {
	InstanceID string
	RTT        time.Duration
	Success    bool
	Error      string // raw error string, NOT used as a metrics label
}

// Prober executes active probes. Implementations include ICMP echo and UDP
// keepalive. Probes must run in the overlay/data-plane netns and bind to the
// corresponding XFRM interface or source tunnel address.
type Prober interface {
	// Probe sends a burst of probe packets and returns the aggregate result.
	Probe(ctx context.Context, target ProbeTarget, cfg ProbeConfig) ProbeResult
	// Type returns the probe type identifier (icmp/udp).
	Type() string
}

// ProbeRunner executes individual probe packets for a Prober.
type ProbeRunner interface {
	PingOnce(ctx context.Context, src, dst netip.Addr, iface string, netns string, timeout time.Duration) (time.Duration, error)
}

// nopProber is a no-op prober used as the default; the daemon injects the real
// implementation (ICMP/UDP) when capabilities allow.
type nopProber struct{}

func (nopProber) Probe(ctx context.Context, target ProbeTarget, cfg ProbeConfig) ProbeResult {
	return ProbeResult{InstanceID: target.InstanceID, Success: false, Error: "no prober configured"}
}

func (nopProber) Type() string { return ProbeTypeICMP }
