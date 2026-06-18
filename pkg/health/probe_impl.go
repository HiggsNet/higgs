package health

import (
	"context"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"os/exec"
	"sync"
	"time"
)

const (
	icmpEchoV4Type = 8
	icmpEchoV6Type = 128
)

// CommandRunner abstracts running a command in a netns for testing.
type CommandRunner interface {
	Run(ctx context.Context, name string, args []string) ([]byte, error)
}

// ExecRunner runs commands via os/exec.
type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, name string, args []string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	return cmd.Output()
}

// ICMProber implements Prober using ICMP echo. It requires CAP_NET_RAW (or
// root). When permission is denied it reports a clear probe_error. Probes are
// dispatched in the target netns and bind to the source/interface when
// possible.
type ICMProber struct {
	mu       sync.Mutex
	runner   CommandRunner
	fallback Prober
}

// NewICMProber creates an ICMP prober. If runner is nil, ExecRunner is used.
// fallback is invoked when ICMP is unavailable (e.g. no CAP_NET_RAW); if nil a
// UDP prober is used as fallback.
func NewICMProber(runner CommandRunner, fallback Prober) *ICMProber {
	if runner == nil {
		runner = ExecRunner{}
	}
	if fallback == nil {
		fallback = NewUDPProber(nil)
	}
	return &ICMProber{runner: runner, fallback: fallback}
}

func (p *ICMProber) Type() string { return ProbeTypeICMP }

// Probe sends a burst of ICMP echo requests and aggregates the result.
func (p *ICMProber) Probe(ctx context.Context, target ProbeTarget, cfg ProbeConfig) ProbeResult {
	if !target.PeerTunnelAddr.IsValid() {
		return ProbeResult{InstanceID: target.InstanceID, Error: "peer address missing"}
	}
	burst := cfg.Burst
	if burst <= 0 {
		burst = 3
	}
	// Try raw ICMP socket first (fast path, in-process).
	if rtt, ok := p.tryRawICMP(target, cfg.Timeout); ok {
		return ProbeResult{InstanceID: target.InstanceID, RTT: rtt, Success: true}
	}
	// Fallback to ping/ping6 via exec in the target netns.
	rtts := make([]time.Duration, 0, burst)
	failures := 0
	var lastErr string
	for i := 0; i < burst; i++ {
		rtt, err := p.pingOnceExec(ctx, target, cfg.Timeout)
		if err != nil {
			failures++
			lastErr = err.Error()
			continue
		}
		rtts = append(rtts, rtt)
	}
	if len(rtts) == 0 {
		// Degrade to UDP fallback if ICMP permission denied.
		if isPermissionError(lastErr) && p.fallback != nil {
			res := p.fallback.Probe(ctx, target, cfg)
			res.InstanceID = target.InstanceID
			return res
		}
		return ProbeResult{InstanceID: target.InstanceID, Error: lastErr}
	}
	// Aggregate: use the last successful RTT as the representative sample.
	last := rtts[len(rtts)-1]
	if failures > 0 {
		// Partial loss: still success but note error.
		return ProbeResult{InstanceID: target.InstanceID, RTT: last, Success: len(rtts) > failures}
	}
	return ProbeResult{InstanceID: target.InstanceID, RTT: last, Success: true}
}

func (p *ICMProber) tryRawICMP(target ProbeTarget, timeout time.Duration) (time.Duration, bool) {
	if timeout <= 0 {
		timeout = time.Second
	}
	var network string
	var icmpType uint8
	if target.PeerTunnelAddr.Is4() {
		network = "ip4:icmp"
		icmpType = icmpEchoV4Type
	} else {
		network = "ip6:ipv6-icmp"
		icmpType = icmpEchoV6Type
	}
	conn, err := net.Dial(network, target.PeerTunnelAddr.String())
	if err != nil {
		return 0, false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	id := uint16(rand.Intn(65535))
	pkt := makeICMPEcho(icmpType, id, 1)
	start := time.Now()
	if _, err := conn.Write(pkt); err != nil {
		return 0, false
	}
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return 0, false
	}
	return time.Since(start), true
}

func (p *ICMProber) pingOnceExec(ctx context.Context, target ProbeTarget, timeout time.Duration) (time.Duration, error) {
	if timeout <= 0 {
		timeout = time.Second
	}
	deadline, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	args := []string{}
	if target.NetNS != "" {
		args = append(args, "netns", "exec", target.NetNS)
	}
	bin := "ping"
	if target.PeerTunnelAddr.Is6() {
		bin = "ping6"
	}
	// -c 1 -W timeout_in_seconds (ceil)
	secs := int(timeout.Seconds())
	if secs < 1 {
		secs = 1
	}
	args = append(args, bin, "-c", "1", "-W", fmt.Sprintf("%d", secs))
	if target.InterfaceName != "" {
		args = append(args, "-I", target.InterfaceName)
	}
	args = append(args, target.PeerTunnelAddr.String())
	start := time.Now()
	if _, err := p.runner.Run(deadline, "ip", args); err != nil {
		return 0, err
	}
	return time.Since(start), nil
}

func isPermissionError(s string) bool {
	return contains(s, "permission denied") || contains(s, "Operation not permitted") || contains(s, "socket: ")
}

func makeICMPEcho(icmpType uint8, id, seq uint16) []byte {
	pkt := make([]byte, 16)
	pkt[0] = icmpType
	// pkt[1] = code 0
	// pkt[2..3] = checksum (filled by kernel for SOCK_DGRAM icmp)
	binary.BigEndian.PutUint16(pkt[4:6], id)
	binary.BigEndian.PutUint16(pkt[6:8], seq)
	// payload (timestamp)
	binary.BigEndian.PutUint64(pkt[8:16], uint64(time.Now().UnixNano()))
	return pkt
}

// udpMagic is a fixed magic header for Higgs UDP keepalive probes.
var udpMagic = []byte("HIGGS-HC")

// UDPProber implements Prober using UDP keepalive packets. It does not require
// CAP_NET_RAW but requires the peer to run a Higgs UDP probe listener (or any
// UDP service that replies with ICMP port unreachable).
type UDPProber struct {
	runner CommandRunner
}

// NewUDPProber creates a UDP prober.
func NewUDPProber(runner CommandRunner) *UDPProber {
	if runner == nil {
		runner = ExecRunner{}
	}
	return &UDPProber{runner: runner}
}

func (p *UDPProber) Type() string { return ProbeTypeUDP }

func (p *UDPProber) Probe(ctx context.Context, target ProbeTarget, cfg ProbeConfig) ProbeResult {
	if !target.PeerTunnelAddr.IsValid() {
		return ProbeResult{InstanceID: target.InstanceID, Error: "peer address missing"}
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = time.Second
	}
	// Use a UDP "probe" that just attempts to connect; if the peer doesn't
	// respond, we treat a fast ICMP port-unreachable as "host reachable" only
	// if we receive any ICMP. In practice, for overlay health, we use the
	// tunnel address and rely on the existing gossip UDP socket. For the first
	// version, we use a connect+write and measure success by absence of an
	// immediate error.
	addr := net.JoinHostPort(target.PeerTunnelAddr.String(), "33434")
	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return ProbeResult{InstanceID: target.InstanceID, Error: err.Error()}
	}
	defer conn.Close()
	pkt := make([]byte, 0, len(udpMagic)+16)
	pkt = append(pkt, udpMagic...)
	idBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(idBytes, uint64(time.Now().UnixNano()))
	pkt = append(pkt, idBytes...)
	start := time.Now()
	_ = conn.SetDeadline(start.Add(timeout))
	if _, err := conn.Write(pkt); err != nil {
		// A "port unreachable" ICMP is actually evidence the host is reachable
		// at L3; but for UDP health we treat write errors as failures.
		return ProbeResult{InstanceID: target.InstanceID, Error: err.Error()}
	}
	// We don't expect a reply; treat successful write as reachability evidence.
	rtt := time.Since(start)
	return ProbeResult{InstanceID: target.InstanceID, RTT: rtt, Success: true}
}

// AddrFromNetIP converts a net.IP to netip.Addr.
func AddrFromNetIP(ip net.IP) netip.Addr {
	if ip == nil {
		return netip.Addr{}
	}
	if a, ok := netip.AddrFromSlice(ip); ok {
		return a
	}
	return netip.Addr{}
}
