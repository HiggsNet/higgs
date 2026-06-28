package health

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strings"
	"time"
)

// CommandRunner abstracts running a command in a netns for testing.
type CommandRunner interface {
	Run(ctx context.Context, name string, args []string) ([]byte, error)
}

// ExecRunner runs commands via os/exec.
type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, name string, args []string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	return cmd.CombinedOutput()
}

// ICMProber implements Prober using ICMP echo. It requires CAP_NET_RAW (or
// a ping binary with the needed capability/setuid setup). Probes are dispatched
// in the target netns and bind to the source/interface when possible.
type ICMProber struct {
	runner CommandRunner
}

// NewICMProber creates an ICMP prober. The fallback argument is retained for
// API compatibility, but ICMP failures are reported directly because UDP probe
// requires an explicit peer listener/capability to avoid false positives.
func NewICMProber(runner CommandRunner, _ Prober) *ICMProber {
	if runner == nil {
		runner = ExecRunner{}
	}
	return &ICMProber{runner: runner}
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
	args = append(args, "ping")
	if target.PeerTunnelAddr.Is6() {
		args = append(args, "-6")
	}
	args = append(args, "-n", "-c", "1")
	if source := pingSourceAddress(target); source != "" {
		args = append(args, "-I", source)
	}
	args = append(args, pingTargetAddress(target))
	start := time.Now()
	if out, err := p.runner.Run(deadline, "ip", args); err != nil {
		if msg := strings.TrimSpace(string(out)); msg != "" {
			return 0, fmt.Errorf("%w: %s", err, msg)
		}
		return 0, err
	}
	return time.Since(start), nil
}

func pingTargetAddress(target ProbeTarget) string {
	addr := target.PeerTunnelAddr.String()
	if target.PeerTunnelAddr.Is6() && target.PeerTunnelAddr.IsLinkLocalUnicast() && target.InterfaceName != "" && !strings.Contains(addr, "%") {
		addr += "%" + target.InterfaceName
	}
	return addr
}

func pingSourceAddress(target ProbeTarget) string {
	if target.LocalTunnelAddr.IsValid() {
		addr := target.LocalTunnelAddr.String()
		if target.LocalTunnelAddr.Is6() && target.LocalTunnelAddr.IsLinkLocalUnicast() && target.InterfaceName != "" && !strings.Contains(addr, "%") {
			addr += "%" + target.InterfaceName
		}
		return addr
	}
	return target.InterfaceName
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
