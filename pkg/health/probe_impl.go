package health

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"regexp"
	"strconv"
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

const pingBurstInterval = 200 * time.Millisecond

var (
	pingReplyTimePattern = regexp.MustCompile(`time[=<]([0-9]+(?:\.[0-9]+)?)\s*ms`)
	pingReceivedPattern  = regexp.MustCompile(`(?:^|[,\s])(\d+)\s+(?:packets?\s+)?received(?:[,\s]|$)`)
)

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
	received, lastRTT, err := p.pingBurstExec(ctx, target, cfg.Timeout, burst)
	if err != nil {
		return ProbeResult{InstanceID: target.InstanceID, Error: err.Error()}
	}
	if received == 0 {
		return ProbeResult{InstanceID: target.InstanceID, Error: "ping returned no replies"}
	}
	// Preserve the previous burst policy: a partial burst is healthy only when
	// more than half of the packets succeeded.
	return ProbeResult{
		InstanceID: target.InstanceID,
		RTT:        lastRTT,
		Success:    received > burst-received,
	}
}

// pingBurstExec executes one ping process for a whole probe burst. Starting a
// separate `ip netns exec ping -c 1` process for every packet is expensive:
// each invocation forks, enters the netns and performs mount setup.
func (p *ICMProber) pingBurstExec(ctx context.Context, target ProbeTarget, timeout time.Duration, burst int) (int, time.Duration, error) {
	if timeout <= 0 {
		timeout = time.Second
	}
	if burst <= 0 {
		burst = 1
	}
	run := func(includeSource bool) (int, time.Duration, []byte, error) {
		// The old implementation allowed one timeout per ping. Keep that total
		// budget while issuing the burst through a single process.
		deadline, cancel := context.WithTimeout(ctx, timeout*time.Duration(burst))
		defer cancel()
		start := time.Now()
		out, err := p.runner.Run(deadline, "ip", pingArgsForCount(target, includeSource, burst))
		received, lastRTT := parsePingBurstOutput(out)
		if received == 0 && err == nil {
			// Successful ping implementations always report replies, but tolerate
			// wrappers whose stdout is intentionally suppressed.
			received = burst
			lastRTT = time.Since(start)
		}
		return received, lastRTT, out, err
	}
	received, lastRTT, out, err := run(true)
	if err != nil && shouldRetryWithoutPingSource(target, out) {
		received, lastRTT, out, err = run(false)
	}
	if received > 0 {
		return received, lastRTT, nil
	}
	if err != nil {
		return 0, 0, pingExecError(err, out)
	}
	return 0, 0, fmt.Errorf("ping returned no replies")
}

func parsePingBurstOutput(out []byte) (int, time.Duration) {
	text := string(out)
	var lastRTT time.Duration
	replies := pingReplyTimePattern.FindAllStringSubmatch(text, -1)
	for _, match := range replies {
		milliseconds, err := strconv.ParseFloat(match[1], 64)
		if err != nil || milliseconds < 0 {
			continue
		}
		lastRTT = time.Duration(milliseconds * float64(time.Millisecond))
	}
	if matches := pingReceivedPattern.FindStringSubmatch(text); len(matches) == 2 {
		if received, err := strconv.Atoi(matches[1]); err == nil && received >= 0 {
			return received, lastRTT
		}
	}
	return len(replies), lastRTT
}

func pingArgs(target ProbeTarget, includeSource bool) []string {
	return pingArgsForCount(target, includeSource, 1)
}

func pingArgsForCount(target ProbeTarget, includeSource bool, count int) []string {
	if count <= 0 {
		count = 1
	}
	args := []string{}
	if target.NetNS != "" {
		args = append(args, "netns", "exec", target.NetNS)
	}
	args = append(args, "ping")
	if target.PeerTunnelAddr.Is6() {
		args = append(args, "-6")
	}
	args = append(args, "-n", "-c", strconv.Itoa(count))
	if count > 1 {
		args = append(args, "-i", formatPingBurstInterval(pingBurstInterval))
	}
	if source := pingSourceAddress(target); includeSource && source != "" {
		args = append(args, "-I", source)
	}
	args = append(args, pingTargetAddress(target))
	return args
}

func formatPingBurstInterval(interval time.Duration) string {
	return strconv.FormatFloat(interval.Seconds(), 'f', -1, 64)
}

func pingExecError(err error, out []byte) error {
	if msg := strings.TrimSpace(string(out)); msg != "" {
		return fmt.Errorf("%w: %s", err, msg)
	}
	return err
}

func shouldRetryWithoutPingSource(target ProbeTarget, out []byte) bool {
	return target.PeerTunnelAddr.Is6() &&
		target.PeerTunnelAddr.IsLinkLocalUnicast() &&
		target.InterfaceName != "" &&
		strings.Contains(string(out), "bind icmp socket: Invalid argument")
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
