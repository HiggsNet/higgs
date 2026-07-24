//go:build linux

package health

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// RawICMProber sends echo requests through raw sockets. A worker is pinned to
// one OS thread for every target network namespace: switching a Go thread with
// setns is thread-local, so it must never be returned to the runtime pool.
// Sockets are cached by source/interface inside that worker.
//
// If raw sockets or setns are unavailable, Probe delegates to fallback. This
// makes CAP_NET_RAW/CAP_SYS_ADMIN deployment mistakes non-disruptive while
// still making the efficient path the normal case.
type RawICMProber struct {
	fallback       Prober
	reportFallback RawICMPFallbackReporter

	mu      sync.Mutex
	workers map[string]rawICMPWorker
	new     func(string) (rawICMPWorker, error)
	nextSeq atomic.Uint32
	id      uint16
}

// RawICMPFallbackReporter observes local raw-ICMP setup failures before the
// portable fallback prober is used. Callers should rate-limit any logging.
type RawICMPFallbackReporter func(ProbeTarget, error)

type rawICMPWorker interface {
	probe(context.Context, ProbeTarget, ProbeConfig, uint16, *atomic.Uint32) rawProbeResult
	close()
}

type rawProbeResult struct {
	received int
	lastRTT  time.Duration
	err      error
	// unavailable is reserved for local setup failures. Packet send failures
	// and timeouts must not cause a second exec-based probe.
	unavailable bool
}

// NewRawICMProber creates the preferred in-process ICMP prober. fallback is
// normally NewICMProber; nil means setup errors are returned to the caller.
// The optional reporter observes fallback reasons for low-volume diagnostics.
func NewRawICMProber(fallback Prober, reporters ...RawICMPFallbackReporter) *RawICMProber {
	p := &RawICMProber{
		fallback: fallback,
		workers:  make(map[string]rawICMPWorker),
		new:      newRawICMPWorker,
		id:       uint16(time.Now().UnixNano()),
	}
	if len(reporters) > 0 {
		p.reportFallback = reporters[0]
	}
	return p
}

func (p *RawICMProber) Type() string { return ProbeTypeICMP }

func (p *RawICMProber) Probe(ctx context.Context, target ProbeTarget, cfg ProbeConfig) ProbeResult {
	if !target.PeerTunnelAddr.IsValid() {
		return ProbeResult{InstanceID: target.InstanceID, Error: "peer address missing"}
	}
	worker, err := p.worker(target.NetNS)
	if err != nil {
		return p.fallbackOrError(ctx, target, cfg, err)
	}
	result := worker.probe(ctx, target, cfg, p.id, &p.nextSeq)
	if result.unavailable {
		return p.fallbackOrError(ctx, target, cfg, result.err)
	}
	if result.err != nil {
		return ProbeResult{InstanceID: target.InstanceID, Error: result.err.Error()}
	}
	if result.received == 0 {
		return ProbeResult{InstanceID: target.InstanceID, Error: "raw ICMP returned no replies"}
	}
	burst := cfg.Burst
	if burst <= 0 {
		burst = 3
	}
	return ProbeResult{
		InstanceID: target.InstanceID,
		RTT:        result.lastRTT,
		Success:    result.received > burst-result.received,
	}
}

func (p *RawICMProber) fallbackOrError(ctx context.Context, target ProbeTarget, cfg ProbeConfig, rawErr error) ProbeResult {
	if p.fallback != nil {
		if p.reportFallback != nil {
			p.reportFallback(target, rawErr)
		}
		return p.fallback.Probe(ctx, target, cfg)
	}
	return ProbeResult{InstanceID: target.InstanceID, Error: rawErr.Error()}
}

func (p *RawICMProber) worker(netns string) (rawICMPWorker, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if worker := p.workers[netns]; worker != nil {
		return worker, nil
	}
	worker, err := p.new(netns)
	if err != nil {
		return nil, err
	}
	p.workers[netns] = worker
	return worker, nil
}

// Close releases the cached raw sockets. It is mainly useful for tests and
// short-lived callers; the daemon process also releases them on exit.
func (p *RawICMProber) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, worker := range p.workers {
		worker.close()
	}
	p.workers = make(map[string]rawICMPWorker)
}

type rawICMPJob struct {
	ctx    context.Context
	target ProbeTarget
	cfg    ProbeConfig
	id     uint16
	seq    *atomic.Uint32
	result chan rawProbeResult
}

type rawICMPNamespaceWorker struct {
	netns string
	jobs  chan rawICMPJob
	done  chan struct{}
	mu    sync.RWMutex
	once  sync.Once
}

func newRawICMPWorker(netns string) (rawICMPWorker, error) {
	w := &rawICMPNamespaceWorker{
		netns: netns,
		jobs:  make(chan rawICMPJob),
		done:  make(chan struct{}),
	}
	ready := make(chan error, 1)
	go w.run(ready)
	if err := <-ready; err != nil {
		return nil, err
	}
	return w, nil
}

func (w *rawICMPNamespaceWorker) run(ready chan<- error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	var restoreFD, targetFD int = -1, -1
	var err error
	if w.netns != "" {
		restoreFD, err = unix.Open("/proc/self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err == nil {
			targetFD, err = unix.Open(netNSPath(w.netns), unix.O_RDONLY|unix.O_CLOEXEC, 0)
		}
		if err == nil {
			err = unix.Setns(targetFD, unix.CLONE_NEWNET)
		}
	}
	if err != nil {
		if targetFD >= 0 {
			_ = unix.Close(targetFD)
		}
		if restoreFD >= 0 {
			_ = unix.Close(restoreFD)
		}
		ready <- fmt.Errorf("enter network namespace %q for raw ICMP: %w", w.netns, err)
		close(w.done)
		return
	}
	ready <- nil

	sockets := make(map[rawSocketKey]int)
	defer func() {
		for _, fd := range sockets {
			_ = unix.Close(fd)
		}
		if restoreFD >= 0 {
			_ = unix.Setns(restoreFD, unix.CLONE_NEWNET)
			_ = unix.Close(restoreFD)
		}
		if targetFD >= 0 {
			_ = unix.Close(targetFD)
		}
		close(w.done)
	}()

	for job := range w.jobs {
		job.result <- probeRawICMP(job, sockets)
	}
}

func (w *rawICMPNamespaceWorker) probe(ctx context.Context, target ProbeTarget, cfg ProbeConfig, id uint16, seq *atomic.Uint32) rawProbeResult {
	// Do not let Close race a channel send. Holding the read lock through the
	// result also makes Close wait for the in-flight probe to release its raw
	// socket on the owning OS thread.
	w.mu.RLock()
	defer w.mu.RUnlock()
	job := rawICMPJob{ctx: ctx, target: target, cfg: cfg, id: id, seq: seq, result: make(chan rawProbeResult, 1)}
	select {
	case w.jobs <- job:
	case <-ctx.Done():
		return rawProbeResult{err: ctx.Err()}
	case <-w.done:
		return rawProbeResult{err: fmt.Errorf("raw ICMP worker for network namespace %q stopped", w.netns), unavailable: true}
	}
	select {
	case result := <-job.result:
		return result
	case <-ctx.Done():
		return rawProbeResult{err: ctx.Err()}
	case <-w.done:
		return rawProbeResult{err: fmt.Errorf("raw ICMP worker for network namespace %q stopped", w.netns), unavailable: true}
	}
}

func (w *rawICMPNamespaceWorker) close() {
	w.once.Do(func() {
		w.mu.Lock()
		close(w.jobs)
		w.mu.Unlock()
		<-w.done
	})
}

type rawSocketKey struct {
	family int
	source netip.Addr
	iface  string
}

func probeRawICMP(job rawICMPJob, sockets map[rawSocketKey]int) rawProbeResult {
	burst := job.cfg.Burst
	if burst <= 0 {
		burst = 3
	}
	timeout := job.cfg.Timeout
	if timeout <= 0 {
		timeout = time.Second
	}
	key := rawSocketKey{source: job.target.LocalTunnelAddr, iface: job.target.InterfaceName}
	if job.target.PeerTunnelAddr.Is6() {
		key.family = unix.AF_INET6
	} else {
		key.family = unix.AF_INET
	}
	fd, ok := sockets[key]
	if !ok {
		var err error
		fd, err = openRawICMPSocket(key)
		if err != nil {
			return rawProbeResult{err: fmt.Errorf("open raw ICMP socket: %w", err), unavailable: true}
		}
		sockets[key] = fd
	}

	deadline := time.Now().Add(timeout * time.Duration(burst))
	if d, ok := job.ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	pending := make(map[uint16]time.Time, burst)
	var received int
	var lastRTT time.Duration
	drain := func() error {
		for {
			seq, ok := readRawICMPReply(fd, key.family, job.id)
			if !ok {
				return nil
			}
			if sent, known := pending[seq]; known {
				delete(pending, seq)
				received++
				lastRTT = time.Since(sent)
			}
		}
	}
	start := time.Now()
	for i := 0; i < burst; i++ {
		nextSend := start.Add(time.Duration(i) * pingBurstInterval)
		if err := waitRawICMP(job.ctx, fd, nextSend, drain); err != nil {
			return rawProbeResult{received: received, lastRTT: lastRTT, err: err}
		}
		sequence := uint16(job.seq.Add(1))
		packet := makeICMPEchoPacket(key.family, job.id, sequence)
		if err := unix.Sendto(fd, packet, 0, rawDestination(job.target, key.family)); err != nil {
			return rawProbeResult{received: received, lastRTT: lastRTT, err: fmt.Errorf("send raw ICMP echo: %w", err)}
		}
		pending[sequence] = time.Now()
	}
	if err := waitRawICMP(job.ctx, fd, deadline, drain); err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			return rawProbeResult{received: received, lastRTT: lastRTT}
		}
		return rawProbeResult{received: received, lastRTT: lastRTT, err: err}
	}
	return rawProbeResult{received: received, lastRTT: lastRTT}
}

func openRawICMPSocket(key rawSocketKey) (int, error) {
	protocol := unix.IPPROTO_ICMP
	if key.family == unix.AF_INET6 {
		protocol = unix.IPPROTO_ICMPV6
	}
	fd, err := unix.Socket(key.family, unix.SOCK_RAW|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, protocol)
	if err != nil {
		return -1, err
	}
	closeOnError := func(err error) (int, error) {
		_ = unix.Close(fd)
		return -1, err
	}
	if key.iface != "" {
		if err := unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, key.iface); err != nil {
			return closeOnError(err)
		}
	}
	if key.family == unix.AF_INET6 {
		// Linux calculates the ICMPv6 pseudo-header checksum at byte offset 2.
		// ICMPv6 raw sockets reject IPV6_CHECKSUM at the IPPROTO_IPV6 level;
		// Linux requires the SOL_RAW/IPPROTO_RAW level for this socket type.
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_RAW, unix.IPV6_CHECKSUM, 2); err != nil {
			return closeOnError(err)
		}
		addr := unix.SockaddrInet6{}
		if key.source.IsValid() {
			addr.Addr = key.source.As16()
		}
		if key.iface != "" {
			iface, err := interfaceIndex(key.iface)
			if err != nil {
				return closeOnError(err)
			}
			addr.ZoneId = uint32(iface)
		}
		if err := unix.Bind(fd, &addr); err != nil {
			return closeOnError(err)
		}
		return fd, nil
	}
	addr := unix.SockaddrInet4{}
	if key.source.IsValid() {
		addr.Addr = key.source.As4()
	}
	if err := unix.Bind(fd, &addr); err != nil {
		return closeOnError(err)
	}
	return fd, nil
}

func rawDestination(target ProbeTarget, family int) unix.Sockaddr {
	if family == unix.AF_INET6 {
		addr := unix.SockaddrInet6{Addr: target.PeerTunnelAddr.As16()}
		if target.InterfaceName != "" && target.PeerTunnelAddr.IsLinkLocalUnicast() {
			if index, err := interfaceIndex(target.InterfaceName); err == nil {
				addr.ZoneId = uint32(index)
			}
		}
		return &addr
	}
	return &unix.SockaddrInet4{Addr: target.PeerTunnelAddr.As4()}
}

func interfaceIndex(name string) (int, error) {
	iface, err := netInterfaceByName(name)
	if err != nil {
		return 0, err
	}
	return iface, nil
}

// netInterfaceByName is isolated to keep the raw socket code testable without
// a real namespace or privileged interface setup. net.InterfaceByName uses a
// netlink query, so after setns it resolves the interface in the worker's
// target network namespace (unlike relying on how /sys happens to be mounted).
var netInterfaceByName = func(name string) (int, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return 0, err
	}
	if iface.Index <= 0 {
		return 0, fmt.Errorf("invalid ifindex for %q", name)
	}
	return iface.Index, nil
}

func makeICMPEchoPacket(family int, id, seq uint16) []byte {
	packet := make([]byte, 8)
	if family == unix.AF_INET6 {
		packet[0] = 128 // ICMPv6 Echo Request
	} else {
		packet[0] = 8 // ICMP Echo Request
	}
	binary.BigEndian.PutUint16(packet[4:6], id)
	binary.BigEndian.PutUint16(packet[6:8], seq)
	if family == unix.AF_INET {
		binary.BigEndian.PutUint16(packet[2:4], internetChecksum(packet))
	}
	return packet
}

func internetChecksum(packet []byte) uint16 {
	var sum uint32
	for len(packet) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(packet[:2]))
		packet = packet[2:]
	}
	if len(packet) == 1 {
		sum += uint32(packet[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// readRawICMPReply returns one matching echo sequence. The socket is
// non-blocking; false means no more packets are currently available.
func readRawICMPReply(fd, family int, id uint16) (uint16, bool) {
	buf := make([]byte, 1500)
	for {
		n, _, err := unix.Recvfrom(fd, buf, unix.MSG_DONTWAIT)
		if err != nil || n == 0 {
			return 0, false
		}
		if seq, ok := parseRawICMPReply(buf[:n], family, id); ok {
			return seq, true
		}
	}
}

func parseRawICMPReply(packet []byte, family int, id uint16) (uint16, bool) {
	if family == unix.AF_INET && len(packet) >= 20 && packet[0]>>4 == 4 {
		headerLen := int(packet[0]&0x0f) * 4
		if headerLen > len(packet) {
			return 0, false
		}
		packet = packet[headerLen:]
	}
	if len(packet) < 8 {
		return 0, false
	}
	wantType := byte(0)
	if family == unix.AF_INET6 {
		wantType = 129
	}
	if packet[0] != wantType || packet[1] != 0 || binary.BigEndian.Uint16(packet[4:6]) != id {
		return 0, false
	}
	return binary.BigEndian.Uint16(packet[6:8]), true
}

func waitRawICMP(ctx context.Context, fd int, until time.Time, drain func() error) error {
	for {
		if err := drain(); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		remaining := time.Until(until)
		if remaining <= 0 {
			return nil
		}
		milliseconds := int((remaining + time.Millisecond - 1) / time.Millisecond)
		if milliseconds < 1 {
			milliseconds = 1
		}
		_, err := unix.Poll([]unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}, milliseconds)
		if err != nil && !errors.Is(err, syscall.EINTR) {
			return err
		}
	}
}

func netNSPath(netns string) string {
	if strings.ContainsRune(netns, '/') {
		return filepath.Clean(netns)
	}
	return filepath.Join("/var/run/netns", netns)
}
