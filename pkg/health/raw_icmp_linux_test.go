//go:build linux

package health

import (
	"context"
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

func TestRawICMProberUsesWorkerAndPreservesBurstMajority(t *testing.T) {
	worker := &fakeRawICMPWorker{result: rawProbeResult{received: 2, lastRTT: 4 * time.Millisecond}}
	p := NewRawICMProber(nil)
	p.new = func(netns string) (rawICMPWorker, error) {
		if netns != "mesh-a" {
			t.Fatalf("worker netns = %q, want mesh-a", netns)
		}
		return worker, nil
	}
	target := ProbeTarget{InstanceID: "link-a", NetNS: "mesh-a", PeerTunnelAddr: netip.MustParseAddr("192.0.2.2")}
	got := p.Probe(context.Background(), target, ProbeConfig{Burst: 3})
	if !got.Success || got.RTT != 4*time.Millisecond || got.Error != "" {
		t.Fatalf("probe result = %+v, want successful majority result", got)
	}
	if worker.calls != 1 {
		t.Fatalf("worker calls = %d, want 1", worker.calls)
	}
	// The namespace worker is cached rather than recreated for every probe.
	_ = p.Probe(context.Background(), target, ProbeConfig{Burst: 3})
	if worker.calls != 2 {
		t.Fatalf("worker calls after second probe = %d, want 2", worker.calls)
	}
}

func TestRawICMProberFallsBackOnlyForLocalSetupFailure(t *testing.T) {
	fallback := &countingRawFallback{}
	worker := &fakeRawICMPWorker{result: rawProbeResult{err: errors.New("operation not permitted"), unavailable: true}}
	var reportedTarget ProbeTarget
	var reportedErr error
	p := NewRawICMProber(fallback, func(target ProbeTarget, err error) {
		reportedTarget = target
		reportedErr = err
	})
	p.new = func(string) (rawICMPWorker, error) { return worker, nil }
	target := ProbeTarget{InstanceID: "link-a", PeerTunnelAddr: netip.MustParseAddr("192.0.2.2")}
	if got := p.Probe(context.Background(), target, ProbeConfig{}); !got.Success {
		t.Fatalf("fallback result = %+v, want success", got)
	}
	if fallback.calls != 1 {
		t.Fatalf("fallback calls = %d, want 1", fallback.calls)
	}
	if reportedTarget.InstanceID != target.InstanceID || reportedErr == nil || reportedErr.Error() != "operation not permitted" {
		t.Fatalf("fallback report = (%+v, %v), want target and raw setup error", reportedTarget, reportedErr)
	}

	worker.result = rawProbeResult{err: errors.New("network is unreachable")}
	reportedErr = nil
	got := p.Probe(context.Background(), target, ProbeConfig{})
	if got.Error != "network is unreachable" {
		t.Fatalf("network error = %q, want raw packet error", got.Error)
	}
	if fallback.calls != 1 {
		t.Fatalf("fallback calls after packet error = %d, want 1", fallback.calls)
	}
	if reportedErr != nil {
		t.Fatalf("packet error unexpectedly reported as fallback: %v", reportedErr)
	}
}

func TestRawICMProberFallsBackWhenNamespaceWorkerCannotStart(t *testing.T) {
	fallback := &countingRawFallback{}
	p := NewRawICMProber(fallback)
	p.new = func(string) (rawICMPWorker, error) {
		return nil, errors.New("setns: operation not permitted")
	}
	target := ProbeTarget{InstanceID: "link-a", NetNS: "mesh-a", PeerTunnelAddr: netip.MustParseAddr("192.0.2.2")}
	if got := p.Probe(context.Background(), target, ProbeConfig{}); !got.Success {
		t.Fatalf("fallback result = %+v, want success", got)
	}
	if fallback.calls != 1 {
		t.Fatalf("fallback calls = %d, want 1", fallback.calls)
	}
}

func TestParseRawICMPReply(t *testing.T) {
	v4 := make([]byte, 20+8)
	v4[0] = 0x45
	v4[20] = 0 // echo reply
	v4[24], v4[25] = 0x12, 0x34
	v4[26], v4[27] = 0x00, 0x09
	if seq, ok := parseRawICMPReply(v4, 2, 0x1234); !ok || seq != 9 {
		t.Fatalf("IPv4 reply = (%d, %t), want (9, true)", seq, ok)
	}
	v6 := []byte{129, 0, 0, 0, 0xab, 0xcd, 0x00, 0x0a}
	if seq, ok := parseRawICMPReply(v6, 10, 0xabcd); !ok || seq != 10 {
		t.Fatalf("IPv6 reply = (%d, %t), want (10, true)", seq, ok)
	}
}

func TestMakeICMPEchoPacketHasValidIPv4Checksum(t *testing.T) {
	packet := makeICMPEchoPacket(2, 0x1234, 0x5678)
	if packet[0] != 8 || internetChecksum(packet) != 0 {
		t.Fatalf("IPv4 echo packet = %x, want echo request with valid checksum", packet)
	}
}

type fakeRawICMPWorker struct {
	result rawProbeResult
	calls  int
}

func (w *fakeRawICMPWorker) probe(context.Context, ProbeTarget, ProbeConfig, uint16, *atomic.Uint32) rawProbeResult {
	w.calls++
	return w.result
}

func (w *fakeRawICMPWorker) close() {}

type countingRawFallback struct{ calls int }

func (p *countingRawFallback) Probe(_ context.Context, target ProbeTarget, _ ProbeConfig) ProbeResult {
	p.calls++
	return ProbeResult{InstanceID: target.InstanceID, RTT: 2 * time.Millisecond, Success: true}
}

func (*countingRawFallback) Type() string { return ProbeTypeICMP }
