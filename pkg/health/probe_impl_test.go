package health

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestICMProberScopedLinkLocalUsesPortablePing(t *testing.T) {
	runner := &recordingCommandRunner{}
	prober := NewICMProber(runner, nil)
	target := ProbeTarget{
		InstanceID:      "link-1",
		NetNS:           "higgstesth2",
		InterfaceName:   "hgs431bcb9f",
		LocalTunnelAddr: netip.MustParseAddr("fe80::7888:86ec:66e0:2620"),
		PeerTunnelAddr:  netip.MustParseAddr("fe80::b09d:5f83:3e81:d064"),
		State:           "up",
	}

	result := prober.Probe(context.Background(), target, ProbeConfig{
		Timeout: 50 * time.Millisecond,
		Burst:   1,
	})
	if !result.Success {
		t.Fatalf("probe success = false, error=%q", result.Error)
	}
	if runner.name != "ip" {
		t.Fatalf("command name = %q, want ip", runner.name)
	}
	want := []string{
		"netns", "exec", "higgstesth2",
		"ping", "-6", "-n", "-c", "1",
		"-I", "fe80::7888:86ec:66e0:2620%hgs431bcb9f",
		"fe80::b09d:5f83:3e81:d064%hgs431bcb9f",
	}
	if !reflect.DeepEqual(runner.args, want) {
		t.Fatalf("command args = %#v, want %#v", runner.args, want)
	}
	for _, arg := range runner.args {
		if arg == "ping6" || arg == "-W" {
			t.Fatalf("command args include non-portable ping option: %#v", runner.args)
		}
	}
}

func TestICMProberIncludesPingOutputInError(t *testing.T) {
	runner := &recordingCommandRunner{
		out: []byte("connect: Network is unreachable\n"),
		err: errors.New("exit status 2"),
	}
	prober := NewICMProber(runner, nil)
	target := ProbeTarget{
		InstanceID:     "link-1",
		NetNS:          "higgstesth2",
		InterfaceName:  "hgs0",
		PeerTunnelAddr: netip.MustParseAddr("fe80::2"),
		State:          "up",
	}

	result := prober.Probe(context.Background(), target, ProbeConfig{
		Timeout: 50 * time.Millisecond,
		Burst:   1,
	})
	if result.Success {
		t.Fatal("probe success = true, want false")
	}
	if !strings.Contains(result.Error, "Network is unreachable") {
		t.Fatalf("probe error = %q, want ping output", result.Error)
	}
}

func TestICMProberRetriesScopedLinkLocalWithoutSourceOnBindInvalid(t *testing.T) {
	runner := &scriptedCommandRunner{
		results: []commandResult{
			{
				out: []byte("ping: bind icmp socket: Invalid argument\n"),
				err: errors.New("exit status 2"),
			},
			{},
		},
	}
	prober := NewICMProber(runner, nil)
	target := ProbeTarget{
		InstanceID:      "link-1",
		NetNS:           "higgstesth2",
		InterfaceName:   "hgs0",
		LocalTunnelAddr: netip.MustParseAddr("fe80::1"),
		PeerTunnelAddr:  netip.MustParseAddr("fe80::2"),
		State:           "up",
	}

	result := prober.Probe(context.Background(), target, ProbeConfig{
		Timeout: 50 * time.Millisecond,
		Burst:   1,
	})
	if !result.Success {
		t.Fatalf("probe success = false, error=%q", result.Error)
	}
	want := [][]string{
		{
			"netns", "exec", "higgstesth2",
			"ping", "-6", "-n", "-c", "1",
			"-I", "fe80::1%hgs0",
			"fe80::2%hgs0",
		},
		{
			"netns", "exec", "higgstesth2",
			"ping", "-6", "-n", "-c", "1",
			"fe80::2%hgs0",
		},
	}
	if !reflect.DeepEqual(runner.calls, want) {
		t.Fatalf("command calls = %#v, want %#v", runner.calls, want)
	}
}

func TestICMProberRunsBurstInOneProcess(t *testing.T) {
	runner := &recordingCommandRunner{out: []byte(`64 bytes from 192.0.2.2: icmp_seq=1 ttl=64 time=1.25 ms
64 bytes from 192.0.2.2: icmp_seq=2 ttl=64 time=2.50 ms
64 bytes from 192.0.2.2: icmp_seq=3 ttl=64 time=3.75 ms
3 packets transmitted, 3 received, 0% packet loss
`)}
	prober := NewICMProber(runner, nil)
	target := ProbeTarget{
		InstanceID:     "link-1",
		NetNS:          "higgstesth2",
		PeerTunnelAddr: netip.MustParseAddr("192.0.2.2"),
		State:          "up",
	}

	result := prober.Probe(context.Background(), target, ProbeConfig{Timeout: time.Second, Burst: 3})
	if !result.Success {
		t.Fatalf("probe success = false, error=%q", result.Error)
	}
	if result.RTT != 3750*time.Microsecond {
		t.Fatalf("probe RTT = %s, want 3.75ms", result.RTT)
	}
	want := []string{"netns", "exec", "higgstesth2", "ping", "-n", "-c", "3", "-i", "0.2", "192.0.2.2"}
	if !reflect.DeepEqual(runner.args, want) {
		t.Fatalf("command args = %#v, want %#v", runner.args, want)
	}
}

func TestICMProberBurstRequiresMajorityOfReplies(t *testing.T) {
	runner := &recordingCommandRunner{
		out: []byte(`64 bytes from 192.0.2.2: icmp_seq=1 ttl=64 time=1.25 ms
3 packets transmitted, 1 received, 66% packet loss
`),
		err: errors.New("exit status 1"),
	}
	prober := NewICMProber(runner, nil)
	target := ProbeTarget{InstanceID: "link-1", PeerTunnelAddr: netip.MustParseAddr("192.0.2.2"), State: "up"}

	result := prober.Probe(context.Background(), target, ProbeConfig{Timeout: time.Second, Burst: 3})
	if result.Success {
		t.Fatal("probe success = true, want false for one reply in a three-packet burst")
	}
	if result.Error != "" {
		t.Fatalf("probe error = %q, want partial loss without a command error", result.Error)
	}
}

func TestParsePingBurstOutput(t *testing.T) {
	received, lastRTT := parsePingBurstOutput([]byte(`3 packets transmitted, 2 packets received, 33% packet loss
64 bytes from 192.0.2.2: icmp_seq=1 ttl=64 time=0.125 ms
64 bytes from 192.0.2.2: icmp_seq=2 ttl=64 time<1 ms
`))
	if received != 2 {
		t.Fatalf("received = %d, want 2", received)
	}
	if lastRTT != time.Millisecond {
		t.Fatalf("last RTT = %s, want 1ms", lastRTT)
	}
}

func TestPingTargetAddressScopesLinkLocal(t *testing.T) {
	target := ProbeTarget{
		InstanceID:     "link-1",
		InterfaceName:  "hgs0",
		PeerTunnelAddr: netip.MustParseAddr("fe80::2"),
		State:          "up",
	}

	if got := pingTargetAddress(target); got != "fe80::2%hgs0" {
		t.Fatalf("ping target address = %q, want scoped link-local", got)
	}
}

func TestPingSourceAddressPrefersLocalTunnelAddressForLinkLocalTarget(t *testing.T) {
	target := ProbeTarget{
		InstanceID:      "link-1",
		InterfaceName:   "hgs0",
		LocalTunnelAddr: netip.MustParseAddr("fe80::1"),
		PeerTunnelAddr:  netip.MustParseAddr("fe80::2"),
		State:           "up",
	}

	if got := pingSourceAddress(target); got != "fe80::1%hgs0" {
		t.Fatalf("ping source address = %q, want scoped local tunnel address", got)
	}
}

func TestPingSourceAddressPrefersLocalTunnelAddressForNonLinkLocalTarget(t *testing.T) {
	target := ProbeTarget{
		InstanceID:      "link-1",
		InterfaceName:   "hgs0",
		LocalTunnelAddr: netip.MustParseAddr("fd00::1"),
		PeerTunnelAddr:  netip.MustParseAddr("fd00::2"),
		State:           "up",
	}

	if got := pingSourceAddress(target); got != "fd00::1" {
		t.Fatalf("ping source address = %q, want local tunnel address", got)
	}
}

func TestPingSourceAddressFallsBackToInterface(t *testing.T) {
	target := ProbeTarget{
		InstanceID:     "link-1",
		InterfaceName:  "hgs0",
		PeerTunnelAddr: netip.MustParseAddr("fe80::2"),
		State:          "up",
	}

	if got := pingSourceAddress(target); got != "hgs0" {
		t.Fatalf("ping source address = %q, want interface fallback", got)
	}
}

type recordingCommandRunner struct {
	name string
	args []string
	out  []byte
	err  error
}

func (r *recordingCommandRunner) Run(ctx context.Context, name string, args []string) ([]byte, error) {
	r.name = name
	r.args = append([]string(nil), args...)
	return r.out, r.err
}

type commandResult struct {
	out []byte
	err error
}

type scriptedCommandRunner struct {
	calls   [][]string
	results []commandResult
}

func (r *scriptedCommandRunner) Run(ctx context.Context, name string, args []string) ([]byte, error) {
	r.calls = append(r.calls, append([]string(nil), args...))
	if len(r.results) == 0 {
		return nil, nil
	}
	result := r.results[0]
	r.results = r.results[1:]
	return result.out, result.err
}
