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

func TestICMProberScopedLinkLocalUsesNetNSAndInterface(t *testing.T) {
	runner := &recordingCommandRunner{}
	prober := NewICMProber(runner, nil)
	target := ProbeTarget{
		InstanceID:      "link-1",
		NetNS:           "h2",
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
		"netns", "exec", "h2",
		"ping6", "-c", "1", "-W", "1",
		"-I", "hgs431bcb9f",
		"fe80::b09d:5f83:3e81:d064%hgs431bcb9f",
	}
	if !reflect.DeepEqual(runner.args, want) {
		t.Fatalf("command args = %#v, want %#v", runner.args, want)
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
		NetNS:          "h2",
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
