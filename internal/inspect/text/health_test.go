package text

import (
	"strings"
	"testing"

	"github.com/Catofes/higgs/internal/inspect"
)

func TestWriteHealthDebugNoTargets(t *testing.T) {
	var buf strings.Builder
	if err := WriteHealthDebug(&buf, inspect.HealthDebugView{}); err != nil {
		t.Fatalf("WriteHealthDebug: %v", err)
	}
	if got := buf.String(); got != "No link instances to probe.\n" {
		t.Fatalf("output = %q", got)
	}
}

func TestWriteHealthDebugSortsTargetsAndShowsLiveState(t *testing.T) {
	view := inspect.HealthDebugView{
		Targets: []inspect.HealthProbeTargetView{
			{
				ProbeID:         "link-b#staged",
				InstanceID:      "link-b",
				PeerZone:        "node-b.catofes.",
				Overlay:         "blue",
				InterfaceName:   "hgs-b",
				LocalTunnelAddr: "fd00::1",
				PeerTunnelAddr:  "fd00::2",
				ProbeRole:       "staged",
				State:           "up",
				Staged:          true,
			},
			{
				ProbeID:         "link-a",
				InstanceID:      "link-a",
				PeerZone:        "node-a.catofes.",
				Overlay:         "blue",
				InterfaceName:   "hgs-a",
				LocalTunnelAddr: "fd00::3",
				PeerTunnelAddr:  "fd00::4",
				State:           "up",
			},
		},
		Live: []inspect.HealthLiveView{{
			ProbeID:         "link-b#staged",
			InstanceID:      "link-b",
			ProbeRole:       "staged",
			State:           "healthy",
			ProbeType:       "icmp",
			Sent:            4,
			Received:        3,
			Lost:            1,
			LossRatio:       25,
			LastRTTMs:       30,
			EWMARTTMs:       25,
			P50RTTMs:        20,
			P95RTTMs:        40,
			P99RTTMs:        45,
			JitterMs:        5,
			LastError:       "timeout",
			ConsecutiveFail: 2,
			CutoverBlocking: true,
		}},
	}

	var buf strings.Builder
	if err := WriteHealthDebug(&buf, view); err != nil {
		t.Fatalf("WriteHealthDebug: %v", err)
	}
	out := buf.String()
	if strings.Index(out, "  link-a\n") > strings.Index(out, "  link-b\n") {
		t.Fatalf("targets are not sorted by instance id:\n%s", out)
	}
	for _, want := range []string{
		"Link health (2 links):",
		"probe_id=link-a role=active underlay=- interface=hgs-a local=fd00::3 peer_addr=fd00::4",
		"probe_id=link-b#staged role=staged underlay=- interface=hgs-b local=fd00::1 peer_addr=fd00::2",
		"Live health state:",
		"link-b#staged: state=healthy role=staged probe=icmp",
		"sent=4 received=3 lost=1 loss=25%",
		"rtt last=30ms ewma=25ms p50=20ms p95=40ms p99=45ms jitter=5ms",
		"last_error=timeout consecutive_fail=2",
		"cutover_blocking=true",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected %q in output:\n%s", want, out)
		}
	}
}
