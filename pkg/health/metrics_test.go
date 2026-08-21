package health

import (
	"strings"
	"testing"
	"time"
)

func TestCollectMetricsAndRenderUsesPacketCounts(t *testing.T) {
	links := []LinkHealth{{
		ProbeID:    "link-a#active",
		InstanceID: "link-a",
		State:      HealthStateDegraded,
		Sent:       30,
		Received:   21,
		Lost:       9,
		LossRatio:  0.3,
		LastRTT:    12 * time.Millisecond,
		Labels: MetricsLabels{
			ProbeID:    "link-a#active",
			InstanceID: "link-a",
			ProbeRole:  "active",
			ProbeType:  ProbeTypeICMP,
		},
	}}
	var output strings.Builder
	if err := RenderOpenMetrics(&output, CollectMetrics(links), map[string]int{"link-a#active": 2}); err != nil {
		t.Fatalf("RenderOpenMetrics: %v", err)
	}
	text := output.String()
	for _, want := range []string{
		"photon_link_probe_packets_sent{probe_id=\"link-a#active\",instance_id=\"link-a\",probe_role=\"active\",probe_type=\"icmp\"} 30",
		"photon_link_probe_packets_received{probe_id=\"link-a#active\",instance_id=\"link-a\",probe_role=\"active\",probe_type=\"icmp\"} 21",
		"photon_link_probe_packets_lost{probe_id=\"link-a#active\",instance_id=\"link-a\",probe_role=\"active\",probe_type=\"icmp\"} 9",
		"photon_link_probe_loss_ratio{probe_id=\"link-a#active\",instance_id=\"link-a\",probe_role=\"active\",probe_type=\"icmp\"} 0.3",
		"photon_link_probe_errors_total{probe_id=\"link-a#active\",instance_id=\"link-a\",probe_role=\"active\",probe_type=\"icmp\"} 2",
		"# EOF\n",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("OpenMetrics output missing %q:\n%s", want, text)
		}
	}
}
