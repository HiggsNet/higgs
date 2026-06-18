package health

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// MetricsSnapshot is the set of current metric samples, suitable for rendering
// to OpenMetrics/Prometheus text format. The Manager is the source of truth;
// this struct is a plain value for easy serialization/testing.
type MetricsSnapshot struct {
	Samples []MetricSample
	Errors  map[string]int // instance -> total errors (for higgs_link_probe_errors_total)
}

// MetricSample is a single gauge/counter sample with low-cardinality labels.
type MetricSample struct {
	Name   string
	Value  float64
	Labels MetricsLabels
}

// CollectMetrics converts a slice of LinkHealth into metric samples. It
// deliberately keeps label cardinality low: only stable dimensions are used.
func CollectMetrics(healths []LinkHealth, now time.Time) MetricsSnapshot {
	snap := MetricsSnapshot{Errors: map[string]int{}}
	for _, h := range healths {
		base := h.Labels
		// Gauge: RTT in seconds.
		if h.LastRTT > 0 {
			snap.Samples = append(snap.Samples, MetricSample{
				Name:   "higgs_link_probe_rtt_seconds",
				Value:  h.LastRTT.Seconds(),
				Labels: base,
			})
		}
		// Gauge: loss ratio (0.0-1.0).
		if h.Sent > 0 {
			snap.Samples = append(snap.Samples, MetricSample{
				Name:   "higgs_link_probe_loss_ratio",
				Value:  h.LossRatio,
				Labels: base,
			})
		}
		// Gauge: jitter in seconds.
		if h.Jitter > 0 {
			snap.Samples = append(snap.Samples, MetricSample{
				Name:   "higgs_link_probe_jitter_seconds",
				Value:  h.Jitter.Seconds(),
				Labels: base,
			})
		}
		// Gauge: health state encoded as 0=healthy,1=degraded,2=down,3=unknown,4=probe_error.
		snap.Samples = append(snap.Samples, MetricSample{
			Name:   "higgs_link_health_state",
			Value:  healthStateValue(h.State),
			Labels: base,
		})
		// Counter: total probe errors.
		snap.Errors[h.InstanceID] = 0 // populated by Manager.ErrorsTotal; placeholder for structure
	}
	return snap
}

// RenderOpenMetrics writes the metrics in OpenMetrics text exposition format.
func RenderOpenMetrics(w io.Writer, snap MetricsSnapshot, errorsTotal map[string]int) {
	var b strings.Builder
	// Group samples by metric name for HELP/TYPE headers.
	byName := map[string][]MetricSample{}
	for _, s := range snap.Samples {
		byName[s.Name] = append(byName[s.Name], s)
	}
	for _, name := range sortedKeys(byName) {
		samples := byName[name]
		help, typ := metricMeta(name)
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, typ)
		for _, s := range samples {
			b.WriteString(name)
			writeLabels(&b, s.Labels)
			fmt.Fprintf(&b, " %s\n", strconv.FormatFloat(s.Value, 'g', -1, 64))
		}
	}
	// Counter: errors total.
	fmt.Fprintf(&b, "# HELP higgs_link_probe_errors_total Total health probe errors per link.\n")
	fmt.Fprintf(&b, "# TYPE higgs_link_probe_errors_total counter\n")
	// We need labels for errors; reconstruct from samples.
	for _, s := range byName["higgs_link_health_state"] {
		total := errorsTotal[s.Labels.InstanceID]
		if total == 0 {
			continue
		}
		b.WriteString("higgs_link_probe_errors_total")
		writeLabels(&b, s.Labels)
		fmt.Fprintf(&b, " %d\n", total)
	}
	io.WriteString(w, b.String())
}

func metricMeta(name string) (help string, typ string) {
	switch name {
	case "higgs_link_probe_rtt_seconds":
		return "Last probe RTT in seconds.", "gauge"
	case "higgs_link_probe_loss_ratio":
		return "Probe loss ratio over rolling window.", "gauge"
	case "higgs_link_probe_jitter_seconds":
		return "Probe jitter in seconds.", "gauge"
	case "higgs_link_health_state":
		return "Link health state (0=healthy,1=degraded,2=down,3=unknown,4=probe_error).", "gauge"
	default:
		return "Higgs link metric.", "gauge"
	}
}

func healthStateValue(state string) float64 {
	switch state {
	case HealthStateHealthy:
		return 0
	case HealthStateDegraded:
		return 1
	case HealthStateDown:
		return 2
	case HealthStateUnknown:
		return 3
	case HealthStateProbeError:
		return 4
	case HealthStateSuppressed:
		return 5
	default:
		return 3
	}
}

func writeLabels(b *strings.Builder, labels MetricsLabels) {
	first := true
	b.WriteByte('{')
	writeLabel := func(k, v string) {
		if v == "" {
			return
		}
		if !first {
			b.WriteByte(',')
		}
		first = false
		fmt.Fprintf(b, "%s=%q", k, escapeLabelValue(v))
	}
	writeLabel("local_zone", labels.LocalZone)
	writeLabel("peer_zone", labels.PeerZone)
	writeLabel("overlay", labels.Overlay)
	writeLabel("instance_id", labels.InstanceID)
	writeLabel("netns", labels.NetNS)
	writeLabel("generation", labels.Generation)
	writeLabel("probe_type", labels.ProbeType)
	writeLabel("reason", labels.Reason)
	b.WriteByte('}')
}

func escapeLabelValue(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	return s
}

func sortedKeys(m map[string][]MetricSample) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j-1] > keys[j]; j-- {
			keys[j-1], keys[j] = keys[j], keys[j-1]
		}
	}
	return keys
}
