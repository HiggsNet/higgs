package healthspool

import (
	"testing"
	"time"
)

func TestStoreAppendAndQuerySeries(t *testing.T) {
	store := New(Config{Enabled: true, Path: t.TempDir(), MaxAge: time.Hour})
	now := time.Unix(2000, 0)
	if err := store.Append(now.Add(-10*time.Minute), []Sample{{
		InstanceID: "link-1", State: "healthy", ProbeType: "icmp", RTTMs: 10,
		Sent: 3, Received: 3,
	}}); err != nil {
		t.Fatalf("Append old sample: %v", err)
	}
	if err := store.Append(now, []Sample{{
		InstanceID: "link-1", State: "degraded", ProbeType: "icmp", RTTMs: 20,
		LossRatioPct: 25, Sent: 4, Received: 3, Lost: 1,
	}}); err != nil {
		t.Fatalf("Append current sample: %v", err)
	}

	series, err := store.Query("link-1", SeriesQuery{Metric: "rtt", Range: 30 * time.Minute, Step: time.Minute, Now: now})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if series.Metric != "rtt" || series.Unit != "ms" || len(series.Points) != 2 || series.Points[1].Value != 20 {
		t.Fatalf("series = %+v, want two rtt points ending at 20ms", series)
	}
	samples, err := readAllHealthSpoolSamples(store.Config().File())
	if err != nil {
		t.Fatalf("read samples: %v", err)
	}
	if len(samples) != 2 || samples[1].Sent != 4 || samples[1].Received != 3 || samples[1].Lost != 1 {
		t.Fatalf("samples = %+v, want retained packet counts", samples)
	}
}

func TestStoreQueryKeepsRotateProbeLines(t *testing.T) {
	store := New(Config{Enabled: true, Path: t.TempDir(), MaxAge: time.Hour})
	now := time.Unix(4000, 0)
	if err := store.Append(now, []Sample{
		{ProbeID: "link-1#old", InstanceID: "link-1", ProbeRole: "old", State: "healthy", RTTMs: 30},
		{ProbeID: "link-1#staged", InstanceID: "link-1", ProbeRole: "staged", State: "healthy", RTTMs: 12},
	}); err != nil {
		t.Fatalf("Append: %v", err)
	}
	series, err := store.Query("link-1", SeriesQuery{Metric: "rtt", Range: time.Minute, Step: time.Minute, Now: now})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	got := map[string]float64{}
	for _, line := range series.Lines {
		if len(line.Points) != 1 {
			t.Fatalf("line %+v has %d points, want 1", line, len(line.Points))
		}
		got[line.ProbeRole] = line.Points[0].Value
	}
	if got["old"] != 30 || got["staged"] != 12 {
		t.Fatalf("line values = %#v, want old=30 staged=12", got)
	}
}
