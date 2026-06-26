package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const healthSpoolSamplesFile = "samples.jsonl"

var errHealthSpoolNotConfigured = errors.New("health local spool not configured")

type healthSpoolSample struct {
	UnixMs       int64  `json:"unix_ms"`
	InstanceID   string `json:"instance_id"`
	State        string `json:"state"`
	ProbeType    string `json:"probe_type,omitempty"`
	RTTMs        int64  `json:"rtt_ms,omitempty"`
	LossRatioPct int    `json:"loss_ratio_pct"`
	JitterMs     int64  `json:"jitter_ms,omitempty"`
	Sent         int    `json:"sent,omitempty"`
	Received     int    `json:"received,omitempty"`
	Lost         int    `json:"lost,omitempty"`
}

type healthSeriesPoint struct {
	UnixMs int64   `json:"unix_ms"`
	Value  float64 `json:"value"`
}

type healthSeriesResult struct {
	Metric    string              `json:"metric"`
	Unit      string              `json:"unit"`
	Range     string              `json:"range"`
	Step      string              `json:"step"`
	Window    string              `json:"window"`
	Points    []healthSeriesPoint `json:"points"`
	Truncated bool                `json:"truncated,omitempty"`
}

type healthSeriesQuery struct {
	Metric string
	Range  time.Duration
	Step   time.Duration
	Now    time.Time
}

func healthSpoolConfigured(cfg healthConfig) bool {
	return cfg.MetricsEnabled && strings.TrimSpace(cfg.LocalSpoolPath) != ""
}

func healthSpoolDir(config *appConfig) string {
	if config == nil {
		return ""
	}
	return strings.TrimSpace(config.Health.LocalSpoolPath)
}

func healthSpoolFile(config *appConfig) string {
	dir := healthSpoolDir(config)
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, healthSpoolSamplesFile)
}

func healthDatasourceInfo(config *appConfig) map[string]any {
	if config == nil || !healthSpoolConfigured(config.Health) {
		return map[string]any{
			"configured": false,
			"type":       "none",
		}
	}
	return map[string]any{
		"configured":    true,
		"type":          "local_spool",
		"local":         true,
		"series_window": config.Health.LocalSpoolMaxAge.String(),
	}
}

func (d *DaemonService) appendHealthSpool(now time.Time, links []healthLinkJSON) error {
	if d == nil || d.Sync == nil || d.Sync.App == nil || d.Sync.App.Config == nil {
		return errHealthSpoolNotConfigured
	}
	config := d.Sync.App.Config
	if !healthSpoolConfigured(config.Health) {
		return errHealthSpoolNotConfigured
	}
	path := healthSpoolFile(config)
	if path == "" {
		return errHealthSpoolNotConfigured
	}
	d.healthSpoolMu.Lock()
	defer d.healthSpoolMu.Unlock()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	for _, link := range links {
		if link.InstanceID == "" {
			continue
		}
		if err := enc.Encode(healthSpoolSample{
			UnixMs:       now.UnixMilli(),
			InstanceID:   link.InstanceID,
			State:        link.State,
			ProbeType:    link.ProbeType,
			RTTMs:        link.LastRTTMs,
			LossRatioPct: link.LossRatio,
			JitterMs:     link.JitterMs,
			Sent:         link.Sent,
			Received:     link.Received,
			Lost:         link.Lost,
		}); err != nil {
			_ = f.Close()
			return err
		}
	}
	if err := f.Close(); err != nil {
		return err
	}
	return pruneHealthSpoolFile(path, now.Add(-config.Health.LocalSpoolMaxAge))
}

func queryHealthSpoolSeries(config *appConfig, linkID string, q healthSeriesQuery) (healthSeriesResult, error) {
	if config == nil || !healthSpoolConfigured(config.Health) {
		return healthSeriesResult{}, errHealthSpoolNotConfigured
	}
	metric, unit, err := normalizeHealthSeriesMetric(q.Metric)
	if err != nil {
		return healthSeriesResult{}, err
	}
	if linkID == "" {
		return healthSeriesResult{}, fmt.Errorf("link id is required")
	}
	if q.Now.IsZero() {
		q.Now = time.Now()
	}
	if q.Range <= 0 {
		q.Range = time.Hour
	}
	if config.Health.LocalSpoolMaxAge > 0 && q.Range > config.Health.LocalSpoolMaxAge {
		q.Range = config.Health.LocalSpoolMaxAge
	}
	if q.Step <= 0 {
		q.Step = 30 * time.Second
	}
	if q.Step < time.Second {
		q.Step = time.Second
	}
	if q.Step > q.Range {
		q.Step = q.Range
	}
	since := q.Now.Add(-q.Range)
	path := healthSpoolFile(config)
	samples, err := readHealthSpoolSamples(path, since, q.Now, linkID)
	if err != nil {
		return healthSeriesResult{}, err
	}
	points := bucketHealthSamples(samples, metric, since, q.Step)
	return healthSeriesResult{
		Metric: metric,
		Unit:   unit,
		Range:  q.Range.String(),
		Step:   q.Step.String(),
		Window: config.Health.LocalSpoolMaxAge.String(),
		Points: points,
	}, nil
}

func normalizeHealthSeriesMetric(metric string) (string, string, error) {
	switch strings.TrimSpace(metric) {
	case "", "rtt":
		return "rtt", "ms", nil
	case "loss":
		return "loss", "percent", nil
	case "jitter":
		return "jitter", "ms", nil
	case "state":
		return "state", "code", nil
	case "babel_rtt", "babel_metric":
		return "", "", fmt.Errorf("metric %q is not available in the local health spool yet", metric)
	default:
		return "", "", fmt.Errorf("unsupported health series metric %q", metric)
	}
}

func readHealthSpoolSamples(path string, since, until time.Time, linkID string) ([]healthSpoolSample, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []healthSpoolSample
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var sample healthSpoolSample
		if err := json.Unmarshal(scanner.Bytes(), &sample); err != nil {
			continue
		}
		if sample.InstanceID != linkID {
			continue
		}
		ts := time.UnixMilli(sample.UnixMs)
		if ts.Before(since) || ts.After(until) {
			continue
		}
		out = append(out, sample)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UnixMs < out[j].UnixMs })
	return out, nil
}

func bucketHealthSamples(samples []healthSpoolSample, metric string, start time.Time, step time.Duration) []healthSeriesPoint {
	if len(samples) == 0 {
		return []healthSeriesPoint{}
	}
	type aggregate struct {
		ts    int64
		sum   float64
		count int
	}
	buckets := map[int64]*aggregate{}
	startMs := start.UnixMilli()
	stepMs := step.Milliseconds()
	if stepMs <= 0 {
		stepMs = 1000
	}
	for _, sample := range samples {
		value, ok := healthSampleValue(sample, metric)
		if !ok {
			continue
		}
		bucket := startMs + ((sample.UnixMs-startMs)/stepMs)*stepMs
		agg := buckets[bucket]
		if agg == nil {
			agg = &aggregate{ts: bucket}
			buckets[bucket] = agg
		}
		agg.sum += value
		agg.count++
	}
	keys := make([]int64, 0, len(buckets))
	for key := range buckets {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	points := make([]healthSeriesPoint, 0, len(keys))
	for _, key := range keys {
		agg := buckets[key]
		if agg.count == 0 {
			continue
		}
		points = append(points, healthSeriesPoint{UnixMs: agg.ts, Value: agg.sum / float64(agg.count)})
	}
	return points
}

func healthSampleValue(sample healthSpoolSample, metric string) (float64, bool) {
	switch metric {
	case "rtt":
		return float64(sample.RTTMs), sample.RTTMs > 0
	case "loss":
		return float64(sample.LossRatioPct), true
	case "jitter":
		return float64(sample.JitterMs), sample.JitterMs > 0
	case "state":
		return healthStateCode(sample.State), true
	default:
		return 0, false
	}
}

func healthStateCode(state string) float64 {
	switch state {
	case "healthy":
		return 0
	case "degraded":
		return 1
	case "down":
		return 2
	case "unknown":
		return 3
	case "probe_error":
		return 4
	case "suppressed":
		return 5
	default:
		return 3
	}
}

func pruneHealthSpoolFile(path string, cutoff time.Time) error {
	if cutoff.IsZero() {
		return nil
	}
	samples, err := readAllHealthSpoolSamples(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	for _, sample := range samples {
		if time.UnixMilli(sample.UnixMs).Before(cutoff) {
			continue
		}
		if err := enc.Encode(sample); err != nil {
			_ = f.Close()
			return err
		}
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func readAllHealthSpoolSamples(path string) ([]healthSpoolSample, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []healthSpoolSample
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var sample healthSpoolSample
		if err := json.Unmarshal(scanner.Bytes(), &sample); err != nil {
			continue
		}
		out = append(out, sample)
	}
	return out, scanner.Err()
}
