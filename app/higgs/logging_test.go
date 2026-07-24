package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Catofes/higgs/pkg/core/gossip"
	"github.com/Catofes/higgs/pkg/core/zone"
)

func (l *appLogger) withNow(now func() time.Time) *appLogger {
	if l == nil {
		l = newAppLogger(nil)
	}
	if now != nil {
		l.now = now
	}
	return l
}

func (l *appLogger) withOutput(out io.Writer) *appLogger {
	if l == nil {
		l = newAppLogger(nil)
	}
	if out != nil {
		l.out = out
	}
	return l
}

func (l *appLogger) setLevel(level logLevel) *appLogger {
	if l == nil {
		l = newAppLogger(nil)
	}
	switch level {
	case logLevelDebug, logLevelInfo, logLevelWarn, logLevelError:
	default:
		level = logLevelInfo
	}
	l.level = level
	return l
}

func syncErrorReason(err error) string {
	var pending *syncPendingZonesError
	switch {
	case err == nil:
		return ""
	case errors.As(err, &pending):
		return "pending_zones"
	case errors.Is(err, context.DeadlineExceeded):
		return "context_deadline"
	case isReceiveTimeout(err):
		return "timeout"
	case errors.Is(err, gossip.ErrUnknownPeer):
		return "unknown_peer"
	case errors.Is(err, gossip.ErrMessageTooLarge):
		return "message_too_large"
	case errors.Is(err, gossip.ErrQuotaExceeded):
		return "quota"
	default:
		reason := gossip.RejectReason(err)
		if reason != "invalid_message" {
			return reason
		}
		return "sync_error"
	}
}

func TestAppLoggerWritesStructuredFields(t *testing.T) {
	var buf bytes.Buffer
	logger := &appLogger{
		level: logLevelInfo,
		out:   &buf,
		now:   func() time.Time { return time.Unix(100, 123).UTC() },
	}

	logger.Warn("sync", "round_failed", map[string]any{
		"peer_id": "node-a.catofes.",
		"reason":  "timeout",
		"error":   "sync receive timed out",
	})

	line := buf.String()
	for _, want := range []string{
		"ts=1970-01-01T00:01:40.000000123Z",
		"level=warn",
		"component=sync",
		"event=round_failed",
		"peer_id=node-a.catofes.",
		"reason=timeout",
		`error="sync receive timed out"`,
	} {
		if !strings.Contains(line, want) {
			t.Fatalf("log line %q does not contain %q", line, want)
		}
	}
}

func TestRepeatedLogLimiterSuppressesUntilInterval(t *testing.T) {
	limiter := newRepeatedLogLimiter(time.Minute)
	now := time.Unix(100, 0)

	if suppressed, ok := limiter.Allow("sync|node-a|timeout", now); !ok || suppressed != 0 {
		t.Fatalf("first Allow = %d/%v, want 0/true", suppressed, ok)
	}
	if suppressed, ok := limiter.Allow("sync|node-a|timeout", now.Add(time.Second)); ok || suppressed != 0 {
		t.Fatalf("second Allow = %d/%v, want 0/false", suppressed, ok)
	}
	if suppressed, ok := limiter.Allow("sync|node-a|timeout", now.Add(2*time.Second)); ok || suppressed != 0 {
		t.Fatalf("third Allow = %d/%v, want 0/false", suppressed, ok)
	}
	if suppressed, ok := limiter.Allow("sync|node-a|timeout", now.Add(time.Minute)); !ok || suppressed != 2 {
		t.Fatalf("interval Allow = %d/%v, want 2/true", suppressed, ok)
	}
}

func TestAppLoggerFiltersByLevel(t *testing.T) {
	var buf bytes.Buffer
	logger := (&appLogger{}).setLevel(logLevelWarn).withOutput(&buf).withNow(func() time.Time {
		return time.Unix(100, 0).UTC()
	})

	logger.Info("sync", "round_completed", map[string]any{"peer_id": "node-a.catofes."})
	logger.Warn("sync", "round_failed", map[string]any{"peer_id": "node-a.catofes."})

	line := buf.String()
	if strings.Contains(line, "round_completed") {
		t.Fatalf("warn logger emitted info line: %q", line)
	}
	if !strings.Contains(line, "event=round_failed") {
		t.Fatalf("warn logger did not emit warn line: %q", line)
	}
}

func TestAppLoggerWritesToConfiguredFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "higgs.log")
	var stderr bytes.Buffer
	logger := newAppLogger(&syncConfigFile{LogMode: "stderr+file", LogFile: path}).withOutput(&stderr).withNow(func() time.Time {
		return time.Unix(100, 0).UTC()
	})

	logger.Warn("gossip", "packet_failed", map[string]any{"peer_id": "node-a.catofes.", "reason": "quota"})

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(log): %v", err)
	}
	line := string(data)
	if !strings.Contains(line, "component=gossip") || !strings.Contains(line, "event=packet_failed") || !strings.Contains(line, "reason=quota") {
		t.Fatalf("file log line = %q, want structured packet failure", line)
	}
	if !strings.Contains(stderr.String(), "event=packet_failed") {
		t.Fatalf("stderr log line = %q, want duplicate console output", stderr.String())
	}
}

func TestSyncErrorReasonPendingZones(t *testing.T) {
	err := &syncPendingZonesError{zones: []zone.ZonePath{"node-b.catofes."}}
	if got := syncErrorReason(err); got != "pending_zones" {
		t.Fatalf("syncErrorReason = %q, want pending_zones", got)
	}
	if !strings.Contains(err.Error(), "sync once timed out with pending zones: node-b.catofes.") {
		t.Fatalf("pending error text = %q", err.Error())
	}
}
