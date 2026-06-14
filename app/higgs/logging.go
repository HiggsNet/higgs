package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Catofes/higgs/pkg/core/gossip"
)

type logLevel string

const (
	logLevelDebug logLevel = "debug"
	logLevelInfo  logLevel = "info"
	logLevelWarn  logLevel = "warn"
	logLevelError logLevel = "error"
)

type appLogger struct {
	level logLevel
	out   io.Writer
	now   func() time.Time
}

func newAppLogger(config *syncConfigFile) *appLogger {
	level := logLevelInfo
	raw := strings.ToLower(strings.TrimSpace(os.Getenv("HIGGS_LOG_LEVEL")))
	if raw == "" && config != nil {
		raw = strings.ToLower(strings.TrimSpace(config.LogLevel))
	}
	switch logLevel(raw) {
	case logLevelDebug, logLevelInfo, logLevelWarn, logLevelError:
		level = logLevel(raw)
	default:
		// Keep unknown values non-fatal so existing configs continue to run.
	}
	return &appLogger{level: level, out: os.Stderr, now: time.Now}
}

func logLevelRank(level logLevel) int {
	switch level {
	case logLevelDebug:
		return 0
	case logLevelInfo:
		return 1
	case logLevelWarn:
		return 2
	case logLevelError:
		return 3
	default:
		return logLevelRank(logLevelInfo)
	}
}

func (l *appLogger) enabled(level logLevel) bool {
	if l == nil {
		return newAppLogger(nil).enabled(level)
	}
	if l.level == "" {
		l.level = logLevelInfo
	}
	if logLevelRank(level) < logLevelRank(l.level) {
		return false
	}
	if level == logLevelDebug && l.level != logLevelDebug {
		return false
	}
	return true
}

func (l *appLogger) debugEnabled() bool {
	if l == nil {
		return newAppLogger(nil).debugEnabled()
	}
	return l.level == logLevelDebug
}

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

func (l *appLogger) Debug(component, event string, fields map[string]any) {
	l.write(logLevelDebug, component, event, fields)
}

// logControlFallback logs a structured warning when a CLI command falls back
// to direct state manipulation because the daemon control socket is not
// available. The fallback is still functional, but operating without the
// daemon is abnormal and should be visible at the default log level.
func logControlFallback(operation string) {
	newAppLogger(nil).Warn("control", "fallback", map[string]any{
		"operation": operation,
		"reason":    "daemon control socket unavailable",
	})
}

func (l *appLogger) Info(component, event string, fields map[string]any) {
	l.write(logLevelInfo, component, event, fields)
}

func (l *appLogger) Warn(component, event string, fields map[string]any) {
	l.write(logLevelWarn, component, event, fields)
}

func (l *appLogger) Error(component, event string, fields map[string]any) {
	l.write(logLevelError, component, event, fields)
}

func (l *appLogger) write(level logLevel, component, event string, fields map[string]any) {
	if l == nil {
		l = newAppLogger(nil)
	}
	if !l.enabled(level) {
		return
	}
	out := l.out
	if out == nil {
		out = os.Stderr
	}
	now := time.Now
	if l.now != nil {
		now = l.now
	}
	base := map[string]any{
		"ts":        now().UTC().Format(time.RFC3339Nano),
		"level":     level,
		"component": component,
		"event":     event,
	}
	for k, v := range fields {
		if v != nil {
			base[k] = v
		}
	}
	keys := make([]string, 0, len(base))
	for key := range base {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	preferred := []string{"ts", "level", "component", "event", "peer_id", "message", "reason", "error"}
	written := make(map[string]bool, len(keys))
	first := true
	for _, key := range preferred {
		if _, ok := base[key]; ok {
			first = writeLogField(out, first, key, base[key])
			written[key] = true
		}
	}
	for _, key := range keys {
		if written[key] {
			continue
		}
		first = writeLogField(out, first, key, base[key])
	}
	fmt.Fprintln(out)
}

func writeLogField(out io.Writer, first bool, key string, value any) bool {
	if !first {
		fmt.Fprint(out, " ")
	}
	fmt.Fprintf(out, "%s=%s", key, quoteLogValue(value))
	return false
}

func quoteLogValue(value any) string {
	switch v := value.(type) {
	case string:
		if v == "" {
			return `""`
		}
		if strings.ContainsAny(v, " \t\n\r\"=") {
			return strconv.Quote(v)
		}
		return v
	case logLevel:
		return string(v)
	case error:
		return quoteLogValue(v.Error())
	case time.Duration:
		return v.String()
	case fmt.Stringer:
		return quoteLogValue(v.String())
	default:
		return fmt.Sprint(v)
	}
}

type repeatedLogLimiter struct {
	mu       sync.Mutex
	interval time.Duration
	entries  map[string]repeatedLogEntry
}

type repeatedLogEntry struct {
	last       time.Time
	suppressed int
}

func newRepeatedLogLimiter(interval time.Duration) *repeatedLogLimiter {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	return &repeatedLogLimiter{interval: interval, entries: make(map[string]repeatedLogEntry)}
}

func (l *repeatedLogLimiter) Allow(key string, now time.Time) (suppressed int, ok bool) {
	if l == nil || key == "" {
		return 0, true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	entry := l.entries[key]
	if entry.last.IsZero() || now.Sub(entry.last) >= l.interval {
		suppressed = entry.suppressed
		l.entries[key] = repeatedLogEntry{last: now}
		return suppressed, true
	}
	entry.suppressed++
	l.entries[key] = entry
	return 0, false
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

func addPeerLogFields(fields map[string]any, state *stateFile, peerID string, now time.Time) {
	if fields == nil || state == nil || peerID == "" {
		return
	}
	peerState := state.SyncPeers[peerID]
	if peerState.DiscoveredAddr != "" {
		fields["discovered_addr"] = peerState.DiscoveredAddr
	}
	if peerState.ObservedAddr != "" {
		fields["observed_addr"] = peerState.ObservedAddr
		fields["observed_active"] = observedPathActive(peerState, now)
	}
	if peerState.BackoffUntilUnix > 0 {
		backoff := backoffRemaining(peerState, now)
		if backoff > 0 {
			fields["backoff"] = backoff
		}
	}
	if peerState.FailureCount > 0 {
		fields["failure_count"] = peerState.FailureCount
	}
	if peerState.LastError != "" {
		fields["last_error"] = peerState.LastError
	}
	if peerState.LastSyncUnix > 0 {
		fields["last_success"] = time.Unix(peerState.LastSyncUnix, 0).UTC().Format(time.RFC3339)
	}
	if peerState.ObjectPullStats != nil {
		fields["object_pull_attempts"] = peerState.ObjectPullStats.Attempts
		fields["object_pull_failures"] = peerState.ObjectPullStats.Failures
		fields["object_pull_last_error"] = peerState.ObjectPullStats.LastError
	}
	if peerState.DatagramStats != nil {
		fields["datagram_too_large_dropped"] = peerState.DatagramStats.TooLargeDropped
		fields["datagram_chunk_fallbacks"] = peerState.DatagramStats.ChunkFallbacks
	}
}
