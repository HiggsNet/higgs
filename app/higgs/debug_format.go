package main

import (
	"time"

	"github.com/Catofes/higgs/pkg/core/zone"
)

func countHistory(zs *zone.ZoneState) int {
	if zs == nil {
		return 0
	}
	var out int
	for _, records := range zs.RecordHistory {
		out += len(records)
	}
	return out
}

func formatLastSuccess(peerState syncPeerState) string {
	if peerState.LastSyncUnix == 0 {
		return "never"
	}
	return formatUnixTime(peerState.LastSyncUnix)
}

func peerStatus(peerState syncPeerState, now time.Time) string {
	if backoffRemaining(peerState, now) > 0 {
		return "backoff"
	}
	if peerState.LastError != "" {
		return "stale"
	}
	if peerState.LastSyncUnix == 0 {
		return "unknown"
	}
	if now.Sub(time.Unix(peerState.LastSyncUnix, 0)) > 2*time.Minute {
		return "stale"
	}
	return "online"
}

func formatNextRetry(peerState syncPeerState, now time.Time) string {
	if backoffRemaining(peerState, now) <= 0 {
		return "-"
	}
	return formatUnixTime(peerState.BackoffUntilUnix)
}

func formatUnixTime(unix int64) string {
	if unix == 0 {
		return "never"
	}
	return time.Unix(unix, 0).UTC().Format(time.RFC3339)
}

func dash(value string) string {
	if value == "" {
		return "-"
	}
	return value
}
