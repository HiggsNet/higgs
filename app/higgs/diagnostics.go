package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/Catofes/higgs/pkg/core/gossip"
	"github.com/Catofes/higgs/pkg/core/zone"
	higgscrypto "github.com/Catofes/higgs/pkg/crypto"
)

func syncDebugLogger(config *syncConfigFile) func(gossip.Event) {
	if !debugLogEnabled(config) {
		return nil
	}
	return func(event gossip.Event) {
		fields := map[string]any{
			"ts":           time.Now().UTC().Format(time.RFC3339Nano),
			"level":        "debug",
			"component":    "gossip",
			"direction":    event.Direction,
			"peer_id":      event.PeerID,
			"message_type": event.Type,
			"addr":         event.Addr,
			"bytes":        event.Bytes,
			"zones":        event.Zones,
			"records":      event.Records,
			"duration_ms":  event.Duration.Milliseconds(),
		}
		if event.Reason != "" {
			fields["reject_reason"] = event.Reason
		}
		if event.Error != "" {
			fields["error"] = event.Error
		}
		data, err := json.Marshal(fields)
		if err != nil {
			return
		}
		fmt.Fprintln(os.Stderr, string(data))
	}
}

func debugLogEnabled(config *syncConfigFile) bool {
	level := strings.ToLower(os.Getenv("HIGGS_LOG_LEVEL"))
	if level == "" && config != nil {
		level = strings.ToLower(config.LogLevel)
	}
	return level == "debug"
}

func debugPeer(peerID string) error {
	state, err := loadState()
	if err != nil {
		return err
	}
	config, err := loadSyncConfig(state)
	if err != nil {
		return err
	}
	known := configuredKnownPeers(config)
	peerState := state.SyncPeers[peerID]
	source, configuredAddr := bootstrapPeerSource(config, peerID)
	resolved := "-"
	if addr := known[peerID]; addr != nil {
		resolved = addr.String()
	}
	fmt.Printf("peer_id: %s\n", peerID)
	fmt.Printf("source: %s\n", source)
	fmt.Printf("configured_addr: %s\n", dash(configuredAddr))
	fmt.Printf("resolved_addr: %s\n", resolved)
	fmt.Printf("status: %s\n", peerStatus(peerState, time.Now()))
	fmt.Printf("last_success: %s\n", formatLastSuccess(peerState))
	fmt.Printf("last_error: %s\n", dash(peerState.LastError))
	fmt.Printf("backoff: %s\n", formatBackoff(peerState, time.Now()))
	fmt.Printf("next_retry: %s\n", formatNextRetry(peerState, time.Now()))
	fmt.Printf("known_endpoint: %s\n", resolved)
	return nil
}

func debugZone(path zone.ZonePath) error {
	state, err := loadState()
	if err != nil {
		return err
	}
	configureValidation(state.Network)
	zs := state.Network.Zones[path]
	if zs == nil {
		return fmt.Errorf("%w: %s", zone.ErrZoneNotFound, path)
	}
	digest := zoneDigest(state.Network, path)
	verifyResult := "ok"
	if err := higgscrypto.VerifyChain(state.Network, path, time.Now()); err != nil {
		verifyResult = err.Error()
	}
	fmt.Printf("zone: %s\n", path)
	fmt.Printf("root: %s\n", hex.EncodeToString(digest.RootHash))
	fmt.Printf("records: %d\n", len(zs.Records))
	fmt.Printf("history: %d\n", countHistory(zs))
	fmt.Printf("pending: %d\n", countPending(zs))
	fmt.Printf("delegations: %d\n", len(zs.Delegations))
	fmt.Printf("parent_proof: %d\n", len(zs.ParentProof))
	fmt.Printf("verify: %s\n", verifyResult)
	printDebugRecords("record", zs.Records)
	printDebugPending(zs)
	return nil
}

func debugPending() error {
	state, err := loadState()
	if err != nil {
		return err
	}
	fetches := pendingPredecessorFetches(state.Network)
	if len(fetches) == 0 {
		fmt.Println("pending_records: 0")
		return nil
	}
	fmt.Printf("pending_records: %d\n", totalPending(state.Network))
	for _, fetch := range fetches {
		fmt.Printf("fetch_record zone=%s key=%s version=%d\n", fetch.Zone, fetch.Key, fetch.Version)
	}
	return nil
}

func bootstrapPeerSource(config *syncConfigFile, peerID string) (string, string) {
	for _, peer := range config.Bootstrap {
		if peer.ID == peerID {
			return "bootstrap", peer.Addr
		}
	}
	return "unknown", ""
}

func zoneDigest(ns *zone.NetworkState, path zone.ZonePath) gossip.ZoneDigest {
	for _, digest := range gossip.ZoneDigests(ns) {
		if digest.Zone == path {
			return digest
		}
	}
	return gossip.ZoneDigest{Zone: path}
}

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

func printDebugRecords(prefix string, records map[string]*zone.Record) {
	keys := make([]string, 0, len(records))
	for key := range records {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		record := records[key]
		if record == nil {
			continue
		}
		fmt.Printf("%s key=%s version=%d type=%s\n", prefix, key, record.Version, record.Type)
	}
}

func printDebugPending(zs *zone.ZoneState) {
	if zs == nil {
		return
	}
	keys := make([]string, 0, len(zs.PendingRecords))
	for key := range zs.PendingRecords {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		for _, record := range zs.PendingRecords[key] {
			if record == nil {
				continue
			}
			fmt.Printf("pending key=%s version=%d missing_prev=%d\n", key, record.Version, missingPredecessorVersion(record))
		}
	}
}

func formatLastSuccess(peerState syncPeerState) string {
	if peerState.LastSyncUnix == 0 || peerState.LastError != "" {
		return "never"
	}
	return time.Unix(peerState.LastSyncUnix, 0).UTC().Format(time.RFC3339)
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

func formatBackoff(peerState syncPeerState, now time.Time) string {
	remaining := backoffRemaining(peerState, now)
	if remaining <= 0 {
		return "-"
	}
	return remaining.Round(time.Second).String()
}

func formatNextRetry(peerState syncPeerState, now time.Time) string {
	if backoffRemaining(peerState, now) <= 0 {
		return "-"
	}
	return time.Unix(peerState.BackoffUntilUnix, 0).UTC().Format(time.RFC3339)
}

func dash(value string) string {
	if value == "" {
		return "-"
	}
	return value
}
