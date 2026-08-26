package state

import "github.com/HiggsNet/photon/pkg/core/zone"

// PeerRuntimeState is the legacy Linux aggregate. C2b2 migrates only fields
// that qualify as loss-tolerant gossip checkpoints; diagnostics move to the
// observability layer instead of the verified store.
type PeerRuntimeState struct {
	LastSyncUnix            int64                         `json:"last_sync_unix,omitempty"`
	LastAttemptUnix         int64                         `json:"last_attempt_unix,omitempty"`
	BackoffUntilUnix        int64                         `json:"backoff_until_unix,omitempty"`
	LastRelayUnix           int64                         `json:"last_relay_unix,omitempty"`
	LastRelayCatalogRootHex string                        `json:"last_relay_catalog_root_hex,omitempty"`
	FailureCount            int                           `json:"failure_count,omitempty"`
	LastError               string                        `json:"last_error,omitempty"`
	LastUpdateSource        string                        `json:"last_update_source,omitempty"`
	LastRelaySuppression    string                        `json:"last_relay_suppression,omitempty"`
	LastRelaySuppressedAt   int64                         `json:"last_relay_suppressed_at,omitempty"`
	DiscoveredAddr          string                        `json:"discovered_addr,omitempty"`
	DiscoveredAtUnix        int64                         `json:"discovered_at_unix,omitempty"`
	ObservedAddr            string                        `json:"observed_addr,omitempty"`
	ObservedFirstSeenUnix   int64                         `json:"observed_first_seen_unix,omitempty"`
	ObservedLastSeenUnix    int64                         `json:"observed_last_seen_unix,omitempty"`
	ObservedLastSyncUnix    int64                         `json:"observed_last_sync_unix,omitempty"`
	ObservedUntilUnix       int64                         `json:"observed_until_unix,omitempty"`
	ObservedSource          string                        `json:"observed_source,omitempty"`
	ObservedFailureCount    int                           `json:"observed_failure_count,omitempty"`
	ObservedGraceAddrs      []PeerObservedGraceAddrState  `json:"observed_grace_addrs,omitempty"`
	ActivePullState         string                        `json:"active_pull_state,omitempty"`
	ActivePullLastEvent     string                        `json:"active_pull_last_event,omitempty"`
	ActivePullUpdatedUnix   int64                         `json:"active_pull_updated_unix,omitempty"`
	HintAccepted            int64                         `json:"hint_accepted,omitempty"`
	HintSuppressed          int64                         `json:"hint_suppressed,omitempty"`
	LastHintUnix            int64                         `json:"last_hint_unix,omitempty"`
	LastHintReason          string                        `json:"last_hint_reason,omitempty"`
	LastHintSuppression     string                        `json:"last_hint_suppression,omitempty"`
	ReadOnlyResponder       int64                         `json:"read_only_responder,omitempty"`
	LastResponderUnix       int64                         `json:"last_responder_unix,omitempty"`
	LastResponderKind       string                        `json:"last_responder_kind,omitempty"`
	LastResponderZone       string                        `json:"last_responder_zone,omitempty"`
	DatagramStats           *PeerDatagramStats            `json:"datagram_stats,omitempty"`
	ObjectPullStats         *PeerObjectPullStats          `json:"object_pull_stats,omitempty"`
	RejectedDigests         map[string]PeerRejectedDigest `json:"rejected_digests,omitempty"`
}

type PeerObservedGraceAddrState struct {
	Addr      string `json:"addr,omitempty"`
	UntilUnix int64  `json:"until_unix,omitempty"`
}

type PeerRejectedDigest struct {
	Zone           zone.ZonePath `json:"zone"`
	Object         string        `json:"object,omitempty"`
	Key            string        `json:"key,omitempty"`
	RootHashHex    string        `json:"root_hash_hex"`
	ObjectHashHex  string        `json:"object_hash_hex,omitempty"`
	Reason         string        `json:"reason"`
	RejectedAtUnix int64         `json:"rejected_at_unix"`
	UntilUnix      int64         `json:"until_unix"`
}

type PeerDatagramStats struct {
	TooLargeDropped           int64  `json:"too_large_dropped,omitempty"`
	DigestOnlyAnnounces       int64  `json:"digest_only_announces,omitempty"`
	ChunkFallbacks            int64  `json:"chunk_fallbacks,omitempty"`
	ChunkRepairNACKs          int64  `json:"chunk_repair_nacks,omitempty"`
	ChunkRepairChunks         int64  `json:"chunk_repair_chunks,omitempty"`
	ChunkRepairIgnored        int64  `json:"chunk_repair_ignored,omitempty"`
	LastCatalogUnix           int64  `json:"last_catalog_unix,omitempty"`
	LastCatalogRootHex        string `json:"last_catalog_root_hex,omitempty"`
	LastCatalogZoneCount      int    `json:"last_catalog_zone_count,omitempty"`
	LastCatalogCursor         string `json:"last_catalog_cursor,omitempty"`
	LastCatalogPageEntries    int    `json:"last_catalog_page_entries,omitempty"`
	LastCatalogRejectedReason string `json:"last_catalog_rejected_reason,omitempty"`
	LastTooLargeUnix          int64  `json:"last_too_large_unix,omitempty"`
	LastTooLargeDirection     string `json:"last_too_large_direction,omitempty"`
	LastTooLargeObject        string `json:"last_too_large_object,omitempty"`
	LastTooLargeZone          string `json:"last_too_large_zone,omitempty"`
	LastTooLargeKey           string `json:"last_too_large_key,omitempty"`
	LastTooLargeBytes         int    `json:"last_too_large_bytes,omitempty"`
	LastTooLargeLimit         int    `json:"last_too_large_limit,omitempty"`
}

type PeerObjectPullStats struct {
	Attempts               int64  `json:"attempts,omitempty"`
	Successes              int64  `json:"successes,omitempty"`
	Failures               int64  `json:"failures,omitempty"`
	LargeObjectUnreachable int64  `json:"large_object_unreachable,omitempty"`
	LastUnix               int64  `json:"last_unix,omitempty"`
	LastError              string `json:"last_error,omitempty"`
	LastObject             string `json:"last_object,omitempty"`
	LastZone               string `json:"last_zone,omitempty"`
	LastKey                string `json:"last_key,omitempty"`
	LastBytes              int    `json:"last_bytes,omitempty"`
	LastSourcePeer         string `json:"last_source_peer,omitempty"`
	LastUnreachable        bool   `json:"last_unreachable,omitempty"`
}
