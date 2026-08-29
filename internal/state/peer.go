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
	DiscoveredAddr          string                        `json:"discovered_addr,omitempty"`
	DiscoveredAtUnix        int64                         `json:"discovered_at_unix,omitempty"`
	ObservedAddr            string                        `json:"observed_addr,omitempty"`
	ObservedFirstSeenUnix   int64                         `json:"observed_first_seen_unix,omitempty"`
	ObservedLastSeenUnix    int64                         `json:"observed_last_seen_unix,omitempty"`
	ObservedLastSyncUnix    int64                         `json:"observed_last_sync_unix,omitempty"`
	ObservedUntilUnix       int64                         `json:"observed_until_unix,omitempty"`
	ObservedFailureCount    int                           `json:"observed_failure_count,omitempty"`
	ObservedGraceAddrs      []PeerObservedGraceAddrState  `json:"observed_grace_addrs,omitempty"`
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
