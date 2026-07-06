package http

import "github.com/Catofes/higgs/internal/inspect"

type PeersResponse struct {
	Peers []PeerJSON `json:"peers"`
}

type PeerJSON struct {
	PeerID                string                     `json:"peer_id"`
	Source                string                     `json:"source,omitempty"`
	ConfiguredAddr        string                     `json:"configured_addr,omitempty"`
	LastSyncUnix          int64                      `json:"last_sync_unix"`
	LastAttemptUnix       int64                      `json:"last_attempt_unix"`
	BackoffUntilUnix      int64                      `json:"backoff_until_unix"`
	LastRelayUnix         int64                      `json:"last_relay_unix,omitempty"`
	FailureCount          int                        `json:"failure_count"`
	LastError             string                     `json:"last_error,omitempty"`
	LastUpdateSource      string                     `json:"last_update_source,omitempty"`
	LastRelaySuppression  string                     `json:"last_relay_suppression,omitempty"`
	LastRelaySuppressedAt int64                      `json:"last_relay_suppressed_at,omitempty"`
	DiscoveredAddr        string                     `json:"discovered_addr,omitempty"`
	DiscoveredAtUnix      int64                      `json:"discovered_at_unix,omitempty"`
	ObservedAddr          string                     `json:"observed_addr,omitempty"`
	ObservedFirstSeenUnix int64                      `json:"observed_first_seen_unix,omitempty"`
	ObservedLastSeenUnix  int64                      `json:"observed_last_seen_unix,omitempty"`
	ObservedLastSyncUnix  int64                      `json:"observed_last_sync_unix,omitempty"`
	ObservedUntilUnix     int64                      `json:"observed_until_unix,omitempty"`
	ObservedSource        string                     `json:"observed_source,omitempty"`
	ObservedFailureCount  int                        `json:"observed_failure_count,omitempty"`
	ObservedGraceAddrs    any                        `json:"observed_grace_addrs,omitempty"`
	Endpoints             []inspect.PeerEndpointView `json:"endpoints,omitempty"`
	DatagramStats         any                        `json:"datagram_stats,omitempty"`
	ObjectPullStats       any                        `json:"object_pull_stats,omitempty"`
	RejectedDigests       any                        `json:"rejected_digests,omitempty"`
}
