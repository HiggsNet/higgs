package http

import (
	"github.com/Catofes/higgs/internal/inspect"
	higgsstate "github.com/Catofes/higgs/internal/state"
)

type PeersResponse struct {
	Peers []PeerJSON `json:"peers"`
}

type PeerJSON struct {
	PeerID         string                     `json:"peer_id"`
	Source         string                     `json:"source,omitempty"`
	ConfiguredAddr string                     `json:"configured_addr,omitempty"`
	Endpoints      []inspect.PeerEndpointView `json:"endpoints,omitempty"`
	PeerRuntimeJSON
}

type PeerRuntimeJSON struct {
	LastSyncUnix          int64                                    `json:"last_sync_unix"`
	LastAttemptUnix       int64                                    `json:"last_attempt_unix"`
	BackoffUntilUnix      int64                                    `json:"backoff_until_unix"`
	LastRelayUnix         int64                                    `json:"last_relay_unix,omitempty"`
	FailureCount          int                                      `json:"failure_count"`
	LastError             string                                   `json:"last_error,omitempty"`
	LastUpdateSource      string                                   `json:"last_update_source,omitempty"`
	LastRelaySuppression  string                                   `json:"last_relay_suppression,omitempty"`
	LastRelaySuppressedAt int64                                    `json:"last_relay_suppressed_at,omitempty"`
	DiscoveredAddr        string                                   `json:"discovered_addr,omitempty"`
	DiscoveredAtUnix      int64                                    `json:"discovered_at_unix,omitempty"`
	ObservedAddr          string                                   `json:"observed_addr,omitempty"`
	ObservedFirstSeenUnix int64                                    `json:"observed_first_seen_unix,omitempty"`
	ObservedLastSeenUnix  int64                                    `json:"observed_last_seen_unix,omitempty"`
	ObservedLastSyncUnix  int64                                    `json:"observed_last_sync_unix,omitempty"`
	ObservedUntilUnix     int64                                    `json:"observed_until_unix,omitempty"`
	ObservedSource        string                                   `json:"observed_source,omitempty"`
	ObservedFailureCount  int                                      `json:"observed_failure_count,omitempty"`
	ObservedGraceAddrs    []higgsstate.PeerObservedGraceAddrState  `json:"observed_grace_addrs,omitempty"`
	ActivePullState       string                                   `json:"active_pull_state,omitempty"`
	ActivePullLastEvent   string                                   `json:"active_pull_last_event,omitempty"`
	ActivePullUpdatedUnix int64                                    `json:"active_pull_updated_unix,omitempty"`
	HintAccepted          int64                                    `json:"hint_accepted,omitempty"`
	HintSuppressed        int64                                    `json:"hint_suppressed,omitempty"`
	LastHintUnix          int64                                    `json:"last_hint_unix,omitempty"`
	LastHintReason        string                                   `json:"last_hint_reason,omitempty"`
	LastHintSuppression   string                                   `json:"last_hint_suppression,omitempty"`
	ReadOnlyResponder     int64                                    `json:"read_only_responder,omitempty"`
	LastResponderUnix     int64                                    `json:"last_responder_unix,omitempty"`
	LastResponderKind     string                                   `json:"last_responder_kind,omitempty"`
	LastResponderZone     string                                   `json:"last_responder_zone,omitempty"`
	DatagramStats         *higgsstate.PeerDatagramStats            `json:"datagram_stats,omitempty"`
	ObjectPullStats       *higgsstate.PeerObjectPullStats          `json:"object_pull_stats,omitempty"`
	RejectedDigests       map[string]higgsstate.PeerRejectedDigest `json:"rejected_digests,omitempty"`
}

func PeerRuntimeJSONFromState(state higgsstate.PeerRuntimeState) PeerRuntimeJSON {
	return PeerRuntimeJSON{
		LastSyncUnix:          state.LastSyncUnix,
		LastAttemptUnix:       state.LastAttemptUnix,
		BackoffUntilUnix:      state.BackoffUntilUnix,
		LastRelayUnix:         state.LastRelayUnix,
		FailureCount:          state.FailureCount,
		LastError:             state.LastError,
		LastUpdateSource:      state.LastUpdateSource,
		LastRelaySuppression:  state.LastRelaySuppression,
		LastRelaySuppressedAt: state.LastRelaySuppressedAt,
		DiscoveredAddr:        state.DiscoveredAddr,
		DiscoveredAtUnix:      state.DiscoveredAtUnix,
		ObservedAddr:          state.ObservedAddr,
		ObservedFirstSeenUnix: state.ObservedFirstSeenUnix,
		ObservedLastSeenUnix:  state.ObservedLastSeenUnix,
		ObservedLastSyncUnix:  state.ObservedLastSyncUnix,
		ObservedUntilUnix:     state.ObservedUntilUnix,
		ObservedSource:        state.ObservedSource,
		ObservedFailureCount:  state.ObservedFailureCount,
		ObservedGraceAddrs:    state.ObservedGraceAddrs,
		ActivePullState:       state.ActivePullState,
		ActivePullLastEvent:   state.ActivePullLastEvent,
		ActivePullUpdatedUnix: state.ActivePullUpdatedUnix,
		HintAccepted:          state.HintAccepted,
		HintSuppressed:        state.HintSuppressed,
		LastHintUnix:          state.LastHintUnix,
		LastHintReason:        state.LastHintReason,
		LastHintSuppression:   state.LastHintSuppression,
		ReadOnlyResponder:     state.ReadOnlyResponder,
		LastResponderUnix:     state.LastResponderUnix,
		LastResponderKind:     state.LastResponderKind,
		LastResponderZone:     state.LastResponderZone,
		DatagramStats:         state.DatagramStats,
		ObjectPullStats:       state.ObjectPullStats,
		RejectedDigests:       state.RejectedDigests,
	}
}
