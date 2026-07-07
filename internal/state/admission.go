package state

// AdmissionState tracks auto-join admission diagnostics. It is persisted so
// that pending reasons survive daemon restarts and operators can inspect
// why a node has not yet been adopted.
type AdmissionState struct {
	// Pending is true when the node is in auto-join pending state.
	Pending bool `json:"pending,omitempty"`
	// PendingSinceUnix is when the node first entered pending state.
	PendingSinceUnix int64 `json:"pending_since_unix,omitempty"`
	// AdoptedAtUnix is when the node was most recently adopted (0 = never).
	AdoptedAtUnix int64 `json:"adopted_at_unix,omitempty"`
	// LastAdoptionError records the most recent adoption failure.
	LastAdoptionError string `json:"last_adoption_error,omitempty"`
	// LastBootstrapSyncUnix tracks the most recent successful bootstrap peer
	// sync round while pending (0 = never synced).
	LastBootstrapSyncUnix int64 `json:"last_bootstrap_sync_unix,omitempty"`
	// JoinRequestB64 is the base64-encoded join request that the parent zone
	// admin needs to sign a delegation for.
	JoinRequestB64 string `json:"join_request_b64,omitempty"`
	// PendingReason is the structured diagnostic reason for the current
	// pending state (e.g. missing_parent_zone, missing_delegation,
	// delegation_key_mismatch, verify_chain_failed, no_bootstrap_sync).
	PendingReason string `json:"pending_reason,omitempty"`
	// PendingReasonDetail provides additional context for the pending reason.
	PendingReasonDetail string `json:"pending_reason_detail,omitempty"`
}
