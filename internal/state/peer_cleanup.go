package state

// PeerLifecycleCleanupState is a local suppression marker. It prevents stale,
// still-valid zone records from recreating platform links after an inactive
// peer has been cleaned up, until that peer synchronizes successfully again.
type PeerLifecycleCleanupState struct {
	LastActiveUnix int64  `json:"last_active_unix,omitempty"`
	CleanupUnix    int64  `json:"cleanup_unix"`
	Reason         string `json:"reason"`
}
