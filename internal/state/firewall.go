package state

type FirewallReconcileState struct {
	Backend     string                                `json:"backend,omitempty"`
	Instances   map[string]*FirewallReconcileInstance `json:"instances,omitempty"`
	LastRunUnix int64                                 `json:"last_run_unix,omitempty"`
	LastError   string                                `json:"last_error,omitempty"`
}

type FirewallReconcileInstance struct {
	Generation   uint64 `json:"generation,omitempty"`
	LastRunUnix  int64  `json:"last_run_unix,omitempty"`
	LastError    string `json:"last_error,omitempty"`
	PolicyHash   string `json:"policy_hash,omitempty"`
	OwnedObjects int    `json:"owned_objects,omitempty"`
}
