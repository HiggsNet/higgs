package state

// RoutingReconcileState captures the last routing reconcile run.
type RoutingReconcileState struct {
	LastRunUnix int64  `json:"last_run_unix,omitempty"`
	LastError   string `json:"last_error,omitempty"`
}
