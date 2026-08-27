package http

type StatusResponse struct {
	PeerID            string `json:"peer_id,omitempty"`
	ManagedZone       string `json:"managed_zone,omitempty"`
	ListenAddr        string `json:"listen_addr,omitempty"`
	DaemonOnline      bool   `json:"daemon_online"`
	StateRevision     uint64 `json:"state_revision"`
	SnapshotTimeUnix  int64  `json:"snapshot_time_unix,omitempty"`
	Dirty             any    `json:"dirty,omitempty"`
	ReconcileProgress any    `json:"reconcile_progress,omitempty"`
	KnownZones        int    `json:"known_zones,omitempty"`
	KnownPeers        int    `json:"known_peers,omitempty"`
	LinkInstances     int    `json:"link_instances,omitempty"`
	DesiredLinks      int    `json:"desired_links,omitempty"`
	LastLinkError     string `json:"last_link_error,omitempty"`
	LastRoutingError  string `json:"last_routing_error,omitempty"`
	LastSyncUnix      int64  `json:"last_sync_unix,omitempty"`
	LastReconcileUnix int64  `json:"last_reconcile_unix,omitempty"`
}

type StatusInput struct {
	PeerID             string
	ManagedZone        string
	ListenAddr         string
	DaemonOnline       bool
	StateRevision      uint64
	SnapshotTimeUnix   int64
	Dirty              any
	ReconcileProgress  any
	KnownZones         int
	KnownPeers         int
	LinkInstances      int
	DesiredLinks       int
	LastLinkError      string
	LastRoutingError   string
	LastSyncUnix       int64
	IPsecLastRunUnix   int64
	RoutingLastRunUnix int64
}

func BuildStatusResponse(input StatusInput) StatusResponse {
	lastReconcileUnix := max(input.RoutingLastRunUnix, input.IPsecLastRunUnix)
	return StatusResponse{
		PeerID:            input.PeerID,
		ManagedZone:       input.ManagedZone,
		ListenAddr:        input.ListenAddr,
		DaemonOnline:      input.DaemonOnline,
		StateRevision:     input.StateRevision,
		SnapshotTimeUnix:  input.SnapshotTimeUnix,
		Dirty:             input.Dirty,
		ReconcileProgress: input.ReconcileProgress,
		KnownZones:        input.KnownZones,
		KnownPeers:        input.KnownPeers,
		LinkInstances:     input.LinkInstances,
		DesiredLinks:      input.DesiredLinks,
		LastLinkError:     input.LastLinkError,
		LastRoutingError:  input.LastRoutingError,
		LastSyncUnix:      input.LastSyncUnix,
		LastReconcileUnix: lastReconcileUnix,
	}
}
