package inspect

type SyncStatusView struct {
	PeerID          string
	ListenAddr      string
	KnownPeers      int
	KnownZones      int
	LocalRootHex    string
	Limits          SyncLimitsView
	Verbose         bool
	AllowlistSource string
	BootstrapPeers  int
	DiscoveredPeers int
	Bootstrap       []SyncVerbosePeerView
	Discovered      []SyncVerbosePeerView
	Peers           []SyncPeerSummaryView
	Zones           []SyncZoneSummaryView
}

type SyncLimitsView struct {
	MaxDatagramBytes int
	MaxSyncZones     int
	MaxSyncRecords   int
	WireVersion      int
	WireCodec        string
}

type SyncVerbosePeerView struct {
	PeerDebugView
	Addr string
}

type SyncPeerSummaryView struct {
	PeerID     string
	Addr       string
	Status     string
	LastSync   string
	KnownZones int
	LastError  string
	NextRetry  string
}

type SyncZoneSummaryView struct {
	Zone        string
	RootHex     string
	Records     int
	History     int
	Delegations int
	Revocations int
}
