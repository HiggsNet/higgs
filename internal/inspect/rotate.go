package inspect

type RotateDebugView struct {
	LastRunUnix       int64
	LinkInstances     int
	PlannedDesired    int
	ReplanIgnored     bool
	LastDesiredLinks  int
	DesiredPlanSource string
	Filter            string
	StoredLabel       string
	LiveLabel         string
	StoredSACount     int
	LiveSACount       int
	LiveSAError       string
	Links             []RotateDebugLink
}

type RotateDebugLink struct {
	Link                  LinkView
	PortGenerationSummary string
	PortSummary           string
	Current               RotateRuntimeView
	Staged                RotateRuntimeView
	HasStaged             bool
	StoredMatchingSAs     []LinkSA
	LiveMatchingSAs       []LinkSA
}

type RotateRuntimeView struct {
	State           string
	Generation      uint64
	Port            string
	RuntimeID       string
	ChildSAName     string
	InterfaceName   string
	XFRMIfID        uint32
	Endpoint        string
	LocalTunnelAddr string
	PeerTunnelAddr  string
}
