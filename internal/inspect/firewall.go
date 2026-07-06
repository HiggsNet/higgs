package inspect

type FirewallDebugView struct {
	Backend   string
	LastError string
	Instances []FirewallInstanceView
}

type FirewallInstanceView struct {
	ID            string
	Scope         string
	Mode          string
	Backend       string
	DefaultPolicy string
	OwnerPrefix   string
	Transit       bool
	AllowPrefixes int
	DenyPrefixes  int
	LocalServices []FirewallLocalServiceView
	IsHost        bool
	HostIKE       bool
	HostNATT      bool
	RedirectGrace bool
	Generation    uint64
	OwnedObjects  int
	PolicyHash    string
	LastError     string
}

type FirewallLocalServiceView struct {
	Proto string
	Port  uint16
}
