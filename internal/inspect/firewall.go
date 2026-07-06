package inspect

const FirewallModeManaged = "managed"

type FirewallDebugView struct {
	Backend   string
	LastError string
	Instances []FirewallInstanceView
}

type FirewallDebugInput struct {
	Backend   string
	LastError string
	Instances []FirewallInstanceInput
	Snapshot  map[string]FirewallInstanceSnapshot
}

type FirewallInstanceInput struct {
	ID            string
	Scope         string
	Enabled       bool
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
}

type FirewallInstanceSnapshot struct {
	Generation   uint64
	OwnedObjects int
	PolicyHash   string
	LastError    string
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

func BuildFirewallDebug(input FirewallDebugInput) FirewallDebugView {
	view := FirewallDebugView{
		Backend:   input.Backend,
		LastError: input.LastError,
	}
	if len(input.Instances) == 0 {
		return view
	}
	for _, inst := range input.Instances {
		mode := inst.Mode
		if mode == "" {
			mode = FirewallModeManaged
		}
		if !inst.Enabled {
			mode = "disabled"
		}
		scope := inst.Scope
		if inst.IsHost {
			scope = "host"
		}
		instView := FirewallInstanceView{
			ID:            inst.ID,
			Scope:         scope,
			Mode:          mode,
			Backend:       inst.Backend,
			DefaultPolicy: inst.DefaultPolicy,
			OwnerPrefix:   inst.OwnerPrefix,
			Transit:       inst.Transit,
			AllowPrefixes: inst.AllowPrefixes,
			DenyPrefixes:  inst.DenyPrefixes,
			LocalServices: append([]FirewallLocalServiceView(nil), inst.LocalServices...),
			IsHost:        inst.IsHost,
			HostIKE:       inst.HostIKE,
			HostNATT:      inst.HostNATT,
			RedirectGrace: inst.RedirectGrace,
		}
		if snapshot, ok := input.Snapshot[inst.ID]; ok {
			instView.Generation = snapshot.Generation
			instView.OwnedObjects = snapshot.OwnedObjects
			instView.PolicyHash = snapshot.PolicyHash
			instView.LastError = snapshot.LastError
		}
		view.Instances = append(view.Instances, instView)
	}
	return view
}
