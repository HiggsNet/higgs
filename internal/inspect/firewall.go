package inspect

import higgsstate "github.com/Catofes/higgs/internal/state"

const FirewallModeManaged = "managed"

type FirewallDebugView struct {
	Backend   string
	LastError string
	Instances []FirewallInstanceView
}

type FirewallDebugInput struct {
	Instances []FirewallInstanceInput
	Reconcile *higgsstate.FirewallReconcileState
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
	view := FirewallDebugView{}
	if input.Reconcile != nil {
		view.Backend = input.Reconcile.Backend
		view.LastError = input.Reconcile.LastError
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
		if snapshot, ok := firewallReconcileInstance(input.Reconcile, inst.ID); ok {
			instView.Generation = snapshot.Generation
			instView.OwnedObjects = snapshot.OwnedObjects
			instView.PolicyHash = snapshot.PolicyHash
			instView.LastError = snapshot.LastError
		}
		view.Instances = append(view.Instances, instView)
	}
	return view
}

func firewallReconcileInstance(reconcile *higgsstate.FirewallReconcileState, id string) (*higgsstate.FirewallReconcileInstance, bool) {
	if reconcile == nil || reconcile.Instances == nil {
		return nil, false
	}
	snapshot, ok := reconcile.Instances[id]
	return snapshot, ok && snapshot != nil
}
