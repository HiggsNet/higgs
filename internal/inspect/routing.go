package inspect

import higgsstate "github.com/Catofes/higgs/internal/state"

const (
	RoutingModeManaged           = "managed"
	RoutingModeExternal          = "external"
	RoutingModeDisabled          = "disabled"
	RoutingShutdownPolicyPersist = "persist"
)

type BirdDumpResponse struct {
	Instances map[string]BirdDumpInstance `json:"instances"`
}

type BirdDumpInstance struct {
	NetNS         string            `json:"netns"`
	InstanceID    string            `json:"instance_id"`
	ControlSocket string            `json:"control_socket"`
	Command       string            `json:"command,omitempty"`
	Raw           map[string]string `json:"raw,omitempty"`
	Error         string            `json:"error,omitempty"`
}

type BabelDebugView struct {
	LastReconcileError string
	Instances          []BabelInstanceView
}

type BabelDebugInput struct {
	LastReconcileError string
	Instances          []BabelInstanceInput
	RuntimeStates      map[string]*higgsstate.BirdInstanceState
}

type BabelInstanceInput struct {
	NetNS          string
	InstanceID     string
	Mode           string
	ShutdownPolicy string
	Enabled        bool
}

type BabelInstanceView struct {
	NetNS          string
	InstanceID     string
	Mode           string
	ShutdownPolicy string
	Enabled        bool
	RouterID       uint32
	ControlSocket  string
	ConfigPath     string
	PIDFile        string
	LastConfigHash string
	Overlays       []string
	State          string
	LastError      string
	HasState       bool
}

func BuildBabelDebug(input BabelDebugInput) BabelDebugView {
	view := BabelDebugView{LastReconcileError: input.LastReconcileError}
	for _, inst := range input.Instances {
		mode := inst.Mode
		if mode == "" {
			mode = RoutingModeManaged
		}
		if !inst.Enabled {
			mode = RoutingModeDisabled
		}
		instView := BabelInstanceView{
			NetNS:      inst.NetNS,
			InstanceID: inst.InstanceID,
			Mode:       mode,
			Enabled:    inst.Enabled,
		}
		if inst.Mode != RoutingModeExternal && inst.Mode != RoutingModeDisabled {
			instView.ShutdownPolicy = normalizedRoutingShutdownPolicy(inst.ShutdownPolicy)
		}
		if !inst.Enabled {
			view.Instances = append(view.Instances, instView)
			continue
		}
		runtime, ok := input.RuntimeStates[inst.NetNS]
		if ok && runtime != nil {
			instView.HasState = true
			instView.RouterID = runtime.RouterID
			instView.ControlSocket = runtime.ControlSocket
			instView.ConfigPath = runtime.ConfigPath
			instView.PIDFile = runtime.PIDFile
			instView.LastConfigHash = runtime.LastConfigHash
			instView.Overlays = append([]string(nil), runtime.Overlays...)
			instView.State = runtime.State
			instView.LastError = runtime.LastError
		}
		view.Instances = append(view.Instances, instView)
	}
	return view
}

func normalizedRoutingShutdownPolicy(policy string) string {
	if policy == "" {
		return RoutingShutdownPolicyPersist
	}
	return policy
}
