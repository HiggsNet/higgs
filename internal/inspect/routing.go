package inspect

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
