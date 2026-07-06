package inspect

type HealthDebugView struct {
	Targets []HealthProbeTargetView
	Live    []HealthLiveView
}

type HealthProbeTargetView struct {
	ProbeID         string
	InstanceID      string
	PeerZone        string
	Overlay         string
	InterfaceName   string
	LocalTunnelAddr string
	PeerTunnelAddr  string
	ProbeRole       string
	State           string
	Staged          bool
}

type HealthLiveView struct {
	ProbeID         string
	InstanceID      string
	ProbeRole       string
	State           string
	ProbeType       string
	Sent            int
	Received        int
	Lost            int
	LossRatio       int
	LastRTTMs       int64
	EWMARTTMs       int64
	P50RTTMs        int64
	P95RTTMs        int64
	P99RTTMs        int64
	JitterMs        int64
	ConsecutiveFail int
	LastError       string
	CutoverBlocking bool
}
