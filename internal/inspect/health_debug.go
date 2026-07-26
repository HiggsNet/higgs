package inspect

import "sort"

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
	UnderlayFamily  string
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

func BuildHealthDebugView(view HealthDebugView) HealthDebugView {
	out := view
	out.Targets = append([]HealthProbeTargetView(nil), view.Targets...)
	out.Live = append([]HealthLiveView(nil), view.Live...)
	sort.SliceStable(out.Targets, func(i, j int) bool {
		if out.Targets[i].InstanceID != out.Targets[j].InstanceID {
			return out.Targets[i].InstanceID < out.Targets[j].InstanceID
		}
		if out.Targets[i].ProbeRole != out.Targets[j].ProbeRole {
			return out.Targets[i].ProbeRole < out.Targets[j].ProbeRole
		}
		return out.Targets[i].ProbeID < out.Targets[j].ProbeID
	})
	return out
}
