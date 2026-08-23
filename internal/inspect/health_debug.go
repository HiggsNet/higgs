package inspect

import "sort"

const (
	HealthSortPeer = "peer"
	HealthSortRTT  = "rtt"
)

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
	return BuildHealthView(view, HealthSortPeer)
}

func BuildHealthView(view HealthDebugView, sortBy string) HealthDebugView {
	out := view
	out.Targets = append([]HealthProbeTargetView(nil), view.Targets...)
	out.Live = append([]HealthLiveView(nil), view.Live...)
	liveByProbe := make(map[string]HealthLiveView, len(out.Live))
	for _, live := range out.Live {
		key := live.ProbeID
		if key == "" {
			key = live.InstanceID
		}
		liveByProbe[key] = live
	}
	sort.SliceStable(out.Targets, func(i, j int) bool {
		left, right := out.Targets[i], out.Targets[j]
		if sortBy == HealthSortRTT {
			leftRTT, leftOK := healthSortRTT(liveByProbe[healthTargetProbeID(left)])
			rightRTT, rightOK := healthSortRTT(liveByProbe[healthTargetProbeID(right)])
			if leftOK != rightOK {
				return leftOK
			}
			if leftOK && leftRTT != rightRTT {
				return leftRTT < rightRTT
			}
		}
		if left.PeerZone != right.PeerZone {
			return ZonePathLess(right.PeerZone, left.PeerZone)
		}
		if left.InstanceID != right.InstanceID {
			return left.InstanceID < right.InstanceID
		}
		if left.ProbeRole != right.ProbeRole {
			return left.ProbeRole < right.ProbeRole
		}
		return left.ProbeID < right.ProbeID
	})
	return out
}

func healthTargetProbeID(target HealthProbeTargetView) string {
	if target.ProbeID != "" {
		return target.ProbeID
	}
	return target.InstanceID
}

func healthSortRTT(live HealthLiveView) (int64, bool) {
	if live.EWMARTTMs > 0 {
		return live.EWMARTTMs, true
	}
	if live.LastRTTMs > 0 {
		return live.LastRTTMs, true
	}
	return 0, false
}
