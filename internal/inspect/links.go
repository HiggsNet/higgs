package inspect

import "sort"

type LinkInput struct {
	Instances      []LinkInstance
	LastDesired    []DesiredLink
	PlannedDesired []DesiredLink
	ActualSAs      []LinkSA
	Health         []LinkHealth
	Actions        []LinkAction
	Skipped        []LinkSkip
	LastRunUnix    int64
	DesiredLinks   int
	LastError      string
}

type LinkInspection struct {
	Summary LinkSummary
	Links   []LinkView
	Actions []LinkAction
	Skipped []LinkSkip
}

type LinkSummary struct {
	LastRunUnix       int64
	DesiredLinks      int
	PlannedDesired    int
	ActualSAs         int
	LinkInstances     int
	LastError         string
	DesiredPlanError  string
	HasPlannedDesired bool
	HasMissingPlanned bool
}

type LinkView struct {
	ID              string
	PeerZone        string
	GroupID         string
	TransportKind   string
	LinkID          string
	PathKey         string
	TransportID     string
	State           string
	ActualState     string
	Endpoint        string
	InterfaceName   string
	XFRMIfID        uint32
	LocalTunnelAddr string
	PeerTunnelAddr  string
	ChildSAName     string
	DesiredSpecHash string
	Desired         *DesiredLink
	ActualSA        *LinkSA
	Health          *LinkHealth
	Routing         LinkRouting
	Rotation        LinkRotation
	Takeover        LinkTakeover
	Owner           LinkOwner
	FailureCount    int
	BackoffUntil    int64
	LastTransition  int64
	LastError       string
	Missing         bool
}

type LinkInstance struct {
	ID                    string
	GroupID               string
	PeerZone              string
	TransportKind         string
	LinkID                string
	PathKey               string
	TransportID           string
	DesiredSpecHash       string
	ActualState           string
	InterfaceName         string
	XFRMIfID              uint32
	LocalTunnelAddr       string
	PeerTunnelAddr        string
	IKEName               string
	ChildSAName           string
	Endpoint              string
	RemoteGeneration      uint64
	StagedGeneration      uint64
	RotatePhase           string
	StagedIKEName         string
	StagedChildSAName     string
	StagedInterfaceName   string
	StagedXFRMIfID        uint32
	StagedLocalTunnelAddr string
	StagedPeerTunnelAddr  string
	RotateDeadline        int64
	LastError             string
	FailureCount          int
	BackoffUntil          int64
	LastTransition        int64
	Owner                 LinkOwner
	InitiatorRole         string
	TakeoverPhase         string
	TakeoverStartedAt     int64
	TakeoverUntil         int64
	LastTakeoverError     string
	ObservedInitiator     string
	Routing               LinkRouting
}

type LinkOwner struct {
	Manager     string `json:"manager,omitempty"`
	GroupID     string `json:"group_id,omitempty"`
	InstanceID  string `json:"instance_id,omitempty"`
	LinkID      string `json:"link_id,omitempty"`
	TransportID string `json:"transport_id,omitempty"`
	Token       string `json:"token,omitempty"`
}

type DesiredLink struct {
	InstanceID      string `json:"instance_id,omitempty"`
	GroupID         string `json:"group_id,omitempty"`
	PeerZone        string `json:"peer_zone,omitempty"`
	LinkID          string `json:"link_id,omitempty"`
	PathKey         string `json:"path_key,omitempty"`
	TransportID     string `json:"transport_id,omitempty"`
	DesiredSpecHash string `json:"desired_spec_hash,omitempty"`
	InterfaceName   string `json:"interface_name,omitempty"`
	XFRMIfID        uint32 `json:"xfrm_if_id,omitempty"`
	Endpoint        string `json:"endpoint,omitempty"`
	LocalTunnelAddr string `json:"local_tunnel_addr,omitempty"`
	PeerTunnelAddr  string `json:"peer_tunnel_addr,omitempty"`
}

type LinkSA struct {
	Name           string `json:"name,omitempty"`
	Peer           string `json:"peer,omitempty"`
	ChildSA        string `json:"child_sa,omitempty"`
	IKEState       string `json:"ike_state,omitempty"`
	ChildState     string `json:"child_state,omitempty"`
	XFRMIfID       uint32 `json:"xfrm_if_id,omitempty"`
	ReqID          uint32 `json:"reqid,omitempty"`
	LocalIdentity  string `json:"local_identity,omitempty"`
	RemoteIdentity string `json:"remote_identity,omitempty"`
	LocalEndpoint  string `json:"local_endpoint,omitempty"`
	RemoteEndpoint string `json:"remote_endpoint,omitempty"`
	Endpoint       string `json:"endpoint,omitempty"`
	Established    bool   `json:"established,omitempty"`
}

type LinkHealth struct {
	ProbeID         string `json:"probe_id,omitempty"`
	InstanceID      string `json:"instance_id"`
	ProbeRole       string `json:"probe_role,omitempty"`
	InterfaceName   string `json:"interface_name,omitempty"`
	State           string `json:"state"`
	ProbeType       string `json:"probe_type"`
	Sent            int    `json:"sent"`
	Received        int    `json:"received"`
	Lost            int    `json:"lost"`
	LossRatio       int    `json:"loss_ratio_pct"`
	LastRTTMs       int64  `json:"last_rtt_ms"`
	EWMARTTMs       int64  `json:"ewma_rtt_ms"`
	P50RTTMs        int64  `json:"p50_rtt_ms"`
	P95RTTMs        int64  `json:"p95_rtt_ms"`
	P99RTTMs        int64  `json:"p99_rtt_ms"`
	JitterMs        int64  `json:"jitter_ms"`
	ConsecutiveFail int    `json:"consecutive_fail"`
	LastError       string `json:"last_error,omitempty"`
	NextProbeUnix   int64  `json:"next_probe_unix,omitempty"`
	CutoverBlocking bool   `json:"cutover_blocking,omitempty"`
}

type LinkRouting struct {
	BirdState      string `json:"bird_state,omitempty"`
	BirdNeighbors  string `json:"bird_neighbors,omitempty"`
	BirdBestRoutes string `json:"bird_best_routes,omitempty"`
}

type LinkRotation struct {
	Phase                 string `json:"phase,omitempty"`
	RemoteGeneration      uint64 `json:"remote_generation,omitempty"`
	StagedGeneration      uint64 `json:"staged_generation,omitempty"`
	StagedIKEName         string `json:"staged_ike_name,omitempty"`
	StagedChildSAName     string `json:"staged_child_sa_name,omitempty"`
	StagedInterfaceName   string `json:"staged_interface_name,omitempty"`
	StagedXFRMIfID        uint32 `json:"staged_xfrm_if_id,omitempty"`
	StagedLocalTunnelAddr string `json:"staged_local_tunnel_addr,omitempty"`
	StagedPeerTunnelAddr  string `json:"staged_peer_tunnel_addr,omitempty"`
	RotateDeadline        int64  `json:"rotate_deadline,omitempty"`
}

type LinkTakeover struct {
	InitiatorRole     string `json:"initiator_role,omitempty"`
	Phase             string `json:"phase,omitempty"`
	StartedAt         int64  `json:"started_at,omitempty"`
	Until             int64  `json:"until,omitempty"`
	ObservedInitiator string `json:"observed_initiator,omitempty"`
	LastError         string `json:"last_error,omitempty"`
}

type LinkAction struct {
	Action     string `json:"action"`
	InstanceID string `json:"instance_id,omitempty"`
	GroupID    string `json:"group_id,omitempty"`
	PeerZone   string `json:"peer_zone,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

type LinkSkip struct {
	GroupID string `json:"group_id,omitempty"`
	Peer    string `json:"peer,omitempty"`
	Reason  string `json:"reason,omitempty"`
	Detail  string `json:"detail,omitempty"`
}

func BuildLinks(input LinkInput) LinkInspection {
	lastDesired := desiredByID(input.LastDesired)
	plannedDesired := desiredByID(input.PlannedDesired)
	sas := sasByID(input.ActualSAs)
	health := healthByID(input.Health)

	ids := make([]string, 0, len(input.Instances))
	instances := make(map[string]LinkInstance, len(input.Instances))
	for _, inst := range input.Instances {
		if inst.ID == "" {
			continue
		}
		instances[inst.ID] = inst
		ids = append(ids, inst.ID)
	}
	sort.Strings(ids)

	links := make([]LinkView, 0, len(ids))
	for _, id := range ids {
		inst := instances[id]
		desired, hasDesired := lastDesired[id]
		if planned, ok := plannedDesired[id]; ok {
			desired = planned
			hasDesired = true
		}
		links = append(links, linkFromInstance(inst, desired, hasDesired, linkSAForView(id, inst, desired, sas), health[id]))
	}
	if len(ids) == 0 && len(plannedDesired) > 0 {
		plannedIDs := make([]string, 0, len(plannedDesired))
		for id := range plannedDesired {
			plannedIDs = append(plannedIDs, id)
		}
		sort.Strings(plannedIDs)
		for _, id := range plannedIDs {
			desired := plannedDesired[id]
			links = append(links, missingLinkFromDesired(desired))
		}
	}

	return LinkInspection{
		Summary: LinkSummary{
			LastRunUnix:       input.LastRunUnix,
			DesiredLinks:      input.DesiredLinks,
			PlannedDesired:    len(plannedDesired),
			ActualSAs:         len(input.ActualSAs),
			LinkInstances:     len(ids),
			LastError:         input.LastError,
			HasPlannedDesired: len(plannedDesired) > 0,
			HasMissingPlanned: len(ids) == 0 && len(plannedDesired) > 0,
		},
		Links:   links,
		Actions: append([]LinkAction(nil), input.Actions...),
		Skipped: append([]LinkSkip(nil), input.Skipped...),
	}
}

func linkSAForView(id string, inst LinkInstance, desired DesiredLink, sas map[string]*LinkSA) *LinkSA {
	for _, key := range []string{id, inst.IKEName, inst.ChildSAName, inst.TransportID, desired.TransportID} {
		if key == "" {
			continue
		}
		if sa := sas[key]; sa != nil {
			return sa
		}
	}
	return nil
}

func linkFromInstance(inst LinkInstance, desired DesiredLink, hasDesired bool, sa *LinkSA, health *LinkHealth) LinkView {
	var desiredPtr *DesiredLink
	if hasDesired {
		desiredCopy := desired
		desiredPtr = &desiredCopy
	}
	localTunnel := inst.LocalTunnelAddr
	peerTunnel := inst.PeerTunnelAddr
	if linkInstanceMatchesDesiredRuntime(inst, desired) {
		localTunnel = firstNonEmpty(localTunnel, desired.LocalTunnelAddr)
		peerTunnel = firstNonEmpty(peerTunnel, desired.PeerTunnelAddr)
	}
	return LinkView{
		ID:              inst.ID,
		PeerZone:        inst.PeerZone,
		GroupID:         inst.GroupID,
		TransportKind:   inst.TransportKind,
		LinkID:          inst.LinkID,
		PathKey:         inst.PathKey,
		TransportID:     inst.TransportID,
		State:           firstNonEmpty(inst.ActualState, "unknown"),
		ActualState:     inst.ActualState,
		Endpoint:        firstNonEmpty(inst.Endpoint, desired.Endpoint),
		InterfaceName:   firstNonEmpty(inst.InterfaceName, desired.InterfaceName),
		XFRMIfID:        firstNonZeroUint32(inst.XFRMIfID, desired.XFRMIfID),
		LocalTunnelAddr: localTunnel,
		PeerTunnelAddr:  peerTunnel,
		ChildSAName:     inst.ChildSAName,
		DesiredSpecHash: firstNonEmpty(inst.DesiredSpecHash, desired.DesiredSpecHash),
		Desired:         desiredPtr,
		ActualSA:        sa,
		Health:          health,
		Routing:         inst.Routing,
		Rotation: LinkRotation{
			Phase:                 inst.RotatePhase,
			RemoteGeneration:      inst.RemoteGeneration,
			StagedGeneration:      inst.StagedGeneration,
			StagedIKEName:         inst.StagedIKEName,
			StagedChildSAName:     inst.StagedChildSAName,
			StagedInterfaceName:   inst.StagedInterfaceName,
			StagedXFRMIfID:        inst.StagedXFRMIfID,
			StagedLocalTunnelAddr: inst.StagedLocalTunnelAddr,
			StagedPeerTunnelAddr:  inst.StagedPeerTunnelAddr,
			RotateDeadline:        inst.RotateDeadline,
		},
		Takeover: LinkTakeover{
			InitiatorRole:     inst.InitiatorRole,
			Phase:             inst.TakeoverPhase,
			StartedAt:         inst.TakeoverStartedAt,
			Until:             inst.TakeoverUntil,
			ObservedInitiator: inst.ObservedInitiator,
			LastError:         inst.LastTakeoverError,
		},
		Owner:          inst.Owner,
		FailureCount:   inst.FailureCount,
		BackoffUntil:   inst.BackoffUntil,
		LastTransition: inst.LastTransition,
		LastError:      inst.LastError,
	}
}

func linkInstanceMatchesDesiredRuntime(inst LinkInstance, desired DesiredLink) bool {
	if desired.InterfaceName != "" && inst.InterfaceName != "" && desired.InterfaceName != inst.InterfaceName {
		return false
	}
	if desired.XFRMIfID != 0 && inst.XFRMIfID != 0 && desired.XFRMIfID != inst.XFRMIfID {
		return false
	}
	if desired.TransportID != "" && inst.TransportID != "" && desired.TransportID != inst.TransportID {
		return false
	}
	return true
}

func missingLinkFromDesired(desired DesiredLink) LinkView {
	desiredCopy := desired
	return LinkView{
		ID:              desired.InstanceID,
		PeerZone:        desired.PeerZone,
		GroupID:         desired.GroupID,
		LinkID:          desired.LinkID,
		PathKey:         desired.PathKey,
		TransportID:     desired.TransportID,
		State:           "missing",
		Endpoint:        desired.Endpoint,
		InterfaceName:   desired.InterfaceName,
		XFRMIfID:        desired.XFRMIfID,
		DesiredSpecHash: desired.DesiredSpecHash,
		Desired:         &desiredCopy,
		Missing:         true,
	}
}

func desiredByID(items []DesiredLink) map[string]DesiredLink {
	out := make(map[string]DesiredLink, len(items))
	for _, item := range items {
		if item.InstanceID != "" {
			out[item.InstanceID] = item
		}
	}
	return out
}

func sasByID(items []LinkSA) map[string]*LinkSA {
	out := make(map[string]*LinkSA, len(items))
	for i := range items {
		item := &items[i]
		if item.Name != "" {
			out[item.Name] = item
		}
		if item.ChildSA != "" {
			out[item.ChildSA] = item
		}
	}
	return out
}

func healthByID(items []LinkHealth) map[string]*LinkHealth {
	out := make(map[string]*LinkHealth, len(items))
	for i := range items {
		item := &items[i]
		if item.InstanceID != "" {
			if _, exists := out[item.InstanceID]; !exists || item.ProbeRole == "" || item.ProbeRole == "active" || item.ProbeRole == "staged" {
				out[item.InstanceID] = item
			}
		}
		if item.ProbeID != "" {
			out[item.ProbeID] = item
		}
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func firstNonZeroUint32(values ...uint32) uint32 {
	for _, value := range values {
		if value != 0 {
			return value
		}
	}
	return 0
}
