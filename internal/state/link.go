package state

import "github.com/HiggsNet/photon/pkg/core/zone"

// LinkInstanceState is the persisted runtime state of a single IPsec link
// instance.
type LinkInstanceState struct {
	ID                    string         `json:"id"`
	GroupID               string         `json:"group_id,omitempty"`
	PeerZone              zone.ZonePath  `json:"peer_zone"`
	TransportKind         string         `json:"transport_kind,omitempty"`
	LinkID                string         `json:"link_id,omitempty"`
	PathKey               string         `json:"path_key,omitempty"`
	TransportID           string         `json:"transport_id,omitempty"`
	DesiredSpecHash       string         `json:"desired_spec_hash,omitempty"`
	ActualState           string         `json:"actual_state,omitempty"`
	InterfaceName         string         `json:"interface_name,omitempty"`
	XFRMIfID              uint32         `json:"xfrm_if_id,omitempty"`
	LocalTunnelAddr       string         `json:"local_tunnel_addr,omitempty"`
	PeerTunnelAddr        string         `json:"peer_tunnel_addr,omitempty"`
	IKEName               string         `json:"ike_name,omitempty"`
	ChildSAName           string         `json:"child_sa_name,omitempty"`
	Endpoint              string         `json:"endpoint,omitempty"`
	RemoteGeneration      uint64         `json:"remote_generation,omitempty"`
	StagedGeneration      uint64         `json:"staged_generation,omitempty"`
	RotatePhase           string         `json:"rotate_phase,omitempty"`
	StagedIKEName         string         `json:"staged_ike_name,omitempty"`
	StagedChildSAName     string         `json:"staged_child_sa_name,omitempty"`
	StagedInterfaceName   string         `json:"staged_interface_name,omitempty"`
	StagedXFRMIfID        uint32         `json:"staged_xfrm_if_id,omitempty"`
	StagedLocalTunnelAddr string         `json:"staged_local_tunnel_addr,omitempty"`
	StagedPeerTunnelAddr  string         `json:"staged_peer_tunnel_addr,omitempty"`
	RotateDeadline        int64          `json:"rotate_deadline,omitempty"`
	LastError             string         `json:"last_error,omitempty"`
	FailureCount          int            `json:"failure_count,omitempty"`
	BackoffUntil          int64          `json:"backoff_until,omitempty"`
	LastTransition        int64          `json:"last_transition,omitempty"`
	Owner                 LinkOwnerState `json:"owner,omitempty"`

	// Phase 4.5 bidirectional takeover state.
	InitiatorRole     string `json:"initiator_role,omitempty"`
	TakeoverPhase     string `json:"takeover_phase,omitempty"`
	TakeoverStartedAt int64  `json:"takeover_started_at,omitempty"`
	TakeoverUntil     int64  `json:"takeover_until,omitempty"`
	LastTakeoverError string `json:"last_takeover_error,omitempty"`
	ObservedInitiator string `json:"observed_initiator,omitempty"`
	SAAbsentSince     int64  `json:"sa_absent_since,omitempty"`
	SAAbsentCount     int    `json:"sa_absent_count,omitempty"`
}

// LinkOwnerState identifies the Photon owner of a link instance.
type LinkOwnerState struct {
	Manager     string `json:"manager,omitempty"`
	GroupID     string `json:"group_id,omitempty"`
	InstanceID  string `json:"instance_id,omitempty"`
	LinkID      string `json:"link_id,omitempty"`
	TransportID string `json:"transport_id,omitempty"`
	Token       string `json:"token,omitempty"`
}
