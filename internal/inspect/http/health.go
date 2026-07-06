package http

import "sort"

type HealthResponse struct {
	Datasource any                 `json:"datasource"`
	Links      []HealthContextItem `json:"links"`
}

type HealthSeriesResponse struct {
	Datasource any    `json:"datasource"`
	LinkID     string `json:"link_id"`
	Series     any    `json:"series"`
}

type HealthContextItem struct {
	Health          any    `json:"health"`
	Instance        any    `json:"instance,omitempty"`
	Desired         any    `json:"desired,omitempty"`
	PeerZone        any    `json:"peer_zone,omitempty"`
	GroupID         string `json:"group_id,omitempty"`
	InterfaceName   string `json:"interface_name,omitempty"`
	Endpoint        string `json:"endpoint,omitempty"`
	ActualState     string `json:"actual_state,omitempty"`
	LocalTunnelAddr string `json:"local_tunnel_addr,omitempty"`
	PeerTunnelAddr  string `json:"peer_tunnel_addr,omitempty"`
	SortInstanceID  string `json:"-"`
	SortProbeRole   string `json:"-"`
}

type HealthContextInput struct {
	HealthLinks []HealthLinkContextInput
	Instances   map[string]HealthInstanceContextInput
	Desired     map[string]HealthDesiredContextInput
	Unknown     func(instanceID string) any
}

type HealthLinkContextInput struct {
	InstanceID    string
	ProbeID       string
	ProbeRole     string
	InterfaceName string
	Health        any
}

type HealthInstanceContextInput struct {
	ID            string
	PeerZone      any
	GroupID       string
	InterfaceName string
	Endpoint      string
	ActualState   string
	Instance      any
}

type HealthDesiredContextInput struct {
	InstanceID      string
	PeerZone        any
	GroupID         string
	InterfaceName   string
	LocalTunnelAddr string
	PeerTunnelAddr  string
	Desired         any
}

func BuildHealthContext(input HealthContextInput) []HealthContextItem {
	healthBaseIDs := map[string]bool{}
	out := make([]HealthContextItem, 0, len(input.HealthLinks)+len(input.Instances))
	for _, health := range input.HealthLinks {
		if health.InstanceID == "" {
			continue
		}
		healthBaseIDs[health.InstanceID] = true
		out = append(out, buildHealthContextItem(health, input.Instances[health.InstanceID], input.Desired[health.InstanceID]))
	}
	ids := make([]string, 0, len(input.Instances))
	for id := range input.Instances {
		if !healthBaseIDs[id] {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	for _, id := range ids {
		rawHealth := any(map[string]any{
			"instance_id": id,
			"state":       "unknown",
		})
		if input.Unknown != nil {
			rawHealth = input.Unknown(id)
		}
		health := HealthLinkContextInput{
			InstanceID: id,
			Health:     rawHealth,
		}
		out = append(out, buildHealthContextItem(health, input.Instances[id], input.Desired[id]))
	}
	sort.SliceStable(out, func(i, j int) bool {
		hi := inputHealthSortKey(out[i])
		hj := inputHealthSortKey(out[j])
		if hi.instanceID != hj.instanceID {
			return hi.instanceID < hj.instanceID
		}
		return hi.probeRole < hj.probeRole
	})
	return out
}

func buildHealthContextItem(health HealthLinkContextInput, inst HealthInstanceContextInput, desired HealthDesiredContextInput) HealthContextItem {
	item := HealthContextItem{
		Health:         health.Health,
		SortInstanceID: health.InstanceID,
		SortProbeRole:  health.ProbeRole,
	}
	if item.Health == nil {
		item.Health = map[string]any{"instance_id": health.InstanceID}
	}
	if inst.ID != "" {
		item.Instance = inst.Instance
		item.PeerZone = inst.PeerZone
		item.GroupID = inst.GroupID
		item.InterfaceName = firstNonEmpty(health.InterfaceName, inst.InterfaceName)
		item.Endpoint = inst.Endpoint
		item.ActualState = inst.ActualState
	}
	if desired.InstanceID != "" {
		item.Desired = desired.Desired
		if item.PeerZone == nil {
			item.PeerZone = desired.PeerZone
		}
		if item.GroupID == "" {
			item.GroupID = desired.GroupID
		}
		if item.InterfaceName == "" {
			item.InterfaceName = firstNonEmpty(health.InterfaceName, desired.InterfaceName)
		}
		item.LocalTunnelAddr = desired.LocalTunnelAddr
		item.PeerTunnelAddr = desired.PeerTunnelAddr
	}
	if item.InterfaceName == "" && health.InterfaceName != "" {
		item.InterfaceName = health.InterfaceName
	}
	return item
}

type healthSortKey struct {
	instanceID string
	probeRole  string
}

func inputHealthSortKey(item HealthContextItem) healthSortKey {
	if item.SortInstanceID != "" || item.SortProbeRole != "" {
		return healthSortKey{instanceID: item.SortInstanceID, probeRole: item.SortProbeRole}
	}
	if link, ok := item.Health.(HealthLinkContextInput); ok {
		return healthSortKey{instanceID: link.InstanceID, probeRole: link.ProbeRole}
	}
	if link, ok := item.Health.(interface {
		HealthContextSortKey() (string, string)
	}); ok {
		instanceID, probeRole := link.HealthContextSortKey()
		return healthSortKey{instanceID: instanceID, probeRole: probeRole}
	}
	if m, ok := item.Health.(map[string]any); ok {
		instanceID, _ := m["instance_id"].(string)
		probeRole, _ := m["probe_role"].(string)
		return healthSortKey{instanceID: instanceID, probeRole: probeRole}
	}
	return healthSortKey{}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
