package http

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
}
