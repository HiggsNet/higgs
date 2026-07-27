package state

// EndpointACL is local, non-gossiped policy for one service endpoint. The
// daemon resolves Selectors against the current authorized route set whenever
// firewall state is reconciled.
type EndpointACL struct {
	Name        string   `json:"name"`
	Destination string   `json:"destination"`
	Scope       string   `json:"scope,omitempty"`
	Protocol    string   `json:"protocol,omitempty"`
	Port        uint16   `json:"port,omitempty"`
	Selectors   []string `json:"selectors"`
}
