package state

// EndpointACL is local, non-gossiped policy for one service endpoint. The
// daemon resolves Selectors against the current authorized route set whenever
// firewall state is reconciled.
type EndpointACL struct {
	Name        string   `json:"name"`
	Destination string   `json:"destination"`
	Protocol    string   `json:"protocol"`
	Port        uint16   `json:"port"`
	Selectors   []string `json:"selectors"`
}
