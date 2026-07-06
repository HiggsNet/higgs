package http

type BirdResponse struct {
	Instances        any    `json:"instances"`
	LastRoutingError string `json:"last_routing_error,omitempty"`
}
