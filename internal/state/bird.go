package state

import "github.com/Catofes/photon/pkg/routing/bird"

type BirdInstanceState struct {
	NetNSName        string                 `json:"netns_name"`
	Overlays         []string               `json:"overlays,omitempty"`
	ConfigPath       string                 `json:"config_path"`
	ControlSocket    string                 `json:"control_socket"`
	PIDFile          string                 `json:"pid_file"`
	RouterID         uint32                 `json:"router_id"`
	Owner            bird.BirdResourceOwner `json:"owner,omitempty"`
	LastConfigHash   string                 `json:"last_config_hash"`
	LastError        string                 `json:"last_error"`
	LastExit         string                 `json:"last_exit,omitempty"`
	FailureCount     int                    `json:"failure_count,omitempty"`
	BackoffUntilUnix int64                  `json:"backoff_until_unix,omitempty"`
	State            string                 `json:"state"`
}
