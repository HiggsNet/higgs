package inspect

import "time"

type PingDebugView struct {
	Zone           string
	Targets        []PingTargetView
	AvailableZones []string
	Count          int
	Timeout        time.Duration
}

type PingTargetView struct {
	InstanceID  string
	ProbeID     string
	Role        string
	Family      string
	Interface   string
	NetNS       string
	LocalTunnel string
	PeerTunnel  string
	Success     bool
	RTT         time.Duration
	Error       string
}
