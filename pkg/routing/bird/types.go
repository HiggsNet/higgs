package bird

import (
	"net/netip"
	"time"
)

// BirdMode controls how Higgs relates to the BIRD daemon for one overlay.
type BirdMode string

const (
	// BirdModeManaged means Higgs creates the netns, generates the config,
	// starts the BIRD process, and performs crash recovery.
	BirdModeManaged BirdMode = "managed"

	// BirdModeExternal means an external operator owns the BIRD process.
	// Higgs only connects via the control socket to configure and observe.
	BirdModeExternal BirdMode = "external"

	// BirdModeDisabled disables routing for the overlay. No config is
	// generated and no process is touched.
	BirdModeDisabled BirdMode = "disabled"
)

// NetNSSpec describes the network namespace where a BIRD instance runs.
// It intentionally mirrors transport/ipsec.NetNSSpec so callers can copy
// the overlay netns config without conversion.
type NetNSSpec struct {
	Kind   string `yaml:"kind" json:"kind"`     // "host", "name", or "path"
	Name   string `yaml:"name,omitempty" json:"name,omitempty"`
	Path   string `yaml:"path,omitempty" json:"path,omitempty"`
	Create bool   `yaml:"create,omitempty" json:"create,omitempty"`
}

// BabelAuthSpec holds per-interface Babel HMAC authentication parameters.
// BIRD requires the password to be present directly in the config file,
// so this struct is only used when auth is enabled.
type BabelAuthSpec struct {
	Enabled   bool   `yaml:"enabled" json:"enabled"`
	Algorithm string `yaml:"algorithm" json:"algorithm"` // e.g. "hmac sha256"
	KeyID     uint8  `yaml:"key_id" json:"key_id"`
	Password  string `yaml:"password" json:"password"` // raw key material
}

// BirdInstanceSpec is the complete configuration for one BIRD instance
// bound to one overlay / netns.
type BirdInstanceSpec struct {
	// RouterID is the 32-bit BIRD router id. It is rendered as an IPv4
	// dotted-quad in bird.conf. Use StableRouterID to derive it.
	RouterID uint32 `yaml:"router_id" json:"router_id"`

	// OverlayID identifies the Higgs overlay this instance serves.
	OverlayID string `yaml:"overlay_id" json:"overlay_id"`

	// NetNS is the network namespace where the BIRD daemon must run.
	NetNS NetNSSpec `yaml:"netns" json:"netns"`

	// Paths used by BIRD and birdc.
	ControlSocketPath string `yaml:"control_socket" json:"control_socket"`
	PIDFilePath       string `yaml:"pid_file" json:"pid_file"`
	ConfigPath        string `yaml:"config_path" json:"config_path"`

	// TableID is the kernel routing table to synchronize with. "main" means
	// the default table for the netns. Non-main values are passed to BIRD as
	// "kernel table <id>".
	TableID string `yaml:"table_id" json:"table_id"`

	// InternalTableName is the BIRD-internal table name. If empty, the
	// generator derives a stable name from the overlay id.
	InternalTableName string `yaml:"internal_table_name,omitempty" json:"internal_table_name,omitempty"`

	// Metrics applied to Babel interfaces of different generations.
	MetricBase     uint `yaml:"metric_base" json:"metric_base"`
	MetricStaged   uint `yaml:"metric_staged" json:"metric_staged"`
	MetricDraining uint `yaml:"metric_draining" json:"metric_draining"`

	// InterfacePattern is the BIRD interface glob, e.g. "hgs*".
	InterfacePattern string `yaml:"interface_pattern" json:"interface_pattern"`

	// Mode selects managed / external / disabled behavior.
	Mode BirdMode `yaml:"mode" json:"mode"`

	// DeviceScanTime is the "protocol device { scan time ... }" interval.
	// Zero means the generator uses its default (5s).
	DeviceScanTime time.Duration `yaml:"device_scan_time,omitempty" json:"device_scan_time,omitempty"`

	// LogTarget is rendered as the BIRD top-level "log" directive.
	// Empty means the generator uses "log syslog all".
	LogTarget string `yaml:"log_target,omitempty" json:"log_target,omitempty"`

	// BabelAuth configures per-interface HMAC authentication. Nil disables it.
	BabelAuth *BabelAuthSpec `yaml:"babel_auth,omitempty" json:"babel_auth,omitempty"`

	// ECMP enables Babel ECMP for equal-cost paths.
	ECMP bool `yaml:"ecmp,omitempty" json:"ecmp,omitempty"`

	// ECMPLimit is the optional "ecmp on limit N" value. Zero means no limit.
	ECMPLimit uint `yaml:"ecmp_limit,omitempty" json:"ecmp_limit,omitempty"`

	// BogonPrefixes are rejected before any accept logic in rendered filters.
	BogonPrefixes []netip.Prefix `yaml:"bogon_prefixes,omitempty" json:"bogon_prefixes,omitempty"`
}

// BirdConfig is a structured model of the desired BIRD configuration.
type BirdConfig struct {
	RouterID       uint32
	LogTarget      string
	ListenSocket   string // Unix control socket path
	DeviceScanTime time.Duration

	// Internal BIRD table names. Empty means disabled for that family.
	IPv4Table string
	IPv6Table string

	// KernelTableID is the numeric kernel table id, or 0 for the default.
	KernelTableID uint32

	Kernel         KernelProtocolBlock
	Babel          BabelProtocolBlock
	ImportFilters  []FilterBlock
	ExportFilters  []FilterBlock
}

// KernelProtocolBlock describes one "protocol kernel { ... }" block.
type KernelProtocolBlock struct {
	Name          string
	IPv4Table     string
	IPv6Table     string
	KernelTableID uint32 // 0 = default/main
	Learn         bool   // import from kernel
	Persist       bool   // persist routes on BIRD shutdown
}

// BabelProtocolBlock describes one "protocol babel { ... }" block.
type BabelProtocolBlock struct {
	Name             string
	IPv4Table        string
	IPv6Table        string
	InterfacePattern string
	TypeTunnel       bool
	MetricBase       uint
	MetricStaged     uint
	MetricDraining   uint
	ECMP             bool
	ECMPLimit        uint
	Auth             *BabelAuthSpec
}

// FilterBlock is a named BIRD filter function.
type FilterBlock struct {
	Name string
	Body string // raw BIRD filter text, including surrounding braces
}

// BirdObservedState is the parsed output of birdc status/commands.
type BirdObservedState struct {
	Status     BirdStatus
	Protocols  []BirdProtocol
	Routes     []BirdRoute
	Interfaces []BirdInterface
	Neighbors  []BirdNeighbor

	FetchedAt time.Time
	Stale     bool     // true if the snapshot timed out or used cached data
	Warnings  []string // non-fatal parse warnings
}

// BirdStatus is the parsed output of "show status".
type BirdStatus struct {
	RouterID     uint32
	Version      string
	UpSince      time.Time
	LastReconfig time.Time
}

// BirdProtocol is the parsed output of "show protocols".
type BirdProtocol struct {
	Name   string
	Proto  string // "Babel", "Kernel", "Device", ...
	Table  string
	State  string // "up", "down", "start", ...
	Info   string
	Since  time.Time
	Uptime time.Duration
}

// BirdRoute is the parsed output of "show route".
type BirdRoute struct {
	Prefix   netip.Prefix
	From     netip.Addr
	Via      netip.Addr
	Iface    string
	Protocol string
	Source   string // e.g. "babel", "static"
	Metric   uint32
	Selected bool
}

// BirdInterface is the parsed output of "show interfaces".
type BirdInterface struct {
	Index     int
	Name      string
	Flags     string
	State     string // "up", "down"
	MTU       int
	LinkLocal netip.Addr
	Addresses []netip.Addr
}

// BirdNeighbor is the parsed output of "show neighbors".
type BirdNeighbor struct {
	Interface string
	Address   netip.Addr
	Protocol  string
	Metric    uint32
	Reach     uint16 // babel reachability bitmap, when available
}

// ConfigGenerator renders a bird.conf from a spec and the current authorized
// import/export prefix sets.
type ConfigGenerator interface {
	Generate(
		spec BirdInstanceSpec,
		importSet []netip.Prefix,
		exportSet []netip.Prefix,
	) ([]byte, error)
}
