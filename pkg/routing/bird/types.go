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
	Kind   string `yaml:"kind" json:"kind"` // "host", "name", or "path"
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
// bound to one network namespace. In the per-netns model, one netns has
// exactly one BIRD instance, shared by all overlays in that netns.
type BirdInstanceSpec struct {
	// RouterID is the 32-bit BIRD router id. It is rendered as an IPv4
	// dotted-quad in bird.conf. Use StableRouterID to derive it.
	RouterID uint32 `yaml:"router_id" json:"router_id"`

	// NetNSName identifies the network namespace this BIRD instance serves.
	// In the per-netns model, this replaces the former OverlayID.
	NetNSName string `yaml:"netns_name" json:"netns_name"`

	// Overlays lists the overlay IDs sharing this BIRD instance. This is
	// informational/debug metadata; it does not affect config generation.
	Overlays []string `yaml:"overlays,omitempty" json:"overlays,omitempty"`

	// NetNS is the network namespace where the BIRD daemon must run.
	NetNS NetNSSpec `yaml:"netns" json:"netns"`

	// Paths used by BIRD and birdc.
	ControlSocketPath string `yaml:"control_socket" json:"control_socket"`
	PIDFilePath       string `yaml:"pid_file" json:"pid_file"`
	ConfigPath        string `yaml:"config_path" json:"config_path"`

	// Owner proves which Higgs-managed runtime resources may be cleaned up
	// during teardown. Empty tokens retain legacy process teardown but skip
	// path/resource cleanup.
	Owner BirdResourceOwner `yaml:"owner,omitempty" json:"owner,omitempty"`

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

	// InterfacePatterns are the BIRD interface globs, e.g. ["hgs*"].
	// Multiple patterns allow one BIRD instance to discover interfaces from
	// multiple overlays sharing the same netns.
	InterfacePatterns []string `yaml:"interface_patterns,omitempty" json:"interface_patterns,omitempty"`

	// InterfacePattern is retained for backward compatibility. When non-empty,
	// it is appended to InterfacePatterns. New code should use InterfacePatterns.
	InterfacePattern string `yaml:"interface_pattern,omitempty" json:"interface_pattern,omitempty"`

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

	// ECMP enables kernel multipath installation for equal-cost Babel paths.
	// BIRD renders this as "merge paths" in each kernel protocol.
	ECMP bool `yaml:"ecmp,omitempty" json:"ecmp,omitempty"`

	// ECMPLimit is the optional "merge paths on limit N" value. Zero means no limit.
	ECMPLimit uint `yaml:"ecmp_limit,omitempty" json:"ecmp_limit,omitempty"`

	// BogonPrefixes are rejected before any accept logic in rendered filters.
	BogonPrefixes []netip.Prefix `yaml:"bogon_prefixes,omitempty" json:"bogon_prefixes,omitempty"`

	// Upstream enables veth-based peering with the main network.
	// When non-nil and enabled, the generator emits a second Babel interface
	// block for the veth and optionally a protocol static block.
	Upstream *UpstreamSpec `yaml:"upstream,omitempty" json:"upstream,omitempty"`

	// StaticRoutes specifies static routes to announce via the upstream
	// interface. Each prefix is routed via the upstream interface name.
	StaticRoutes []StaticRouteSpec `yaml:"static_routes,omitempty" json:"static_routes,omitempty"`
}

// BirdResourceOwner carries per-resource ownership tokens for managed BIRD
// runtime artifacts. Separate tokens keep cleanup decisions scoped to the
// concrete resource being removed.
type BirdResourceOwner struct {
	Manager            string `yaml:"manager,omitempty" json:"manager,omitempty"`
	InstanceID         string `yaml:"instance_id,omitempty" json:"instance_id,omitempty"`
	NetNSName          string `yaml:"netns_name,omitempty" json:"netns_name,omitempty"`
	Token              string `yaml:"token,omitempty" json:"token,omitempty"`
	ControlSocketToken string `yaml:"control_socket_token,omitempty" json:"control_socket_token,omitempty"`
	PIDFileToken       string `yaml:"pid_file_token,omitempty" json:"pid_file_token,omitempty"`
	ConfigFileToken    string `yaml:"config_file_token,omitempty" json:"config_file_token,omitempty"`
	RouteTableToken    string `yaml:"route_table_token,omitempty" json:"route_table_token,omitempty"`
	RuleToken          string `yaml:"rule_token,omitempty" json:"rule_token,omitempty"`
}

// ProcessExit records a managed BIRD process exit observed by waitpid/Wait.
type ProcessExit struct {
	PID   int    `json:"pid,omitempty"`
	Error string `json:"error,omitempty"`
}

// UpstreamSpec configures a veth-based Babel peering with the main network.
type UpstreamSpec struct {
	// Interface is the veth endpoint inside the mesh netns.
	Interface string `yaml:"interface" json:"interface"`

	// InterfacePattern is the BIRD interface glob for upstream interfaces.
	// Defaults to "hgs-2host*".
	InterfacePattern string `yaml:"interface_pattern,omitempty" json:"interface_pattern,omitempty"`
}

// StaticRouteSpec describes a static route for the BIRD protocol static block.
type StaticRouteSpec struct {
	// Prefix is the CIDR to announce.
	Prefix netip.Prefix `yaml:"prefix" json:"prefix"`

	// Via is the interface name for "via" routes. When empty, the route
	// is a blackhole route.
	Via string `yaml:"via,omitempty" json:"via,omitempty"`

	// Blackhole forces a blackhole route even if Via is set.
	Blackhole bool `yaml:"blackhole,omitempty" json:"blackhole,omitempty"`
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

	Kernel         []KernelProtocolBlock
	Babel          BabelProtocolBlock
	ImportFilters  []FilterBlock
	ExportFilters  []FilterBlock
	StaticRoutes   []StaticRouteBlock
	UpstreamFilter *FilterBlock // optional kernel export filter for upstream
}

// StaticRouteBlock describes one "protocol static { route ... }" block.
type StaticRouteBlock struct {
	Name       string
	IPv4Routes []StaticRoute
	IPv6Routes []StaticRoute
}

// StaticRoute is a single route line within a protocol static block.
type StaticRoute struct {
	Prefix    netip.Prefix
	Via       string // interface name for "via" routes; empty for blackhole
	Blackhole bool
}

// KernelProtocolBlock describes one "protocol kernel { ... }" block.
type KernelProtocolBlock struct {
	Name          string
	IPv4Table     string
	IPv6Table     string
	KernelTableID uint32 // 0 = default/main
	Learn         bool   // import from kernel
	Persist       bool   // persist routes on BIRD shutdown
	// MergePaths asks the kernel protocol to install equal-cost routes as a
	// single multipath route. BIRD 2.x accepts this in protocol kernel, not
	// protocol babel.
	MergePaths      bool
	MergePathsLimit uint
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
	Auth             *BabelAuthSpec
	UpstreamBlock    *BabelInterfaceBlock // optional second interface block for veth upstream
}

// BabelInterfaceBlock describes one "interface ... { ... }" block inside a
// Babel protocol. The primary XFRM tunnel block is rendered inline in
// BabelProtocolBlock; the upstream veth block uses this separate struct
// because it must NOT have type tunnel.
type BabelInterfaceBlock struct {
	InterfacePattern string
	TypeTunnel       bool
	MetricBase       uint
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
