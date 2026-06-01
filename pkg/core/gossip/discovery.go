package gossip

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/Catofes/higgs/pkg/core/zone"
)

const (
	// EndpointRecordKeyPrefix is the prefix for endpoint records in a zone.
	EndpointRecordKeyPrefix = "sync/endpoint/"
	// EndpointRecordKeyUDP is the well-known key for UDP gossip endpoints.
	EndpointRecordKeyUDP = "sync/endpoint/udp"
	// DefaultEndpointTTL is used when an endpoint record does not carry a TTL.
	DefaultEndpointTTL = time.Hour
	// DefaultEndpointGrace is the old-address retention window after an endpoint changes.
	DefaultEndpointGrace = 10 * time.Minute
)

// EndpointRecord is the JSON value stored under sync/endpoint/* keys.
type EndpointRecord struct {
	Endpoints    []EndpointEntry `json:"endpoints"`
	TTL          int64           `json:"ttl_seconds,omitempty"`
	GraceSeconds int64           `json:"grace_seconds,omitempty"`
	Source       string          `json:"source,omitempty"`
	UpdatedAt    int64           `json:"updated_at,omitempty"`
}

// EndpointEntry represents a single network endpoint.
type EndpointEntry struct {
	Address      string `json:"address"`
	Port         uint16 `json:"port"`
	Protocol     string `json:"protocol,omitempty"`
	Scope        string `json:"scope,omitempty"`
	Source       string `json:"source,omitempty"`
	Priority     int    `json:"priority,omitempty"`
	LastObserved int64  `json:"last_observed,omitempty"`
}

// UDPAddr resolves the entry to a UDP address.
func (e EndpointEntry) UDPAddr() (*net.UDPAddr, error) {
	ip := net.ParseIP(e.Address)
	if ip == nil {
		return nil, fmt.Errorf("invalid address: %s", e.Address)
	}
	return &net.UDPAddr{IP: ip, Port: int(e.Port)}, nil
}

// ExtractPeerEndpoints scans all verified active zones for endpoint records
// and returns a map from peer ID (zone name) to endpoint entries.
func ExtractPeerEndpoints(ns *zone.NetworkState) map[string][]EndpointEntry {
	return ExtractPeerEndpointsAt(ns, time.Now())
}

// ExtractPeerEndpointsAt scans all verified active zones for endpoint records
// and filters endpoints whose TTL/grace window has elapsed.
func ExtractPeerEndpointsAt(ns *zone.NetworkState, now time.Time) map[string][]EndpointEntry {
	out := make(map[string][]EndpointEntry)
	if ns == nil {
		return out
	}
	for path, zs := range ns.Zones {
		peerID := string(path)
		for key, record := range zs.Records {
			if !strings.HasPrefix(key, EndpointRecordKeyPrefix) {
				continue
			}
			var er EndpointRecord
			if err := json.Unmarshal(record.Value, &er); err != nil {
				continue
			}
			recordUpdatedAt := er.UpdatedAt
			if recordUpdatedAt == 0 {
				recordUpdatedAt = record.Timestamp
			}
			for _, ep := range er.Endpoints {
				if ep.Protocol == "" {
					ep.Protocol = "udp"
				}
				if ep.LastObserved == 0 {
					ep.LastObserved = recordUpdatedAt
				}
				if endpointExpired(ep, er, now) {
					continue
				}
				out[peerID] = append(out[peerID], ep)
			}
		}
	}
	for _, entries := range out {
		sort.SliceStable(entries, func(i, j int) bool {
			if entries[i].Priority != entries[j].Priority {
				return entries[i].Priority > entries[j].Priority
			}
			return entries[i].LastObserved > entries[j].LastObserved
		})
	}
	return out
}

func endpointExpired(ep EndpointEntry, record EndpointRecord, now time.Time) bool {
	ttl := time.Duration(record.TTL) * time.Second
	if ttl <= 0 {
		ttl = DefaultEndpointTTL
	}
	grace := time.Duration(record.GraceSeconds) * time.Second
	if grace < 0 {
		grace = 0
	}
	if ep.LastObserved == 0 {
		return false
	}
	expiresAt := time.Unix(ep.LastObserved, 0).Add(ttl + grace)
	return now.After(expiresAt)
}

// LocalEndpointSource indicates how a local endpoint was discovered.
type LocalEndpointSource int

const (
	// SourceAdvertise means the endpoint came from explicit configuration.
	SourceAdvertise LocalEndpointSource = iota
	// SourceInterface means the endpoint came from local interface scanning.
	SourceInterface
	// SourceReflector means the endpoint came from a public IP reflector.
	SourceReflector
)

// LocalEndpoint is a candidate endpoint on this machine.
type LocalEndpoint struct {
	IP       net.IP
	Port     uint16
	Scope    string
	Priority int
	Source   LocalEndpointSource
}

// CollectLocalEndpoints gathers candidate endpoints from explicit advertise
// addresses and local interface scanning.
func CollectLocalEndpoints(listenPort uint16, advertiseAddrs []string) []LocalEndpoint {
	var out []LocalEndpoint
	for _, addr := range advertiseAddrs {
		ip, port, err := parseHostPortDefault(addr, listenPort)
		if err != nil {
			continue
		}
		out = append(out, LocalEndpoint{
			IP:       ip,
			Port:     port,
			Scope:    "advertise",
			Priority: 100,
			Source:   SourceAdvertise,
		})
	}
	for _, ep := range scanInterfaceEndpoints(listenPort) {
		out = append(out, ep)
	}
	return dedupLocalEndpoints(out)
}

func parseHostPortDefault(addr string, defaultPort uint16) (net.IP, uint16, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
		portStr = ""
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, 0, fmt.Errorf("invalid ip: %s", host)
	}
	port := defaultPort
	if portStr != "" {
		var p int
		if _, err := fmt.Sscanf(portStr, "%d", &p); err == nil && p > 0 && p <= 65535 {
			port = uint16(p)
		}
	}
	return ip, port, nil
}

func scanInterfaceEndpoints(listenPort uint16) []LocalEndpoint {
	var out []LocalEndpoint
	ifaces, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipNet.IP
			if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
				continue
			}
			if isTemporaryOrContainerIface(iface.Name) {
				continue
			}
			scope := "site"
			if ip.IsGlobalUnicast() {
				scope = "global"
			}
			priority := 10
			if ip.To4() != nil {
				priority = 20
			}
			out = append(out, LocalEndpoint{
				IP:       ip,
				Port:     listenPort,
				Scope:    scope,
				Priority: priority,
				Source:   SourceInterface,
			})
		}
	}
	return out
}

func isTemporaryOrContainerIface(name string) bool {
	n := strings.ToLower(name)
	return strings.HasPrefix(n, "docker") ||
		strings.HasPrefix(n, "br-") ||
		strings.HasPrefix(n, "veth") ||
		strings.HasPrefix(n, "cali") ||
		strings.HasPrefix(n, "flannel") ||
		strings.HasPrefix(n, "wg")
}

func dedupLocalEndpoints(in []LocalEndpoint) []LocalEndpoint {
	seen := make(map[string]bool)
	var out []LocalEndpoint
	for _, ep := range in {
		key := fmt.Sprintf("%s/%d", ep.IP.String(), ep.Port)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, ep)
	}
	return out
}

// QueryPublicIP attempts to discover the public IP via external reflector services.
// Phase 2.7 stub: returns an error to signal unavailability.
func QueryPublicIP(reflectors []string, timeout time.Duration) (net.IP, error) {
	if len(reflectors) == 0 {
		return nil, errors.New("no reflectors configured")
	}
	return nil, errors.New("public ip reflector not available")
}

// LocalEndpointsToRecord builds an EndpointRecord from local candidates.
func LocalEndpointsToRecord(endpoints []LocalEndpoint, now time.Time) *EndpointRecord {
	return LocalEndpointsToRecordWithPolicy(endpoints, nil, now, DefaultEndpointTTL, DefaultEndpointGrace)
}

// LocalEndpointsToRecordWithPolicy builds an EndpointRecord and carries recently
// observed old endpoints through the configured grace window.
func LocalEndpointsToRecordWithPolicy(endpoints []LocalEndpoint, previous *EndpointRecord, now time.Time, ttl, grace time.Duration) *EndpointRecord {
	if ttl <= 0 {
		ttl = DefaultEndpointTTL
	}
	if grace < 0 {
		grace = 0
	}
	er := &EndpointRecord{
		Source:       "local",
		UpdatedAt:    now.Unix(),
		TTL:          int64(ttl / time.Second),
		GraceSeconds: int64(grace / time.Second),
	}
	active := make(map[string]bool)
	for _, ep := range endpoints {
		entry := localEndpointEntry(ep, now)
		er.Endpoints = append(er.Endpoints, EndpointEntry{
			Address:      entry.Address,
			Port:         entry.Port,
			Scope:        entry.Scope,
			Source:       entry.Source,
			Priority:     entry.Priority,
			Protocol:     entry.Protocol,
			LastObserved: entry.LastObserved,
		})
		active[endpointKey(entry)] = true
	}
	if previous != nil && grace > 0 {
		for _, ep := range previous.Endpoints {
			if ep.Protocol == "" {
				ep.Protocol = "udp"
			}
			if ep.LastObserved == 0 {
				ep.LastObserved = previous.UpdatedAt
			}
			if ep.LastObserved == 0 || active[endpointKey(ep)] {
				continue
			}
			if now.After(time.Unix(ep.LastObserved, 0).Add(grace)) {
				continue
			}
			ep.Source = mergeEndpointSource(ep.Source, "grace")
			if ep.Priority > 0 {
				ep.Priority--
			}
			er.Endpoints = append(er.Endpoints, ep)
		}
	}
	sort.SliceStable(er.Endpoints, func(i, j int) bool {
		if er.Endpoints[i].Priority != er.Endpoints[j].Priority {
			return er.Endpoints[i].Priority > er.Endpoints[j].Priority
		}
		return er.Endpoints[i].LastObserved > er.Endpoints[j].LastObserved
	})
	return er
}

func localEndpointEntry(ep LocalEndpoint, now time.Time) EndpointEntry {
	return EndpointEntry{
		Address:      ep.IP.String(),
		Port:         ep.Port,
		Scope:        ep.Scope,
		Source:       localEndpointSourceName(ep.Source),
		Priority:     ep.Priority,
		Protocol:     "udp",
		LastObserved: now.Unix(),
	}
}

func localEndpointSourceName(source LocalEndpointSource) string {
	switch source {
	case SourceAdvertise:
		return "advertise"
	case SourceInterface:
		return "interface"
	case SourceReflector:
		return "reflector"
	default:
		return "unknown"
	}
}

func mergeEndpointSource(source, suffix string) string {
	if source == "" {
		return suffix
	}
	if strings.Contains(source, suffix) {
		return source
	}
	return source + "+" + suffix
}

func endpointKey(ep EndpointEntry) string {
	protocol := ep.Protocol
	if protocol == "" {
		protocol = "udp"
	}
	return fmt.Sprintf("%s/%s/%d", protocol, ep.Address, ep.Port)
}

// EndpointRecordBytes marshals local endpoints into the record JSON value.
func EndpointRecordBytes(endpoints []LocalEndpoint, now time.Time) []byte {
	er := LocalEndpointsToRecord(endpoints, now)
	data, _ := json.Marshal(er)
	return data
}
