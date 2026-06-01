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
)

// EndpointRecord is the JSON value stored under sync/endpoint/* keys.
type EndpointRecord struct {
	Endpoints []EndpointEntry `json:"endpoints"`
	TTL       int64           `json:"ttl_seconds,omitempty"`
	Source    string          `json:"source,omitempty"`
	UpdatedAt int64           `json:"updated_at,omitempty"`
}

// EndpointEntry represents a single network endpoint.
type EndpointEntry struct {
	Address  string `json:"address"`
	Port     uint16 `json:"port"`
	Protocol string `json:"protocol,omitempty"`
	Scope    string `json:"scope,omitempty"`
	Priority int    `json:"priority,omitempty"`
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
			for _, ep := range er.Endpoints {
				if ep.Protocol == "" {
					ep.Protocol = "udp"
				}
				out[peerID] = append(out[peerID], ep)
			}
		}
	}
	for _, entries := range out {
		sort.SliceStable(entries, func(i, j int) bool {
			return entries[i].Priority > entries[j].Priority
		})
	}
	return out
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
	er := &EndpointRecord{
		Source:    "local",
		UpdatedAt: now.Unix(),
		TTL:       3600,
	}
	for _, ep := range endpoints {
		er.Endpoints = append(er.Endpoints, EndpointEntry{
			Address:  ep.IP.String(),
			Port:     ep.Port,
			Scope:    ep.Scope,
			Priority: ep.Priority,
			Protocol: "udp",
		})
	}
	return er
}

// EndpointRecordBytes marshals local endpoints into the record JSON value.
func EndpointRecordBytes(endpoints []LocalEndpoint, now time.Time) []byte {
	er := LocalEndpointsToRecord(endpoints, now)
	data, _ := json.Marshal(er)
	return data
}
