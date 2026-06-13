package bird

import (
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	codePrefixRe = regexp.MustCompile(`^\d{4}[- ]`)

	routerIDRe     = regexp.MustCompile(`(?im)^(?:\s*Router ID is\s+(\d+\.\d+\.\d+\.\d+))`)
	birdVersionRe  = regexp.MustCompile(`(?im)^(?:\s*BIRD\s+([\d.]+\S*))`)
	rebootTimeRe   = regexp.MustCompile(`(?im)^(?:\s*Last reboot on\s+(.+?))\s*$`)
	reconfigTimeRe = regexp.MustCompile(`(?im)^(?:\s*Last reconfiguration on\s+(.+?))\s*$`)

	protocolHeaderRe = regexp.MustCompile(`(?im)^\s*Name\s+Proto\s+Table\s+State\s+Since\s+Info`)
	protocolRowRe    = regexp.MustCompile(`(?m)^\s*(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)(?:\s+(.*))?`)

	routeHeaderRe = regexp.MustCompile(`(?im)^\s*(?:Table|VRF)\s+`)
	routeLineRe   = regexp.MustCompile(`(?m)^\s*(\S+?)\s+(?:unicast|multicast)?\s*\[([^\]]+)\]\s*(\*)?\s*\((\d+)\)`)
	routeViaRe    = regexp.MustCompile(`(?m)^\s+via\s+(\S+)\s+on\s+(\S+)`)
	routeFromRe   = regexp.MustCompile(`(?m)^\s+from\s+(\S+)`)

	interfaceHeaderRe = regexp.MustCompile(`(?im)^\s*(?:Interface|Iface)\s+`)
	interfaceRowRe    = regexp.MustCompile(`(?m)^\s*(\S+)\s+(up|down)\s+(\d+)\s+(\S+)?`)
	interfaceAddrRe   = regexp.MustCompile(`(?im)^\s+(?:IPv4|IPv6|addresses?:?)\s*[:=]?\s*(.+)`)

	babelHeaderRe = regexp.MustCompile(`(?im)^\s*Interface\s+Neighbor`)
	babelRowRe    = regexp.MustCompile(`(?m)^\s*(\S+)\s+(\S+)\s+(\d+)(?:\s+\S+\s+\S+)?`)
)

// stripCodes removes BIRD CLI numeric prefixes like "1001-" or "0001 " from each line.
func stripCodes(output string) string {
	var out strings.Builder
	for _, line := range strings.Split(output, "\n") {
		if codePrefixRe.MatchString(line) {
			line = line[5:]
		}
		out.WriteString(line)
		out.WriteByte('\n')
	}
	return out.String()
}

// parseTime tries several BIRD timestamp formats.
func parseTime(value string) (time.Time, error) {
	value = strings.TrimSpace(value)
	formats := []string{
		"2006-01-02 15:04:05.000",
		"2006-01-02 15:04:05",
		"2006-01-02 15:04",
		"06-01-02 15:04:05.000",
		"06-01-02 15:04:05",
	}
	for _, f := range formats {
		if t, err := time.ParseInLocation(f, value, time.Local); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("unrecognized time format: %q", value)
}

// routerIDToUint32 converts an IPv4 dotted-quad to a 32-bit router id.
func routerIDToUint32(s string) (uint32, error) {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return 0, err
	}
	if !addr.Is4() {
		return 0, fmt.Errorf("router id %q is not IPv4", s)
	}
	b := addr.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3]), nil
}

// parseStatus parses the output of "show status" into BirdStatus.
func parseStatus(output string) (BirdStatus, error) {
	output = stripCodes(output)
	var status BirdStatus

	if m := birdVersionRe.FindStringSubmatch(output); len(m) > 1 {
		status.Version = m[1]
	}
	if m := routerIDRe.FindStringSubmatch(output); len(m) > 1 {
		id, err := routerIDToUint32(m[1])
		if err != nil {
			return status, fmt.Errorf("router id: %w", err)
		}
		status.RouterID = id
	}
	if m := rebootTimeRe.FindStringSubmatch(output); len(m) > 1 {
		t, err := parseTime(m[1])
		if err == nil {
			status.UpSince = t
		}
	}
	if m := reconfigTimeRe.FindStringSubmatch(output); len(m) > 1 {
		t, err := parseTime(m[1])
		if err == nil {
			status.LastReconfig = t
		}
	}

	return status, nil
}

// parseProtocols parses the output of "show protocols" into BirdProtocol entries.
func parseProtocols(output string) []BirdProtocol {
	output = stripCodes(output)
	var protocols []BirdProtocol

	lines := strings.Split(output, "\n")
	var headerFound bool
	for _, line := range lines {
		if !headerFound {
			if protocolHeaderRe.MatchString(line) {
				headerFound = true
			}
			continue
		}
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}

		m := protocolRowRe.FindStringSubmatch(line)
		if len(m) >= 6 {
			info := ""
			if len(m) > 6 {
				info = strings.TrimSpace(m[6])
			}
			since, _ := parseTime(strings.TrimSpace(m[5]))
			protocols = append(protocols, BirdProtocol{
				Name:  strings.TrimSpace(m[1]),
				Proto: strings.TrimSpace(m[2]),
				Table: strings.TrimSpace(m[3]),
				State: strings.TrimSpace(m[4]),
				Since: since,
				Info:  info,
			})
			continue
		}

		// Indented line that does not look like a row is a continuation.
		if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
			if len(protocols) > 0 {
				protocols[len(protocols)-1].Info += " " + strings.TrimSpace(line)
			}
		}
	}
	return protocols
}

// parseRoutes parses the output of "show route" into BirdRoute entries.
func parseRoutes(output string) []BirdRoute {
	output = stripCodes(output)
	var routes []BirdRoute

	lines := strings.Split(output, "\n")
	var current *BirdRoute
	for _, raw := range lines {
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		// Ignore table/VRF header lines.
		if routeHeaderRe.MatchString(line) {
			continue
		}

		m := routeLineRe.FindStringSubmatch(line)
		if len(m) >= 5 {
			if current != nil {
				routes = append(routes, *current)
			}
			prefix, _ := netip.ParsePrefix(m[1])
			metric, _ := strconv.ParseUint(m[4], 10, 32)
			current = &BirdRoute{
				Prefix:   prefix,
				Protocol: strings.TrimSpace(m[2]),
				Metric:   uint32(metric),
				Selected: m[3] == "*",
			}
			continue
		}

		if current == nil {
			continue
		}
		if m := routeViaRe.FindStringSubmatch(line); len(m) >= 3 {
			current.Via, _ = netip.ParseAddr(m[1])
			current.Iface = strings.TrimSpace(m[2])
			continue
		}
		if m := routeFromRe.FindStringSubmatch(line); len(m) >= 2 {
			current.From, _ = netip.ParseAddr(m[1])
			continue
		}
		// Try to extract source information if present.
		if strings.Contains(line, "Source:") || strings.Contains(line, "source") {
			parts := strings.SplitN(trimmed, ":", 2)
			if len(parts) == 2 {
				current.Source = strings.TrimSpace(parts[1])
			}
		}
	}
	if current != nil {
		routes = append(routes, *current)
	}
	return routes
}

// parseInterfaces parses the output of "show interfaces" into BirdInterface entries.
func parseInterfaces(output string) []BirdInterface {
	output = stripCodes(output)
	var ifaces []BirdInterface

	lines := strings.Split(output, "\n")
	var headerFound bool
	for _, raw := range lines {
		line := strings.TrimRight(raw, "\r")
		if !headerFound {
			if interfaceHeaderRe.MatchString(line) {
				headerFound = true
			}
			continue
		}
		if strings.TrimSpace(line) == "" {
			continue
		}

		m := interfaceRowRe.FindStringSubmatch(line)
		if len(m) >= 4 {
			mtu, _ := strconv.Atoi(strings.TrimSpace(m[3]))
			iface := BirdInterface{
				Name:  strings.TrimSpace(m[1]),
				State: strings.TrimSpace(m[2]),
				MTU:   mtu,
			}
			if len(m) >= 5 && m[4] != "" {
				iface.LinkLocal, _ = netip.ParseAddr(strings.TrimSpace(m[4]))
			}
			ifaces = append(ifaces, iface)
			continue
		}

		// Address continuation lines.
		if m := interfaceAddrRe.FindStringSubmatch(line); len(m) >= 2 && len(ifaces) > 0 {
			for _, s := range strings.Fields(m[1]) {
				s = strings.TrimSpace(s)
				s = strings.Trim(s, "[],")
				if s == "" {
					continue
				}
				if addr, err := netip.ParseAddr(s); err == nil {
					last := &ifaces[len(ifaces)-1]
					last.Addresses = append(last.Addresses, addr)
				}
			}
		}
	}
	return ifaces
}

// parseBabelNeighbors parses the output of "show babel neighbors" into BirdNeighbor entries.
func parseBabelNeighbors(output string) []BirdNeighbor {
	output = stripCodes(output)
	var neighbors []BirdNeighbor

	lines := strings.Split(output, "\n")
	var headerFound bool
	for _, raw := range lines {
		line := strings.TrimRight(raw, "\r")
		if !headerFound {
			if babelHeaderRe.MatchString(line) {
				headerFound = true
			}
			continue
		}
		if strings.TrimSpace(line) == "" {
			continue
		}

		m := babelRowRe.FindStringSubmatch(line)
		if len(m) >= 4 {
			metric, _ := strconv.ParseUint(strings.TrimSpace(m[3]), 10, 32)
			addr, _ := netip.ParseAddr(strings.TrimSpace(m[2]))
			neighbors = append(neighbors, BirdNeighbor{
				Interface: strings.TrimSpace(m[1]),
				Address:   addr,
				Metric:    uint32(metric),
			})
		}
	}
	return neighbors
}
