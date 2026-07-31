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
	// BIRD emits a destination type between the prefix and source bracket
	// (e.g. unicast, blackhole, unreachable, prohibit). It is deliberately
	// parsed as a token rather than a fixed enum because BIRD can add types.
	routeLineRe = regexp.MustCompile(`(?m)^\s*(\S+)\s+(?:\S+\s+)?\[([^\]\s]+)(?:\s+[^\]]*)?\]\s*([*!]?)\s*\((\d+)(?:/\d+)?\)`)
	routeViaRe  = regexp.MustCompile(`(?m)^\s+via\s+(\S+)\s+on\s+(\S+)`)
	routeDevRe  = regexp.MustCompile(`(?m)^\s+dev\s+(\S+)`)
	routeFromRe = regexp.MustCompile(`(?m)^\s+from\s+(\S+)`)

	interfaceStartRe   = regexp.MustCompile(`(?m)^\s*(\S+)\s+(up|down)\s+\(index=(\d+)(?:\s+[^)]*)?\)`)
	interfaceDetailsRe = regexp.MustCompile(`^\s*(.*?)\s+MTU=(\d+)\s*$`)

	babelNeighborsHeaderRe = regexp.MustCompile(`(?im)^\s*IP\s+address\s+Interface\s+Metric`)
	babelProtocolNameRe    = regexp.MustCompile(`^\s*(\S+):\s*$`)
)

// stripCodes removes BIRD CLI numeric prefixes like "1001-" or "0001 " from each line.
func stripCodes(output string) string {
	var out strings.Builder
	for line := range strings.SplitSeq(output, "\n") {
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
	for _, f := range []string{"15:04:05.000", "15:04:05", "15:04"} {
		if t, err := time.ParseInLocation(f, value, time.Local); err == nil {
			now := time.Now().In(time.Local)
			return time.Date(now.Year(), now.Month(), now.Day(), t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), time.Local), nil
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
				// BIRD's verbose output has no stable "Source:" line. The
				// bracketed protocol name is the source relevant to callers.
				Source:   strings.TrimSpace(m[2]),
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
		if m := routeDevRe.FindStringSubmatch(line); len(m) >= 2 {
			current.Iface = strings.TrimSpace(m[1])
			continue
		}
		if m := routeFromRe.FindStringSubmatch(line); len(m) >= 2 {
			current.From, _ = netip.ParseAddr(m[1])
			continue
		}
	}
	if current != nil {
		routes = append(routes, *current)
	}
	return routes
}

// parseInterfaces parses BIRD's headerless "show interfaces" output.
func parseInterfaces(output string) []BirdInterface {
	output = stripCodes(output)
	var ifaces []BirdInterface

	lines := strings.SplitSeq(output, "\n")
	for raw := range lines {
		line := strings.TrimRight(raw, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}

		m := interfaceStartRe.FindStringSubmatch(line)
		if len(m) >= 4 {
			index, _ := strconv.Atoi(strings.TrimSpace(m[3]))
			iface := BirdInterface{
				Name:  strings.TrimSpace(m[1]),
				State: strings.TrimSpace(m[2]),
				Index: index,
			}
			ifaces = append(ifaces, iface)
			continue
		}

		if len(ifaces) == 0 {
			continue
		}
		last := &ifaces[len(ifaces)-1]
		if m := interfaceDetailsRe.FindStringSubmatch(line); len(m) >= 3 {
			last.Flags = strings.TrimSpace(m[1])
			last.MTU, _ = strconv.Atoi(m[2])
			continue
		}
		// Address rows begin with an address/prefix, followed by annotations.
		if fields := strings.Fields(line); len(fields) > 0 {
			if prefix, err := netip.ParsePrefix(fields[0]); err == nil {
				addr := prefix.Addr()
				last.Addresses = append(last.Addresses, addr)
				if addr.Is6() && addr.IsLinkLocalUnicast() {
					last.LinkLocal = addr
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
	var inNeighbors bool
	var protocol string
	for _, raw := range lines {
		line := strings.TrimRight(raw, "\r")
		if m := babelProtocolNameRe.FindStringSubmatch(line); len(m) >= 2 {
			protocol = m[1]
			continue
		}
		if babelNeighborsHeaderRe.MatchString(line) {
			inNeighbors = true
			continue
		}
		if !inNeighbors || strings.TrimSpace(line) == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		addrText, iface, metricText := fields[0], fields[1], fields[2]
		addr, err := netip.ParseAddr(addrText)
		if err != nil {
			continue
		}
		metric, err := strconv.ParseUint(metricText, 10, 32)
		if err != nil {
			continue
		}
		neighbors = append(neighbors, BirdNeighbor{Interface: iface, Address: addr, Protocol: protocol, Metric: uint32(metric)})
	}
	return neighbors
}
