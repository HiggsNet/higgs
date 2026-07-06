package text

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/Catofes/higgs/internal/inspect"
)

func WritePingDebug(w io.Writer, view inspect.PingDebugView) error {
	out := newLineWriter(w)
	out.Linef("zone: %s", view.Zone)
	out.Linef("targets: %d", len(view.Targets))
	if len(view.Targets) == 0 {
		out.Linef("no IPsec link instances for zone %s", view.Zone)
		out.LineIf(len(view.AvailableZones) > 0, "available peer zones: %s", strings.Join(view.AvailableZones, ", "))
		return out.Err()
	}
	out.Linef("count: %d timeout: %s", view.Count, view.Timeout)
	out.Blank()
	for _, instanceID := range orderedPingInstances(view.Targets) {
		out.Linef("instance %s", instanceID)
		for _, row := range pingRowsForInstance(view.Targets, instanceID) {
			out.Linef("  role=%s family=%s", pingTargetRole(row), row.Family)
			out.Linef("    interface: %s", dash(row.Interface))
			out.LineIf(row.NetNS != "", "  netns: %s", row.NetNS)
			out.Blank()
			out.Linef("    local: %s  peer: %s", dash(row.LocalTunnel), dash(row.PeerTunnel))
			out.Linef("    result: %s", formatPingResult(row))
		}
	}
	return out.Err()
}

func orderedPingInstances(targets []inspect.PingTargetView) []string {
	seen := map[string]struct{}{}
	ordered := make([]string, 0, len(targets))
	for _, target := range targets {
		id := pingTargetInstanceID(target)
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		ordered = append(ordered, id)
	}
	sort.Strings(ordered)
	return ordered
}

func pingRowsForInstance(targets []inspect.PingTargetView, instanceID string) []inspect.PingTargetView {
	rows := make([]inspect.PingTargetView, 0, len(targets))
	for _, target := range targets {
		if pingTargetInstanceID(target) != instanceID {
			continue
		}
		rows = append(rows, target)
	}
	sort.Slice(rows, func(i, j int) bool {
		if ri, rj := pingTargetRole(rows[i]), pingTargetRole(rows[j]); ri != rj {
			return ri < rj
		}
		return rows[i].Family < rows[j].Family
	})
	return rows
}

func pingTargetInstanceID(target inspect.PingTargetView) string {
	if target.InstanceID != "" {
		return target.InstanceID
	}
	return target.ProbeID
}

func pingTargetRole(target inspect.PingTargetView) string {
	if target.Role != "" {
		return target.Role
	}
	return "active"
}

func formatPingResult(target inspect.PingTargetView) string {
	if target.Success {
		if target.RTT > 0 {
			return fmt.Sprintf("ok rtt=%s", target.RTT.Round(time.Microsecond))
		}
		return "ok"
	}
	if target.Error != "" {
		return fmt.Sprintf("fail error=%q", target.Error)
	}
	return "fail"
}
