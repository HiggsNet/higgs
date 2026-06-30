package main

import (
	"context"
	"fmt"
	"io"
	"net/netip"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/Catofes/higgs/pkg/core/zone"
	"github.com/Catofes/higgs/pkg/health"
	"github.com/Catofes/higgs/pkg/transport/ipsec"
)

const (
	defaultPingCount   = 4
	defaultPingTimeout = time.Second
)

// pingFlags captures the user-supplied options for `higgs debug ping`.
type pingFlags struct {
	count   int
	timeout time.Duration
	family  string // "", "ipv4", "ipv6"
	role    string // "", "active", "old", "staged"
}

// pingOutcome is the result of probing a single target.
type pingOutcome struct {
	Target health.ProbeTarget
	Family string // "ipv4" | "ipv6"
	Result health.ProbeResult
}

// debugPing resolves the IPsec link targets for a peer zone and pings each one
// (current SA, plus old and new SA during a rotate) across IPv4/IPv6. It runs
// the pings directly in the CLI process via the health ICMP prober.
func debugPing(ctx context.Context, peerZone zone.ZonePath, opts pingFlags) error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	state, err := rt.LoadState()
	if err != nil {
		return err
	}
	if state == nil {
		fmt.Println("no state loaded")
		return nil
	}
	localZone := string(state.ManagedZone)
	var groups []ipsec.LinkGroupSpec
	if rt.Config != nil {
		groups = rt.Config.IPsec.LinkGroups
	}
	targets := healthTargetsFromState(state, localZone, groups)
	selected := selectPingTargets(targets, peerZone, opts)

	count, timeout := resolvePingCountTimeout(opts, rt.Config)
	cfg := health.ProbeConfig{Timeout: timeout, Burst: count}
	prober := health.NewICMProber(nil, nil)
	outcomes := runPingOutcomes(ctx, prober, selected, cfg)
	return writePingReport(os.Stdout, peerZone, outcomes, distinctPeerZones(targets), count, timeout)
}

// selectPingTargets filters health targets to those matching the requested peer
// zone, address family, and SA role. Targets with no valid peer tunnel address
// are dropped.
func selectPingTargets(targets []health.ProbeTarget, peerZone zone.ZonePath, opts pingFlags) []health.ProbeTarget {
	wantZone := string(peerZone)
	out := make([]health.ProbeTarget, 0, len(targets))
	for _, t := range targets {
		if !t.PeerTunnelAddr.IsValid() {
			continue
		}
		if string(t.PeerZone) != wantZone {
			continue
		}
		if opts.family != "" && familyFor(t.PeerTunnelAddr) != opts.family {
			continue
		}
		if opts.role != "" && pingRole(t) != opts.role {
			continue
		}
		out = append(out, t)
	}
	return out
}

// runPingOutcomes probes each target and records the outcome. The prober is
// injected so the logic can be exercised without running a real ping.
func runPingOutcomes(ctx context.Context, prober health.Prober, targets []health.ProbeTarget, cfg health.ProbeConfig) []pingOutcome {
	out := make([]pingOutcome, 0, len(targets))
	for _, t := range targets {
		result := health.ProbeResult{InstanceID: t.InstanceID, Error: "no prober configured"}
		if prober != nil {
			result = prober.Probe(ctx, t, cfg)
		}
		out = append(out, pingOutcome{Target: t, Family: familyFor(t.PeerTunnelAddr), Result: result})
	}
	return out
}

func resolvePingCountTimeout(opts pingFlags, config *appConfig) (int, time.Duration) {
	count := opts.count
	if count <= 0 && config != nil {
		count = config.Health.Burst
	}
	if count <= 0 {
		count = defaultPingCount
	}
	timeout := opts.timeout
	if timeout <= 0 && config != nil {
		timeout = config.Health.Timeout
	}
	if timeout <= 0 {
		timeout = defaultPingTimeout
	}
	return count, timeout
}

func familyFor(addr netip.Addr) string {
	if addr.Is6() {
		return "ipv6"
	}
	return "ipv4"
}

func pingRole(t health.ProbeTarget) string {
	if t.ProbeRole != "" {
		return t.ProbeRole
	}
	return "active"
}

func distinctPeerZones(targets []health.ProbeTarget) []string {
	seen := map[string]struct{}{}
	for _, t := range targets {
		if t.PeerZone != "" {
			seen[t.PeerZone] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for z := range seen {
		out = append(out, z)
	}
	sort.Strings(out)
	return out
}

// writePingReport prints the ping results grouped by link instance and SA role.
// When no targets matched, it lists the peer zones currently known to state so
// the operator can spot a typo.
func writePingReport(w io.Writer, peerZone zone.ZonePath, outcomes []pingOutcome, availableZones []string, count int, timeout time.Duration) error {
	fmt.Fprintf(w, "zone: %s\n", peerZone)
	fmt.Fprintf(w, "targets: %d\n", len(outcomes))
	if len(outcomes) == 0 {
		fmt.Fprintf(w, "no IPsec link instances for zone %s\n", peerZone)
		if len(availableZones) > 0 {
			fmt.Fprintf(w, "available peer zones: %s\n", strings.Join(availableZones, ", "))
		}
		return nil
	}
	fmt.Fprintf(w, "count: %d timeout: %s\n\n", count, timeout)
	for _, instanceID := range orderedPingInstances(outcomes) {
		fmt.Fprintf(w, "instance %s\n", instanceID)
		rows := pingRowsForInstance(outcomes, instanceID)
		for _, row := range rows {
			fmt.Fprintf(w, "  role=%s family=%s\n", pingRole(row.Target), row.Family)
			fmt.Fprintf(w, "    interface: %s", dash(row.Target.InterfaceName))
			if row.Target.NetNS != "" {
				fmt.Fprintf(w, "  netns: %s", row.Target.NetNS)
			}
			fmt.Fprintln(w)
			fmt.Fprintf(w, "    local: %s  peer: %s\n", dash(row.Target.LocalTunnelAddr.String()), dash(row.Target.PeerTunnelAddr.String()))
			fmt.Fprintf(w, "    result: %s\n", formatPingResult(row.Result))
		}
	}
	return nil
}

func orderedPingInstances(outcomes []pingOutcome) []string {
	seen := map[string]struct{}{}
	ordered := make([]string, 0, len(outcomes))
	for _, o := range outcomes {
		id := o.Target.InstanceID
		if id == "" {
			id = o.Target.ProbeID
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		ordered = append(ordered, id)
	}
	sort.Strings(ordered)
	return ordered
}

func pingRowsForInstance(outcomes []pingOutcome, instanceID string) []pingOutcome {
	rows := make([]pingOutcome, 0, len(outcomes))
	for _, o := range outcomes {
		id := o.Target.InstanceID
		if id == "" {
			id = o.Target.ProbeID
		}
		if id != instanceID {
			continue
		}
		rows = append(rows, o)
	}
	sort.Slice(rows, func(i, j int) bool {
		if ri, rj := pingRole(rows[i].Target), pingRole(rows[j].Target); ri != rj {
			return ri < rj
		}
		return rows[i].Family < rows[j].Family
	})
	return rows
}

func formatPingResult(r health.ProbeResult) string {
	if r.Success {
		if r.RTT > 0 {
			return fmt.Sprintf("ok rtt=%s", r.RTT.Round(time.Microsecond))
		}
		return "ok"
	}
	if r.Error != "" {
		return fmt.Sprintf("fail error=%q", r.Error)
	}
	return "fail"
}
