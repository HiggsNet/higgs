package main

import (
	"context"
	"fmt"
	"io"
	"net/netip"
	"os"
	"sort"
	"time"

	"github.com/Catofes/higgs/internal/inspect"
	inspecttext "github.com/Catofes/higgs/internal/inspect/text"
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
	return inspecttext.WritePingDebug(w, buildPingDebugView(peerZone, outcomes, availableZones, count, timeout))
}

func buildPingDebugView(peerZone zone.ZonePath, outcomes []pingOutcome, availableZones []string, count int, timeout time.Duration) inspect.PingDebugView {
	view := inspect.PingDebugView{
		Zone:           string(peerZone),
		AvailableZones: append([]string(nil), availableZones...),
		Count:          count,
		Timeout:        timeout,
	}
	for _, outcome := range outcomes {
		view.Targets = append(view.Targets, inspect.PingTargetView{
			InstanceID:  outcome.Target.InstanceID,
			ProbeID:     outcome.Target.ProbeID,
			Role:        pingRole(outcome.Target),
			Family:      outcome.Family,
			Interface:   outcome.Target.InterfaceName,
			NetNS:       outcome.Target.NetNS,
			LocalTunnel: outcome.Target.LocalTunnelAddr.String(),
			PeerTunnel:  outcome.Target.PeerTunnelAddr.String(),
			Success:     outcome.Result.Success,
			RTT:         outcome.Result.RTT,
			Error:       outcome.Result.Error,
		})
	}
	return view
}
