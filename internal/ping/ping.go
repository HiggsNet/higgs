package ping

import (
	"context"
	"net/netip"
	"sort"
	"time"

	"github.com/Catofes/higgs/internal/inspect"
	"github.com/Catofes/higgs/pkg/health"
)

const (
	DefaultCount   = 4
	DefaultTimeout = time.Second
)

type Options struct {
	Count           int
	Timeout         time.Duration
	FallbackCount   int
	FallbackTimeout time.Duration
	Family          string
	Role            string
}

type ResolvedOptions struct {
	Count   int
	Timeout time.Duration
	Family  string
	Role    string
}

type Outcome struct {
	Target health.ProbeTarget
	Family string
	Result health.ProbeResult
}

func ResolveOptions(opts Options) ResolvedOptions {
	count := opts.Count
	if count <= 0 {
		count = opts.FallbackCount
	}
	if count <= 0 {
		count = DefaultCount
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = opts.FallbackTimeout
	}
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	return ResolvedOptions{
		Count:   count,
		Timeout: timeout,
		Family:  opts.Family,
		Role:    opts.Role,
	}
}

func (opts ResolvedOptions) ProbeConfig() health.ProbeConfig {
	return health.ProbeConfig{Timeout: opts.Timeout, Burst: opts.Count}
}

func SelectTargets(targets []health.ProbeTarget, peerZone string, opts Options) []health.ProbeTarget {
	return SelectTargetsResolved(targets, peerZone, ResolveOptions(opts))
}

func SelectTargetsResolved(targets []health.ProbeTarget, peerZone string, opts ResolvedOptions) []health.ProbeTarget {
	out := make([]health.ProbeTarget, 0, len(targets))
	for _, target := range targets {
		if !target.PeerTunnelAddr.IsValid() {
			continue
		}
		if string(target.PeerZone) != peerZone {
			continue
		}
		if opts.Family != "" && FamilyFor(target.PeerTunnelAddr) != opts.Family {
			continue
		}
		if opts.Role != "" && Role(target) != opts.Role {
			continue
		}
		out = append(out, target)
	}
	return out
}

func Run(ctx context.Context, prober health.Prober, targets []health.ProbeTarget, cfg health.ProbeConfig) []Outcome {
	out := make([]Outcome, 0, len(targets))
	for _, target := range targets {
		result := health.ProbeResult{InstanceID: target.InstanceID, Error: "no prober configured"}
		if prober != nil {
			result = prober.Probe(ctx, target, cfg)
		}
		out = append(out, Outcome{
			Target: target,
			Family: FamilyFor(target.PeerTunnelAddr),
			Result: result,
		})
	}
	return out
}

func BuildDebugView(peerZone string, outcomes []Outcome, availableZones []string, count int, timeout time.Duration) inspect.PingDebugView {
	view := inspect.PingDebugView{
		Zone:           peerZone,
		AvailableZones: append([]string(nil), availableZones...),
		Count:          count,
		Timeout:        timeout,
	}
	for _, outcome := range outcomes {
		view.Targets = append(view.Targets, inspect.PingTargetView{
			InstanceID:  outcome.Target.InstanceID,
			ProbeID:     outcome.Target.ProbeID,
			Role:        Role(outcome.Target),
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

func DistinctPeerZones(targets []health.ProbeTarget) []string {
	seen := map[string]struct{}{}
	for _, target := range targets {
		if target.PeerZone != "" {
			seen[target.PeerZone] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for peerZone := range seen {
		out = append(out, peerZone)
	}
	sort.Strings(out)
	return out
}

func FamilyFor(addr netip.Addr) string {
	if addr.Is6() {
		return "ipv6"
	}
	return "ipv4"
}

func Role(target health.ProbeTarget) string {
	if target.ProbeRole != "" {
		return target.ProbeRole
	}
	return "active"
}
