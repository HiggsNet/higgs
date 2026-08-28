package main

import (
	"context"
	"fmt"
	"os"

	inspecttext "github.com/HiggsNet/photon/internal/inspect/text"
	pingdebug "github.com/HiggsNet/photon/internal/ping"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/health"
)

// debugPing resolves the IPsec link targets for a peer zone and pings each one
// (current SA, plus old and new SA during a rotate) across IPv4/IPv6. It runs
// the pings directly in the CLI process via the health ICMP prober.
func debugPing(ctx context.Context, peerZone zone.ZonePath, opts pingdebug.Options) error {
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
	targets := healthTargets(state.LinkInstances, state.IPsecReconcile, localZone)
	if rt.Config != nil {
		opts.FallbackCount = rt.Config.Health.Burst
		opts.FallbackTimeout = rt.Config.Health.Timeout
	}
	resolved := pingdebug.ResolveOptions(opts)
	selected := pingdebug.SelectTargetsResolved(targets, string(peerZone), resolved)

	prober := health.NewICMProber(nil, nil)
	outcomes := pingdebug.Run(ctx, prober, selected, resolved.ProbeConfig())
	view := pingdebug.BuildDebugView(string(peerZone), outcomes, pingdebug.DistinctPeerZones(targets), resolved.Count, resolved.Timeout)
	return inspecttext.WritePingDebug(os.Stdout, view)
}
