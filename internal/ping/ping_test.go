package ping

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/Catofes/higgs/pkg/health"
)

type fakeProber struct {
	byProbeID map[string]health.ProbeResult
	calls     int
}

func (f *fakeProber) Probe(_ context.Context, target health.ProbeTarget, _ health.ProbeConfig) health.ProbeResult {
	f.calls++
	if result, ok := f.byProbeID[target.ProbeID]; ok {
		return result
	}
	return health.ProbeResult{InstanceID: target.InstanceID, Error: "no fake result"}
}

func (fakeProber) Type() string { return health.ProbeTypeICMP }

func TestSelectTargetsByZoneFamilyAndRole(t *testing.T) {
	targets := []health.ProbeTarget{
		{InstanceID: "b4", PeerZone: "node-b.", ProbeRole: "active", UnderlayFamily: "ipv4", PeerTunnelAddr: netip.MustParseAddr("fd00::2")},
		{InstanceID: "b6", PeerZone: "node-b.", ProbeRole: "active", UnderlayFamily: "ipv6", PeerTunnelAddr: netip.MustParseAddr("fd00::3")},
		{InstanceID: "cold", PeerZone: "node-c.", ProbeRole: "old", PeerTunnelAddr: netip.MustParseAddr("fd00::3")},
		{InstanceID: "cstaged", PeerZone: "node-c.", ProbeRole: "staged", PeerTunnelAddr: netip.MustParseAddr("fd00::4")},
		{InstanceID: "bad", PeerZone: "node-c."},
	}
	tests := []struct {
		name    string
		zone    string
		opts    Options
		wantLen int
	}{
		{"zone-b all", "node-b.", Options{}, 2},
		{"zone-b ipv4", "node-b.", Options{Family: "ipv4"}, 1},
		{"zone-b ipv6", "node-b.", Options{Family: "ipv6"}, 1},
		{"zone-c all", "node-c.", Options{}, 2},
		{"zone-c staged", "node-c.", Options{Role: "staged"}, 1},
		{"zone-c old", "node-c.", Options{Role: "old"}, 1},
		{"unknown zone", "nope.", Options{}, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := SelectTargetsResolved(targets, tc.zone, ResolveOptions(tc.opts))
			if len(got) != tc.wantLen {
				t.Fatalf("SelectTargets(%s, %+v) = %d targets, want %d", tc.zone, tc.opts, len(got), tc.wantLen)
			}
		})
	}
}

func TestResolveOptionsUsesExplicitFallbackAndDefaults(t *testing.T) {
	explicit := ResolveOptions(Options{
		Count:           2,
		Timeout:         500 * time.Millisecond,
		FallbackCount:   3,
		FallbackTimeout: time.Second,
		Family:          "ipv4",
		Role:            "staged",
	})
	if explicit.Count != 2 || explicit.Timeout != 500*time.Millisecond || explicit.Family != "ipv4" || explicit.Role != "staged" {
		t.Fatalf("explicit resolved = %+v", explicit)
	}

	fallback := ResolveOptions(Options{
		FallbackCount:   3,
		FallbackTimeout: time.Second,
	})
	if fallback.Count != 3 || fallback.Timeout != time.Second {
		t.Fatalf("fallback resolved = %+v", fallback)
	}

	defaults := ResolveOptions(Options{})
	if defaults.Count != DefaultCount || defaults.Timeout != DefaultTimeout {
		t.Fatalf("defaults resolved = %+v, want count=%d timeout=%s", defaults, DefaultCount, DefaultTimeout)
	}
	if cfg := defaults.ProbeConfig(); cfg.Burst != DefaultCount || cfg.Timeout != DefaultTimeout {
		t.Fatalf("probe config = %+v", cfg)
	}
}

func TestRunUsesProber(t *testing.T) {
	targets := []health.ProbeTarget{
		{ProbeID: "t1", InstanceID: "t1", PeerZone: "z.", ProbeRole: "active", UnderlayFamily: "ipv4", PeerTunnelAddr: netip.MustParseAddr("fd00::2"), LocalTunnelAddr: netip.MustParseAddr("fd00::1")},
		{ProbeID: "t2", InstanceID: "t2", PeerZone: "z.", ProbeRole: "staged", UnderlayFamily: "ipv6", PeerTunnelAddr: netip.MustParseAddr("fd00::4"), LocalTunnelAddr: netip.MustParseAddr("fd00::3")},
	}
	fake := &fakeProber{byProbeID: map[string]health.ProbeResult{
		"t1": {Success: true, RTT: 2 * time.Millisecond},
		"t2": {Error: "100% packet loss"},
	}}
	outcomes := Run(context.Background(), fake, targets, health.ProbeConfig{})
	if len(outcomes) != 2 {
		t.Fatalf("outcomes = %d, want 2", len(outcomes))
	}
	if fake.calls != 2 {
		t.Fatalf("prober called %d times, want 2", fake.calls)
	}
	if outcomes[0].Family != "ipv4" || !outcomes[0].Result.Success {
		t.Fatalf("outcome[0] = %+v, want ipv4 success", outcomes[0])
	}
	if outcomes[1].Family != "ipv6" || outcomes[1].Result.Success || outcomes[1].Result.Error == "" {
		t.Fatalf("outcome[1] = %+v, want ipv6 failure with error", outcomes[1])
	}
}

func TestBuildDebugView(t *testing.T) {
	outcomes := []Outcome{{
		Target: health.ProbeTarget{
			ProbeID:         "t1",
			InstanceID:      "link-1",
			ProbeRole:       "staged",
			UnderlayFamily:  "ipv4",
			InterfaceName:   "hgs-new",
			NetNS:           "higgstesth2",
			LocalTunnelAddr: netip.MustParseAddr("fd00::1"),
			PeerTunnelAddr:  netip.MustParseAddr("fd00::2"),
		},
		Family: "ipv4",
		Result: health.ProbeResult{Success: true, RTT: time.Millisecond},
	}}
	view := BuildDebugView("node-b.", outcomes, []string{"node-a.", "node-b."}, 4, time.Second)
	if view.Zone != "node-b." || view.Count != 4 || view.Timeout != time.Second {
		t.Fatalf("view summary = %+v", view)
	}
	if len(view.Targets) != 1 {
		t.Fatalf("targets = %d, want 1", len(view.Targets))
	}
	target := view.Targets[0]
	if target.InstanceID != "link-1" || target.Role != "staged" || target.Family != "ipv4" || target.TunnelFamily != "ipv6" || target.NetNS != "higgstesth2" {
		t.Fatalf("target = %+v", target)
	}
	if !target.Success || target.RTT != time.Millisecond {
		t.Fatalf("target result = %+v", target)
	}
}

func TestDistinctPeerZones(t *testing.T) {
	got := DistinctPeerZones([]health.ProbeTarget{
		{PeerZone: "node-c."},
		{PeerZone: "node-b."},
		{PeerZone: "node-c."},
	})
	if len(got) != 2 || got[0] != "node-b." || got[1] != "node-c." {
		t.Fatalf("DistinctPeerZones = %v", got)
	}
}
