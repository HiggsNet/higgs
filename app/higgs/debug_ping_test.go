package main

import (
	"bytes"
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/Catofes/higgs/pkg/core/zone"
	"github.com/Catofes/higgs/pkg/health"
)

// fakePingProber is a test double for health.Prober, keyed by ProbeID.
type fakePingProber struct {
	byProbeID map[string]health.ProbeResult
	calls     int
}

func (f *fakePingProber) Probe(_ context.Context, t health.ProbeTarget, _ health.ProbeConfig) health.ProbeResult {
	f.calls++
	if r, ok := f.byProbeID[t.ProbeID]; ok {
		return r
	}
	return health.ProbeResult{InstanceID: t.InstanceID, Error: "no fake result"}
}

func (fakePingProber) Type() string { return health.ProbeTypeICMP }

// pingDebugTargets builds the health targets for a fixture state with a
// dual-stack non-rotating link to node-b. and a rotating IPv6 link to node-c.
func pingDebugTargets(t *testing.T) []health.ProbeTarget {
	t.Helper()
	state := &stateFile{
		ManagedZone: zone.ZonePath("local."),
		LinkInstances: map[string]linkInstanceState{
			"link-b": {ActualState: "up"},
			"link-c": {
				ActualState:           "up",
				InterfaceName:         "hgs-old",
				LocalTunnelAddr:       "fd00::1",
				PeerTunnelAddr:        "fd00::2",
				StagedGeneration:      2,
				RotatePhase:           "testing_new",
				StagedInterfaceName:   "hgs-new",
				StagedLocalTunnelAddr: "fd00::3",
				StagedPeerTunnelAddr:  "fd00::4",
			},
		},
		IPsecReconcile: &ipsecReconcileState{
			Desired: []desiredLinkState{
				{InstanceID: "link-b", GroupID: "g", PeerZone: zone.ZonePath("node-b."), LocalTunnelAddr: "10.0.0.1", PeerTunnelAddr: "10.0.0.2"},
				{InstanceID: "link-b", GroupID: "g", PeerZone: zone.ZonePath("node-b."), LocalTunnelAddr: "fd00::1", PeerTunnelAddr: "fd00::2"},
				{InstanceID: "link-c", GroupID: "g", PeerZone: zone.ZonePath("node-c."), LocalTunnelAddr: "fd00::1", PeerTunnelAddr: "fd00::2"},
			},
		},
	}
	return healthTargetsFromState(state, string(state.ManagedZone), nil)
}

func TestSelectPingTargetsByZone(t *testing.T) {
	targets := pingDebugTargets(t)
	// Sanity: the fixture yields link-b (ipv4+ipv6 active) and link-c (old+staged ipv6).
	if got := len(targets); got != 4 {
		t.Fatalf("fixture targets = %d, want 4", got)
	}

	tests := []struct {
		name    string
		zone    zone.ZonePath
		opts    pingFlags
		wantLen int
	}{
		{"zone-b all", "node-b.", pingFlags{}, 2},
		{"zone-b ipv4", "node-b.", pingFlags{family: "ipv4"}, 1},
		{"zone-b ipv6", "node-b.", pingFlags{family: "ipv6"}, 1},
		{"zone-c all", "node-c.", pingFlags{}, 2},
		{"zone-c staged", "node-c.", pingFlags{role: "staged"}, 1},
		{"zone-c old", "node-c.", pingFlags{role: "old"}, 1},
		{"unknown zone", "nope.", pingFlags{}, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := selectPingTargets(targets, tc.zone, tc.opts)
			if len(got) != tc.wantLen {
				t.Fatalf("selectPingTargets(%s, %+v) = %d targets, want %d", tc.zone, tc.opts, len(got), tc.wantLen)
			}
		})
	}

	// The rotate pair for node-c. must be exactly old + staged.
	cSel := selectPingTargets(targets, "node-c.", pingFlags{})
	roles := map[string]bool{}
	for _, sel := range cSel {
		roles[pingRole(sel)] = true
	}
	if !roles["old"] || !roles["staged"] {
		t.Fatalf("node-c. roles = %v, want old+staged", roles)
	}
}

func TestRunPingOutcomesUsesProber(t *testing.T) {
	targets := []health.ProbeTarget{
		{ProbeID: "t1", InstanceID: "t1", PeerZone: "z.", ProbeRole: "active", PeerTunnelAddr: netip.MustParseAddr("10.0.0.2"), LocalTunnelAddr: netip.MustParseAddr("10.0.0.1")},
		{ProbeID: "t2", InstanceID: "t2", PeerZone: "z.", ProbeRole: "staged", PeerTunnelAddr: netip.MustParseAddr("fd00::2"), LocalTunnelAddr: netip.MustParseAddr("fd00::1")},
	}
	fake := &fakePingProber{byProbeID: map[string]health.ProbeResult{
		"t1": {Success: true, RTT: 2 * time.Millisecond},
		"t2": {Success: false, Error: "100% packet loss"},
	}}
	outcomes := runPingOutcomes(context.Background(), fake, targets, health.ProbeConfig{})
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

func TestWritePingReportOutput(t *testing.T) {
	outcomes := []pingOutcome{
		{
			Target: health.ProbeTarget{ProbeID: "t1", InstanceID: "t1", ProbeRole: "active", InterfaceName: "hgs0", NetNS: "higgstesth2",
				LocalTunnelAddr: netip.MustParseAddr("10.0.0.1"), PeerTunnelAddr: netip.MustParseAddr("10.0.0.2")},
			Family: "ipv4",
			Result: health.ProbeResult{Success: true, RTT: 2300 * time.Microsecond},
		},
		{
			Target: health.ProbeTarget{ProbeID: "t2", InstanceID: "t1", ProbeRole: "staged", InterfaceName: "hgs-new",
				LocalTunnelAddr: netip.MustParseAddr("fd00::1"), PeerTunnelAddr: netip.MustParseAddr("fd00::2")},
			Family: "ipv6",
			Result: health.ProbeResult{Success: false, Error: "100% packet loss"},
		},
	}
	var buf bytes.Buffer
	if err := writePingReport(&buf, "node-b.", outcomes, []string{"node-b.", "node-c."}, 4, time.Second); err != nil {
		t.Fatalf("writePingReport: %v", err)
	}
	got := buf.String()
	for _, want := range []string{
		"zone: node-b.",
		"targets: 2",
		"count: 4 timeout: 1s",
		"instance t1",
		"role=active family=ipv4",
		"interface: hgs0  netns: higgstesth2",
		"result: ok rtt=2.3ms",
		"role=staged family=ipv6",
		`result: fail error="100% packet loss"`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("report missing %q\n--- got ---\n%s", want, got)
		}
	}
	// Rows for the same instance are ordered active before staged.
	if actIdx, stgIdx := strings.Index(got, "role=active"), strings.Index(got, "role=staged"); actIdx >= stgIdx {
		t.Errorf("expected active row before staged row in report\n%s", got)
	}
}

func TestWritePingReportEmpty(t *testing.T) {
	var buf bytes.Buffer
	if err := writePingReport(&buf, "nope.", nil, []string{"node-b.", "node-c."}, 4, time.Second); err != nil {
		t.Fatalf("writePingReport: %v", err)
	}
	got := buf.String()
	for _, want := range []string{
		"zone: nope.",
		"targets: 0",
		"no IPsec link instances for zone nope.",
		"available peer zones: node-b., node-c.",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("report missing %q\n--- got ---\n%s", want, got)
		}
	}
}
