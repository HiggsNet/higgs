package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Catofes/higgs/pkg/core/gossip"
	"github.com/Catofes/higgs/pkg/core/zone"
	higgscrypto "github.com/Catofes/higgs/pkg/crypto"
	"github.com/Catofes/higgs/pkg/transport/ipsec"
)

func TestNewDaemonServiceDefaultsInterval(t *testing.T) {
	service := newDaemonService(&Runtime{}, &stateFile{}, &syncConfigFile{}, 0)
	if service.Interval != defaultDaemonInterval {
		t.Fatalf("default interval = %s, want %s", service.Interval, defaultDaemonInterval)
	}
	if service.Sync == nil {
		t.Fatal("sync runtime is nil")
	}
}

func TestConfiguredStrongSwanDriverWithoutLinkGroupsIsNoop(t *testing.T) {
	drivers, err := newConfiguredIPsecDrivers(ipsecConfig{Driver: ipsecDriverStrongSwan}, nil)
	if err != nil {
		t.Fatalf("newConfiguredIPsecDrivers: %v", err)
	}
	if drivers.ipsecDriver != nil || drivers.xfrmDriver != nil || drivers.close != nil {
		t.Fatalf("drivers = %+v, want no-op without link groups", drivers)
	}
}

func TestDaemonServiceStateChangedHook(t *testing.T) {
	state := &stateFile{}
	service := newDaemonService(&Runtime{}, state, &syncConfigFile{}, time.Second)
	var called bool
	service.Hooks.OnStateChanged = func(got *stateFile) {
		called = true
		if got != state {
			t.Fatalf("hook got unexpected state pointer")
		}
	}
	service.notifyStateChanged()
	if !called {
		t.Fatal("state changed hook was not called")
	}
}

func TestDaemonStateChangedReconcilesIPsecLinks(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(4000, 0)
	addTestIPsecRecords(t, state.Network.Zones["node-b.catofes."], "node-b.catofes.", now, ipsec.AcceptInbound)
	appConfig := defaultAppConfig()
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{{
		ID:                 "main",
		Provider:           ipsec.ProviderStrongSwan,
		NetNS:              ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: "h2", Create: true},
		DefaultPathMode:    ipsec.PathModeFamilyRedundant,
		AddressSourceOrder: []string{ipsec.SourceManualAddress},
		ConnectRules:       []string{"strongswan://*.catofes.?accept=inbound"},
	}}
	rt := &Runtime{
		Config:    appConfig,
		StatePath: filepath.Join(t.TempDir(), "higgs.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	service := newDaemonService(rt, state, config, time.Second)

	service.notifyStateChanged()

	latest, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if len(latest.LinkInstances) != 1 {
		t.Fatalf("link instances len = %d, want 1", len(latest.LinkInstances))
	}
	if latest.IPsecReconcile == nil || latest.IPsecReconcile.DesiredLinks != 1 {
		t.Fatalf("ipsec reconcile = %+v, want one desired link", latest.IPsecReconcile)
	}
	if len(latest.IPsecReconcile.Actions) != 1 || latest.IPsecReconcile.Actions[0].Action != ipsec.ReconcileActionCreate {
		t.Fatalf("actions = %+v, want create", latest.IPsecReconcile.Actions)
	}
	for _, inst := range latest.LinkInstances {
		if inst.Owner.Manager != "higgs" || inst.ActualState != ipsec.LinkStateConnecting {
			t.Fatalf("instance = %+v, want higgs connecting", inst)
		}
	}

	service.setState(latest)
	service.notifyStateChanged()
	reloaded, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState(second): %v", err)
	}
	if len(reloaded.LinkInstances) != 1 {
		t.Fatalf("second link instances len = %d, want 1", len(reloaded.LinkInstances))
	}
	if len(reloaded.IPsecReconcile.Actions) != 1 || reloaded.IPsecReconcile.Actions[0].Action != ipsec.ReconcileActionNoop {
		t.Fatalf("second actions = %+v, want noop", reloaded.IPsecReconcile.Actions)
	}
}

func TestDaemonStateChangedReconcilesIPsecPortRotation(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(4000, 0)
	state.Network.Zones["node-a.catofes."] = zone.NewZoneState("node-a.catofes.", nil)
	addTestIPsecRecords(t, state.Network.Zones["node-a.catofes."], "node-a.catofes.", now, ipsec.AcceptNone)
	addTestIPsecRecords(t, state.Network.Zones["node-b.catofes."], "node-b.catofes.", now, ipsec.AcceptInbound)
	appConfig := defaultAppConfig()
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{{
		ID:                 "main",
		Provider:           ipsec.ProviderStrongSwan,
		NetNS:              ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: "h2", Create: true},
		DefaultPathMode:    ipsec.PathModeFamilyRedundant,
		AddressSourceOrder: []string{ipsec.SourceManualAddress},
		ConnectRules:       []string{"strongswan://*.catofes.?accept=inbound"},
	}}
	rt := &Runtime{
		Config:    appConfig,
		StatePath: filepath.Join(t.TempDir(), "higgs.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	service := newDaemonService(rt, state, config, time.Second)
	service.notifyStateChanged()

	latest, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	var inst linkInstanceState
	for _, v := range latest.LinkInstances {
		inst = v
	}
	if inst.ActualState != ipsec.LinkStateConnecting {
		t.Fatalf("initial state = %q, want connecting", inst.ActualState)
	}

	// Simulate peer publishing generation 2 port record.
	state = latest
	zs := state.Network.Zones["node-b.catofes."]
	zs.Records[ipsec.RecordKeyPorts] = unsignedIPsecRecord(t, "node-b.catofes.", ipsec.RecordKeyPorts, ipsec.RecordTypePorts, ipsec.PortRecord{
		Version: 1,
		Mode:    ipsec.PortModeFixed,
		Current: &ipsec.PortSelection{
			Generation: 2,
			IKE:        ipsec.PortBinding{Advertised: ipsec.DefaultIKEPort},
			NATT:       ipsec.PortBinding{Advertised: 4501},
		},
		UpdatedAt: now.Unix(),
	})
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState(rotate): %v", err)
	}
	service.setState(state)
	service.notifyStateChanged()

	rotated, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState(rotate): %v", err)
	}
	for _, v := range rotated.LinkInstances {
		inst = v
	}
	if inst.RotatePhase != ipsec.RotatePhaseTestingNew {
		t.Fatalf("rotate phase = %q, want testing_new", inst.RotatePhase)
	}
	if inst.StagedGeneration != 2 {
		t.Fatalf("staged generation = %d, want 2", inst.StagedGeneration)
	}
	if inst.StagedIKEName != ipsec.RuntimeConnectionID(inst.LinkID, 2, inst.TransportKind) {
		t.Fatalf("staged ike name = %q", inst.StagedIKEName)
	}
	foundPrepare := false
	for _, action := range rotated.IPsecReconcile.Actions {
		if action.Action == ipsec.ReconcileActionPrepareRotate {
			foundPrepare = true
		}
	}
	if !foundPrepare {
		t.Fatalf("expected prepare_rotate action, got %+v", rotated.IPsecReconcile.Actions)
	}
}

func TestDaemonReconcileUsesSystemXFRMDriverSmoke(t *testing.T) {
	if os.Getenv("HIGGS_IPSEC_XFRM_SMOKE") != "1" {
		t.Skip("set HIGGS_IPSEC_XFRM_SMOKE=1 to run the root/system XFRM smoke")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	state, config := buildTestNetworkState(t)
	now := time.Unix(4060, 0)
	addTestIPsecRecords(t, state.Network.Zones["node-b.catofes."], "node-b.catofes.", now, ipsec.AcceptInbound)

	ns := "higgs-daemon-xfrm-" + time.Now().UTC().Format("20060102150405")
	group := testIPsecLinkGroup()
	group.NetNS = ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: ns, Create: true}
	setTestIPsecOverlayIntent(t, state.Network.Zones["node-b.catofes."], "node-b.catofes.", group, now)
	appConfig := defaultAppConfig()
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{group}
	rt := &Runtime{
		Config:    appConfig,
		StatePath: filepath.Join(t.TempDir(), "higgs.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	t.Cleanup(func() {
		_, _ = appExecCommand(context.Background(), "ip", "netns", "delete", ns)
	})

	service := newDaemonService(rt, state, config, time.Second)
	service.IPsecDriver = &observedIPsecDriver{}
	service.XFRMDriver = ipsec.NewSystemXFRMDriver(group.NetNS)
	service.recoverIPsecLinksOnStart(ctx)

	latest, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if latest.IPsecReconcile == nil || latest.IPsecReconcile.LastError != "" {
		t.Fatalf("ipsec reconcile = %+v, want successful system xfrm apply", latest.IPsecReconcile)
	}
	if len(latest.LinkInstances) != 1 {
		t.Fatalf("link instances = %+v, want one system-applied link", latest.LinkInstances)
	}
	var inst linkInstanceState
	for _, item := range latest.LinkInstances {
		inst = item
	}
	if inst.ActualState != ipsec.LinkStateConnecting {
		t.Fatalf("instance state = %+v, want connecting after provider apply", inst)
	}
	if _, err := appExecCommand(ctx, "ip", "netns", "exec", ns, "ip", "link", "show", "dev", inst.InterfaceName); err != nil {
		t.Fatalf("daemon-created xfrm interface %s not visible in %s: %v", inst.InterfaceName, ns, err)
	}
	if _, err := appExecCommand(ctx, "ip", "netns", "exec", ns, "ip", "addr", "show", "dev", inst.InterfaceName); err != nil {
		t.Fatalf("daemon-assigned tunnel address not visible on %s/%s: %v", ns, inst.InterfaceName, err)
	}

	service.setState(latest)
	service.Sync.App.Config.IPsec.LinkGroups = nil
	service.recoverIPsecLinksOnStart(ctx)
	removed, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState(after teardown): %v", err)
	}
	if removed.IPsecReconcile == nil || removed.IPsecReconcile.LastError != "" {
		t.Fatalf("teardown reconcile = %+v, want successful system xfrm teardown", removed.IPsecReconcile)
	}
	if len(removed.LinkInstances) != 0 {
		t.Fatalf("link instances after teardown = %+v, want none", removed.LinkInstances)
	}
	if _, err := appExecCommand(ctx, "ip", "netns", "exec", ns, "ip", "link", "show", "dev", inst.InterfaceName); err == nil {
		t.Fatalf("daemon-created xfrm interface %s still exists after teardown", inst.InterfaceName)
	}
}

func TestDaemonStrongSwanReconcileBringupSmoke(t *testing.T) {
	if os.Getenv("HIGGS_IPSEC_XFRM_SMOKE") != "1" {
		t.Skip("set HIGGS_IPSEC_XFRM_SMOKE=1 to run the root/system StrongSwan daemon smoke")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 70*time.Second)
	defer cancel()

	suffix := time.Now().UTC().Format("20060102150405")
	nsA := "higgs-daemon-ike-a-" + suffix
	nsB := "higgs-daemon-ike-b-" + suffix
	viciA := "/tmp/charon-" + nsA + ".vici"
	viciB := "/tmp/charon-" + nsB + ".vici"
	t.Cleanup(func() {
		_, _ = appExecCommand(context.Background(), "ip", "netns", "delete", nsA)
		_, _ = appExecCommand(context.Background(), "ip", "netns", "delete", nsB)
		_ = os.Remove(viciA)
		_ = os.Remove(viciB)
	})

	runAppCommand(t, ctx, "ip", "netns", "add", nsA)
	runAppCommand(t, ctx, "ip", "netns", "add", nsB)
	runAppCommand(t, ctx, "ip", "link", "add", "hgdvetha", "type", "veth", "peer", "name", "hgdvethb")
	runAppCommand(t, ctx, "ip", "link", "set", "hgdvetha", "netns", nsA)
	runAppCommand(t, ctx, "ip", "link", "set", "hgdvethb", "netns", nsB)
	for _, args := range [][]string{
		{"netns", "exec", nsA, "ip", "link", "set", "lo", "up"},
		{"netns", "exec", nsB, "ip", "link", "set", "lo", "up"},
		{"netns", "exec", nsA, "ip", "addr", "add", "192.0.2.1/30", "dev", "hgdvetha"},
		{"netns", "exec", nsB, "ip", "addr", "add", "192.0.2.2/30", "dev", "hgdvethb"},
		{"netns", "exec", nsA, "ip", "link", "set", "hgdvetha", "up"},
		{"netns", "exec", nsB, "ip", "link", "set", "hgdvethb", "up"},
	} {
		runAppCommand(t, ctx, "ip", args...)
	}

	confA, err := writeDaemonStrongSwanConf(viciA)
	if err != nil {
		t.Fatalf("write strongswan.conf A: %v", err)
	}
	confB, err := writeDaemonStrongSwanConf(viciB)
	if err != nil {
		t.Fatalf("write strongswan.conf B: %v", err)
	}
	piddirA := t.TempDir()
	piddirB := t.TempDir()
	logA, err := os.CreateTemp("", "higgs-daemon-charon-a-*.log")
	if err != nil {
		t.Fatalf("create charon A log: %v", err)
	}
	logB, err := os.CreateTemp("", "higgs-daemon-charon-b-*.log")
	if err != nil {
		t.Fatalf("create charon B log: %v", err)
	}
	charonA := startDaemonTestCharonInNetNS(ctx, t, nsA, piddirA, confA, logA)
	charonB := startDaemonTestCharonInNetNS(ctx, t, nsB, piddirB, confB, logB)
	defer func() {
		_ = charonA.Process.Kill()
		_ = charonB.Process.Kill()
		_ = charonA.Wait()
		_ = charonB.Wait()
		_ = os.Remove(confA)
		_ = os.Remove(confB)
		_ = logA.Close()
		_ = logB.Close()
		_ = os.Remove(logA.Name())
		_ = os.Remove(logB.Name())
	}()
	clientA, err := waitDaemonTestVICI(ctx, viciA)
	if err != nil {
		t.Fatalf("connect to charon A VICI: %v", err)
	}
	defer clientA.Close()
	clientB, err := waitDaemonTestVICI(ctx, viciB)
	if err != nil {
		t.Fatalf("connect to charon B VICI: %v", err)
	}
	defer clientB.Close()
	defer func() {
		if t.Failed() {
			dumpCtx, dumpCancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer dumpCancel()
			logDaemonTestFile(t, "charon A", logA.Name())
			logDaemonTestFile(t, "charon B", logB.Name())
			dumpDaemonSystemState(t, dumpCtx, nsA, nsB)
			dumpDaemonVICISAs(t, dumpCtx, viciA, "A")
			dumpDaemonVICISAs(t, dumpCtx, viciB, "B")
		}
	}()

	now := time.Unix(4140, 0)
	stateA, configA, stateB, configB := buildTestABDaemonStates(t)
	keyA, recordA := daemonTestTransportKey(t, now)
	keyB, recordB := daemonTestTransportKey(t, now)
	stateA.IPsecTransportKey = keyA
	stateB.IPsecTransportKey = keyB
	addDaemonTestIPsecRecords(t, stateA.Network.Zones["node-a.catofes."], "node-a.catofes.", "192.0.2.1", recordA, ipsec.AcceptNone, now)
	addDaemonTestIPsecRecords(t, stateB.Network.Zones["node-b.catofes."], "node-b.catofes.", "192.0.2.2", recordB, ipsec.AcceptInbound, now)
	stateA.Network.Zones["node-b.catofes."] = stateB.Network.Zones["node-b.catofes."]
	stateB.Network.Zones["node-a.catofes."] = stateA.Network.Zones["node-a.catofes."]

	groupA := testIPsecLinkGroup()
	groupA.ConnectRules = nil
	groupA.NetNS = ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: nsA, Create: false}
	groupA.TunnelAddressSpec = ipsec.TunnelAddressSpec{Mode: ipsec.TunnelAddressDerivedLinkLocal, Family: ipsec.FamilyIPv6}
	groupA.Reconcile.RotateRetentionSeconds = 0
	groupB := testIPsecLinkGroup()
	groupB.ConnectRules = nil
	groupB.NetNS = ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: nsB, Create: false}
	groupB.TunnelAddressSpec = ipsec.TunnelAddressSpec{Mode: ipsec.TunnelAddressDerivedLinkLocal, Family: ipsec.FamilyIPv6}
	groupB.Reconcile.RotateRetentionSeconds = 0
	rtA := &Runtime{
		Config:    testDaemonIPsecAppConfig(t.TempDir(), "127.0.0.1:0", groupA),
		StatePath: filepath.Join(t.TempDir(), "node-a.db"),
		Clock:     func() time.Time { return now },
	}
	rtB := &Runtime{
		Config:    testDaemonIPsecAppConfig(t.TempDir(), "127.0.0.1:0", groupB),
		StatePath: filepath.Join(t.TempDir(), "node-b.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rtA.SaveState(stateA); err != nil {
		t.Fatalf("SaveState(node-a): %v", err)
	}
	if err := rtB.SaveState(stateB); err != nil {
		t.Fatalf("SaveState(node-b): %v", err)
	}
	serviceA := newDaemonService(rtA, stateA, configA, time.Second)
	serviceA.IPsecDriver = &ipsec.StrongSwanDriver{VICI: clientA, KeyDir: t.TempDir()}
	serviceA.XFRMDriver = daemonTestXFRMDriver(groupA.NetNS, nsA)
	serviceB := newDaemonService(rtB, stateB, configB, time.Second)
	serviceB.IPsecDriver = &ipsec.StrongSwanDriver{VICI: clientB, KeyDir: t.TempDir()}
	serviceB.XFRMDriver = daemonTestXFRMDriver(groupB.NetNS, nsB)

	serviceB.recoverIPsecLinksOnStart(ctx)
	serviceA.recoverIPsecLinksOnStart(ctx)
	latestA, err := rtA.LoadState()
	if err != nil {
		t.Fatalf("LoadState(node-a connecting): %v", err)
	}
	latestB, err := rtB.LoadState()
	if err != nil {
		t.Fatalf("LoadState(node-b connecting): %v", err)
	}
	specA := daemonSystemDesiredSpec(t, latestA, groupA, now)
	specB := daemonSystemDesiredSpec(t, latestB, groupB, now)
	if err := waitDaemonTestSA(ctx, clientA, specA.TransportID); err != nil {
		t.Fatalf("wait for daemon SA on A: %v", err)
	}
	if err := waitDaemonTestSA(ctx, clientB, specB.TransportID); err != nil {
		t.Fatalf("wait for daemon SA on B: %v", err)
	}

	serviceA.setState(latestA)
	serviceB.setState(latestB)
	serviceA.recoverIPsecLinksOnStart(ctx)
	serviceB.recoverIPsecLinksOnStart(ctx)
	latestA, err = rtA.LoadState()
	if err != nil {
		t.Fatalf("LoadState(node-a up): %v", err)
	}
	latestB, err = rtB.LoadState()
	if err != nil {
		t.Fatalf("LoadState(node-b up): %v", err)
	}
	assertDaemonSystemLinkUp(t, latestA, specA)
	assertDaemonSystemLinkUp(t, latestB, specB)

	addTunnelRoute(t, ctx, nsA, specA)
	addTunnelRoute(t, ctx, nsB, specB)
	pingTunnelAddr(t, ctx, nsA, specA.PeerTunnelAddr, specA.InterfaceName)
	pingTunnelAddr(t, ctx, nsB, specB.PeerTunnelAddr, specB.InterfaceName)

	restartedA, err := rtA.LoadState()
	if err != nil {
		t.Fatalf("LoadState(node-a before restart): %v", err)
	}
	restartServiceA := newDaemonService(rtA, restartedA, configA, time.Second)
	restartServiceA.IPsecDriver = &ipsec.StrongSwanDriver{VICI: clientA, KeyDir: t.TempDir()}
	restartServiceA.XFRMDriver = daemonTestXFRMDriver(groupA.NetNS, nsA)
	restartServiceA.recoverIPsecLinksOnStart(ctx)
	recoveredA, err := rtA.LoadState()
	if err != nil {
		t.Fatalf("LoadState(node-a after restart): %v", err)
	}
	assertDaemonSystemLinkUp(t, recoveredA, specA)
	if recoveredA.IPsecReconcile == nil || len(recoveredA.IPsecReconcile.Actions) != 1 {
		t.Fatalf("restart reconcile = %+v, want one recovery observation action", recoveredA.IPsecReconcile)
	}
	restartAction := recoveredA.IPsecReconcile.Actions[0].Action
	if restartAction != ipsec.ReconcileActionAdopt && restartAction != ipsec.ReconcileActionNoop {
		t.Fatalf("restart reconcile action = %s, want adopt or noop with existing SA", restartAction)
	}
	if count, err := daemonTestEstablishedSACount(ctx, clientA, specA.TransportID); err != nil {
		t.Fatalf("count node-a SAs after restart: %v", err)
	} else if count != 1 {
		t.Fatalf("node-a established SA count after restart = %d, want 1", count)
	}
	pingTunnelAddr(t, ctx, nsA, specA.PeerTunnelAddr, specA.InterfaceName)

	parent := recoveredA.Network.Zones["catofes."]
	if parent == nil || parent.Delegations["node-b.catofes."] == nil {
		t.Fatalf("node-a state missing node-b delegation before revoke")
	}
	delegation := parent.Delegations["node-b.catofes."]
	parent.Revocations["node-b.catofes."] = &zone.DelegationRevocation{
		ChildZone:             "node-b.catofes.",
		ParentZone:            "catofes.",
		RevokedAuthorityEpoch: delegation.AuthorityEpoch,
		RevokedAuthorityHash:  delegation.AuthorityHash,
		Reason:                "ipsec root smoke revoke",
		RevokedAt:             now.Add(-time.Second).Unix(),
	}
	if err := rtA.SaveState(recoveredA); err != nil {
		t.Fatalf("SaveState(node-a revoked): %v", err)
	}
	restartServiceA.setState(recoveredA)
	restartServiceA.recoverIPsecLinksOnStart(ctx)
	revokedA, err := rtA.LoadState()
	if err != nil {
		t.Fatalf("LoadState(node-a revoked): %v", err)
	}
	if len(revokedA.LinkInstances) != 0 {
		t.Fatalf("node-a link instances after revoke = %+v, want none", revokedA.LinkInstances)
	}
	if revokedA.IPsecReconcile == nil || len(revokedA.IPsecReconcile.Actions) != 1 || revokedA.IPsecReconcile.Actions[0].Action != ipsec.ReconcileActionTeardown {
		t.Fatalf("revoke reconcile = %+v, want teardown", revokedA.IPsecReconcile)
	}
	if !hasDebugSkip(revokedA.IPsecReconcile.Skipped, "node-b.catofes.", ipsec.SkipRevokedZone) {
		t.Fatalf("revoke skips = %+v, want revoked node-b", revokedA.IPsecReconcile.Skipped)
	}
	if err := waitDaemonTestNoSA(ctx, clientA, specA.TransportID); err != nil {
		t.Fatalf("node-a SA after revoke: %v", err)
	}
	if _, err := appExecCommand(ctx, "ip", "netns", "exec", nsA, "ip", "link", "show", "dev", specA.InterfaceName); err == nil {
		t.Fatalf("node-a xfrm interface %s still exists after revoke", specA.InterfaceName)
	}
	if out := pingTunnelAddrShouldFail(t, ctx, nsA, specA.PeerTunnelAddr, specA.InterfaceName); out != nil {
		t.Logf("post-revoke ping failed as expected: %s", string(out))
	}
}

func TestDaemonStrongSwanReconcileBringupDerivedPoolSmoke(t *testing.T) {
	if os.Getenv("HIGGS_IPSEC_XFRM_SMOKE") != "1" {
		t.Skip("set HIGGS_IPSEC_XFRM_SMOKE=1 to run the root/system StrongSwan daemon smoke")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 70*time.Second)
	defer cancel()

	suffix := time.Now().UTC().Format("20060102150405")
	nsA := "higgs-daemon-pool-a-" + suffix
	nsB := "higgs-daemon-pool-b-" + suffix
	viciA := "/tmp/charon-" + nsA + ".vici"
	viciB := "/tmp/charon-" + nsB + ".vici"
	t.Cleanup(func() {
		_, _ = appExecCommand(context.Background(), "ip", "netns", "delete", nsA)
		_, _ = appExecCommand(context.Background(), "ip", "netns", "delete", nsB)
		_ = os.Remove(viciA)
		_ = os.Remove(viciB)
	})

	runAppCommand(t, ctx, "ip", "netns", "add", nsA)
	runAppCommand(t, ctx, "ip", "netns", "add", nsB)
	runAppCommand(t, ctx, "ip", "link", "add", "hgdpoola", "type", "veth", "peer", "name", "hgdpoolb")
	runAppCommand(t, ctx, "ip", "link", "set", "hgdpoola", "netns", nsA)
	runAppCommand(t, ctx, "ip", "link", "set", "hgdpoolb", "netns", nsB)
	for _, args := range [][]string{
		{"netns", "exec", nsA, "ip", "link", "set", "lo", "up"},
		{"netns", "exec", nsB, "ip", "link", "set", "lo", "up"},
		{"netns", "exec", nsA, "ip", "addr", "add", "192.0.2.1/30", "dev", "hgdpoola"},
		{"netns", "exec", nsB, "ip", "addr", "add", "192.0.2.2/30", "dev", "hgdpoolb"},
		{"netns", "exec", nsA, "ip", "link", "set", "hgdpoola", "up"},
		{"netns", "exec", nsB, "ip", "link", "set", "hgdpoolb", "up"},
	} {
		runAppCommand(t, ctx, "ip", args...)
	}

	confA, err := writeDaemonStrongSwanConf(viciA)
	if err != nil {
		t.Fatalf("write strongswan.conf A: %v", err)
	}
	confB, err := writeDaemonStrongSwanConf(viciB)
	if err != nil {
		t.Fatalf("write strongswan.conf B: %v", err)
	}
	piddirA := t.TempDir()
	piddirB := t.TempDir()
	logA, err := os.CreateTemp("", "higgs-daemon-charon-pool-a-*.log")
	if err != nil {
		t.Fatalf("create charon A log: %v", err)
	}
	logB, err := os.CreateTemp("", "higgs-daemon-charon-pool-b-*.log")
	if err != nil {
		t.Fatalf("create charon B log: %v", err)
	}
	charonA := startDaemonTestCharonInNetNS(ctx, t, nsA, piddirA, confA, logA)
	charonB := startDaemonTestCharonInNetNS(ctx, t, nsB, piddirB, confB, logB)
	defer func() {
		_ = charonA.Process.Kill()
		_ = charonB.Process.Kill()
		_ = charonA.Wait()
		_ = charonB.Wait()
		_ = os.Remove(confA)
		_ = os.Remove(confB)
		_ = logA.Close()
		_ = logB.Close()
		_ = os.Remove(logA.Name())
		_ = os.Remove(logB.Name())
	}()
	clientA, err := waitDaemonTestVICI(ctx, viciA)
	if err != nil {
		t.Fatalf("connect to charon A VICI: %v", err)
	}
	defer clientA.Close()
	clientB, err := waitDaemonTestVICI(ctx, viciB)
	if err != nil {
		t.Fatalf("connect to charon B VICI: %v", err)
	}
	defer clientB.Close()
	defer func() {
		if t.Failed() {
			dumpCtx, dumpCancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer dumpCancel()
			logDaemonTestFile(t, "charon A", logA.Name())
			logDaemonTestFile(t, "charon B", logB.Name())
			dumpDaemonSystemState(t, dumpCtx, nsA, nsB)
			dumpDaemonVICISAs(t, dumpCtx, viciA, "A")
			dumpDaemonVICISAs(t, dumpCtx, viciB, "B")
		}
	}()

	now := time.Unix(4140, 0)
	stateA, configA, stateB, configB := buildTestABDaemonStates(t)
	keyA, recordA := daemonTestTransportKey(t, now)
	keyB, recordB := daemonTestTransportKey(t, now)
	stateA.IPsecTransportKey = keyA
	stateB.IPsecTransportKey = keyB
	addDaemonTestIPsecRecords(t, stateA.Network.Zones["node-a.catofes."], "node-a.catofes.", "192.0.2.1", recordA, ipsec.AcceptNone, now)
	addDaemonTestIPsecRecords(t, stateB.Network.Zones["node-b.catofes."], "node-b.catofes.", "192.0.2.2", recordB, ipsec.AcceptInbound, now)
	stateA.Network.Zones["node-b.catofes."] = stateB.Network.Zones["node-b.catofes."]
	stateB.Network.Zones["node-a.catofes."] = stateA.Network.Zones["node-a.catofes."]

	pool := netip.MustParsePrefix("10.88.0.0/24")
	groupA := testIPsecLinkGroup()
	groupA.ConnectRules = nil
	groupA.NetNS = ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: nsA, Create: false}
	groupA.TunnelAddressSpec = ipsec.TunnelAddressSpec{Mode: ipsec.TunnelAddressDerivedPool, Family: ipsec.FamilyIPv4, Pool: pool}
	groupB := testIPsecLinkGroup()
	groupB.ConnectRules = nil
	groupB.NetNS = ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: nsB, Create: false}
	groupB.TunnelAddressSpec = ipsec.TunnelAddressSpec{Mode: ipsec.TunnelAddressDerivedPool, Family: ipsec.FamilyIPv4, Pool: pool}
	setTestIPsecOverlayIntent(t, stateA.Network.Zones["node-a.catofes."], "node-a.catofes.", groupA, now)
	setTestIPsecOverlayIntent(t, stateA.Network.Zones["node-b.catofes."], "node-b.catofes.", groupB, now)
	setTestIPsecOverlayIntent(t, stateB.Network.Zones["node-a.catofes."], "node-a.catofes.", groupA, now)
	setTestIPsecOverlayIntent(t, stateB.Network.Zones["node-b.catofes."], "node-b.catofes.", groupB, now)

	rtA := &Runtime{
		Config:    testDaemonIPsecAppConfig(t.TempDir(), "127.0.0.1:0", groupA),
		StatePath: filepath.Join(t.TempDir(), "node-a.db"),
		Clock:     func() time.Time { return now },
	}
	rtB := &Runtime{
		Config:    testDaemonIPsecAppConfig(t.TempDir(), "127.0.0.1:0", groupB),
		StatePath: filepath.Join(t.TempDir(), "node-b.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rtA.SaveState(stateA); err != nil {
		t.Fatalf("SaveState(node-a): %v", err)
	}
	if err := rtB.SaveState(stateB); err != nil {
		t.Fatalf("SaveState(node-b): %v", err)
	}
	serviceA := newDaemonService(rtA, stateA, configA, time.Second)
	serviceA.IPsecDriver = &ipsec.StrongSwanDriver{VICI: clientA, KeyDir: t.TempDir()}
	serviceA.XFRMDriver = daemonTestXFRMDriver(groupA.NetNS, nsA)
	serviceB := newDaemonService(rtB, stateB, configB, time.Second)
	serviceB.IPsecDriver = &ipsec.StrongSwanDriver{VICI: clientB, KeyDir: t.TempDir()}
	serviceB.XFRMDriver = daemonTestXFRMDriver(groupB.NetNS, nsB)

	serviceB.recoverIPsecLinksOnStart(ctx)
	serviceA.recoverIPsecLinksOnStart(ctx)
	latestA, err := rtA.LoadState()
	if err != nil {
		t.Fatalf("LoadState(node-a connecting): %v", err)
	}
	latestB, err := rtB.LoadState()
	if err != nil {
		t.Fatalf("LoadState(node-b connecting): %v", err)
	}
	specA := daemonSystemDesiredSpec(t, latestA, groupA, now)
	specB := daemonSystemDesiredSpec(t, latestB, groupB, now)
	if err := waitDaemonTestSA(ctx, clientA, specA.TransportID); err != nil {
		t.Fatalf("wait for daemon SA on A: %v", err)
	}
	if err := waitDaemonTestSA(ctx, clientB, specB.TransportID); err != nil {
		t.Fatalf("wait for daemon SA on B: %v", err)
	}

	serviceA.setState(latestA)
	serviceB.setState(latestB)
	serviceA.recoverIPsecLinksOnStart(ctx)
	serviceB.recoverIPsecLinksOnStart(ctx)
	latestA, err = rtA.LoadState()
	if err != nil {
		t.Fatalf("LoadState(node-a up): %v", err)
	}
	latestB, err = rtB.LoadState()
	if err != nil {
		t.Fatalf("LoadState(node-b up): %v", err)
	}
	assertDaemonSystemLinkUp(t, latestA, specA)
	assertDaemonSystemLinkUp(t, latestB, specB)

	if !pool.Contains(specA.LocalTunnelAddr) || !pool.Contains(specA.PeerTunnelAddr) {
		t.Fatalf("derived pool addresses not in %s: local=%s peer=%s", pool, specA.LocalTunnelAddr, specA.PeerTunnelAddr)
	}
	if !specA.LocalTunnelAddr.Is4() || !specA.PeerTunnelAddr.Is4() {
		t.Fatalf("expected IPv4 derived pool addresses, got local=%s peer=%s", specA.LocalTunnelAddr, specA.PeerTunnelAddr)
	}

	addTunnelRoute(t, ctx, nsA, specA)
	addTunnelRoute(t, ctx, nsB, specB)
	pingTunnelAddr(t, ctx, nsA, specA.PeerTunnelAddr, specA.InterfaceName)
	pingTunnelAddr(t, ctx, nsB, specB.PeerTunnelAddr, specB.InterfaceName)
}

func TestDaemonStrongSwanPortRotationSmoke(t *testing.T) {
	if os.Getenv("HIGGS_IPSEC_XFRM_SMOKE") != "1" {
		t.Skip("set HIGGS_IPSEC_XFRM_SMOKE=1 to run the root/system StrongSwan port rotation smoke")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	suffix := time.Now().UTC().Format("20060102150405")
	nsA := "higgs-daemon-rot-a-" + suffix
	nsB := "higgs-daemon-rot-b-" + suffix
	viciA := "/tmp/charon-" + nsA + ".vici"
	viciB := "/tmp/charon-" + nsB + ".vici"
	t.Cleanup(func() {
		_, _ = appExecCommand(context.Background(), "ip", "netns", "delete", nsA)
		_, _ = appExecCommand(context.Background(), "ip", "netns", "delete", nsB)
		_ = os.Remove(viciA)
		_ = os.Remove(viciB)
	})

	runAppCommand(t, ctx, "ip", "netns", "add", nsA)
	runAppCommand(t, ctx, "ip", "netns", "add", nsB)
	runAppCommand(t, ctx, "ip", "link", "add", "hgdrota", "type", "veth", "peer", "name", "hgdrotb")
	runAppCommand(t, ctx, "ip", "link", "set", "hgdrota", "netns", nsA)
	runAppCommand(t, ctx, "ip", "link", "set", "hgdrotb", "netns", nsB)
	for _, args := range [][]string{
		{"netns", "exec", nsA, "ip", "link", "set", "lo", "up"},
		{"netns", "exec", nsB, "ip", "link", "set", "lo", "up"},
		{"netns", "exec", nsA, "ip", "addr", "add", "192.0.2.1/30", "dev", "hgdrota"},
		{"netns", "exec", nsB, "ip", "addr", "add", "192.0.2.2/30", "dev", "hgdrotb"},
		{"netns", "exec", nsA, "ip", "link", "set", "hgdrota", "up"},
		{"netns", "exec", nsB, "ip", "link", "set", "hgdrotb", "up"},
	} {
		runAppCommand(t, ctx, "ip", args...)
	}

	confA, err := writeDaemonStrongSwanConf(viciA)
	if err != nil {
		t.Fatalf("write strongswan.conf A: %v", err)
	}
	confB, err := writeDaemonStrongSwanConf(viciB)
	if err != nil {
		t.Fatalf("write strongswan.conf B: %v", err)
	}
	piddirA := t.TempDir()
	piddirB := t.TempDir()
	logA, err := os.CreateTemp("", "higgs-daemon-charon-rot-a-*.log")
	if err != nil {
		t.Fatalf("create charon A log: %v", err)
	}
	logB, err := os.CreateTemp("", "higgs-daemon-charon-rot-b-*.log")
	if err != nil {
		t.Fatalf("create charon B log: %v", err)
	}
	charonA := startDaemonTestCharonInNetNS(ctx, t, nsA, piddirA, confA, logA)
	charonB := startDaemonTestCharonInNetNS(ctx, t, nsB, piddirB, confB, logB)
	defer func() {
		_ = charonA.Process.Kill()
		_ = charonB.Process.Kill()
		_ = charonA.Wait()
		_ = charonB.Wait()
		_ = os.Remove(confA)
		_ = os.Remove(confB)
		_ = logA.Close()
		_ = logB.Close()
		_ = os.Remove(logA.Name())
		_ = os.Remove(logB.Name())
	}()
	clientA, err := waitDaemonTestVICI(ctx, viciA)
	if err != nil {
		t.Fatalf("connect to charon A VICI: %v", err)
	}
	defer clientA.Close()
	clientB, err := waitDaemonTestVICI(ctx, viciB)
	if err != nil {
		t.Fatalf("connect to charon B VICI: %v", err)
	}
	defer clientB.Close()
	defer func() {
		if t.Failed() {
			dumpCtx, dumpCancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer dumpCancel()
			logDaemonTestFile(t, "charon A", logA.Name())
			logDaemonTestFile(t, "charon B", logB.Name())
			dumpDaemonSystemState(t, dumpCtx, nsA, nsB)
			dumpDaemonVICISAs(t, dumpCtx, viciA, "A")
			dumpDaemonVICISAs(t, dumpCtx, viciB, "B")
		}
	}()

	now := time.Unix(4140, 0)
	stateA, configA, stateB, configB := buildTestABDaemonStates(t)
	keyA, recordA := daemonTestTransportKey(t, now)
	keyB, recordB := daemonTestTransportKey(t, now)
	stateA.IPsecTransportKey = keyA
	stateB.IPsecTransportKey = keyB
	addDaemonTestIPsecRecords(t, stateA.Network.Zones["node-a.catofes."], "node-a.catofes.", "192.0.2.1", recordA, ipsec.AcceptNone, now)
	addDaemonTestIPsecRecords(t, stateB.Network.Zones["node-b.catofes."], "node-b.catofes.", "192.0.2.2", recordB, ipsec.AcceptInbound, now)
	stateA.Network.Zones["node-b.catofes."] = stateB.Network.Zones["node-b.catofes."]
	stateB.Network.Zones["node-a.catofes."] = stateA.Network.Zones["node-a.catofes."]

	groupA := testIPsecLinkGroup()
	groupA.ConnectRules = nil
	groupA.NetNS = ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: nsA, Create: false}
	groupA.TunnelAddressSpec = ipsec.TunnelAddressSpec{Mode: ipsec.TunnelAddressDerivedLinkLocal, Family: ipsec.FamilyIPv6}
	groupB := testIPsecLinkGroup()
	groupB.ConnectRules = nil
	groupB.NetNS = ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: nsB, Create: false}
	groupB.TunnelAddressSpec = ipsec.TunnelAddressSpec{Mode: ipsec.TunnelAddressDerivedLinkLocal, Family: ipsec.FamilyIPv6}
	rtA := &Runtime{
		Config:    testDaemonIPsecAppConfig(t.TempDir(), "127.0.0.1:0", groupA),
		StatePath: filepath.Join(t.TempDir(), "node-a.db"),
		Clock:     func() time.Time { return now },
	}
	rtB := &Runtime{
		Config:    testDaemonIPsecAppConfig(t.TempDir(), "127.0.0.1:0", groupB),
		StatePath: filepath.Join(t.TempDir(), "node-b.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rtA.SaveState(stateA); err != nil {
		t.Fatalf("SaveState(node-a): %v", err)
	}
	if err := rtB.SaveState(stateB); err != nil {
		t.Fatalf("SaveState(node-b): %v", err)
	}
	serviceA := newDaemonService(rtA, stateA, configA, time.Second)
	serviceA.IPsecDriver = &ipsec.StrongSwanDriver{VICI: clientA, KeyDir: t.TempDir()}
	serviceA.XFRMDriver = daemonTestXFRMDriver(groupA.NetNS, nsA)
	serviceB := newDaemonService(rtB, stateB, configB, time.Second)
	serviceB.IPsecDriver = &ipsec.StrongSwanDriver{VICI: clientB, KeyDir: t.TempDir()}
	serviceB.XFRMDriver = daemonTestXFRMDriver(groupB.NetNS, nsB)

	serviceB.recoverIPsecLinksOnStart(ctx)
	serviceA.recoverIPsecLinksOnStart(ctx)
	latestA, err := rtA.LoadState()
	if err != nil {
		t.Fatalf("LoadState(node-a connecting): %v", err)
	}
	latestB, err := rtB.LoadState()
	if err != nil {
		t.Fatalf("LoadState(node-b connecting): %v", err)
	}
	specA := daemonSystemDesiredSpec(t, latestA, groupA, now)
	specB := daemonSystemDesiredSpec(t, latestB, groupB, now)
	if err := waitDaemonTestSA(ctx, clientA, specA.TransportID); err != nil {
		t.Fatalf("wait for daemon SA on A: %v", err)
	}
	if err := waitDaemonTestSA(ctx, clientB, specB.TransportID); err != nil {
		t.Fatalf("wait for daemon SA on B: %v", err)
	}

	serviceA.setState(latestA)
	serviceB.setState(latestB)
	serviceA.recoverIPsecLinksOnStart(ctx)
	serviceB.recoverIPsecLinksOnStart(ctx)
	latestA, err = rtA.LoadState()
	if err != nil {
		t.Fatalf("LoadState(node-a up): %v", err)
	}
	latestB, err = rtB.LoadState()
	if err != nil {
		t.Fatalf("LoadState(node-b up): %v", err)
	}
	assertDaemonSystemLinkUp(t, latestA, specA)
	assertDaemonSystemLinkUp(t, latestB, specB)
	addTunnelRoute(t, ctx, nsA, specA)
	addTunnelRoute(t, ctx, nsB, specB)
	pingTunnelAddr(t, ctx, nsA, specA.PeerTunnelAddr, specA.InterfaceName)
	pingTunnelAddr(t, ctx, nsB, specB.PeerTunnelAddr, specB.InterfaceName)

	// Rotate both peers to generation 2 on IKE port 500. The initial base
	// connection uses NAT-T port 4500, so the staged connection on port 500
	// gets independent IKE_SAs on both sides.
	const rotIKEPort uint16 = ipsec.DefaultIKEPort
	rotateA := latestA
	rotateB := latestB
	updateDaemonTestPortRecord(t, rotateA.Network.Zones["node-a.catofes."], "node-a.catofes.", 2, rotIKEPort, now.Add(time.Minute))
	updateDaemonTestPortRecord(t, rotateB.Network.Zones["node-a.catofes."], "node-a.catofes.", 2, rotIKEPort, now.Add(time.Minute))
	updateDaemonTestPortRecord(t, rotateA.Network.Zones["node-b.catofes."], "node-b.catofes.", 2, rotIKEPort, now.Add(time.Minute))
	updateDaemonTestPortRecord(t, rotateB.Network.Zones["node-b.catofes."], "node-b.catofes.", 2, rotIKEPort, now.Add(time.Minute))
	if err := rtA.SaveState(rotateA); err != nil {
		t.Fatalf("SaveState(node-a rotated peer ports): %v", err)
	}
	if err := rtB.SaveState(rotateB); err != nil {
		t.Fatalf("SaveState(node-b rotated local ports): %v", err)
	}
	serviceB.setState(rotateB)
	serviceB.recoverIPsecLinksOnStart(ctx)
	serviceA.setState(rotateA)
	serviceA.recoverIPsecLinksOnStart(ctx)
	preparedA, err := rtA.LoadState()
	if err != nil {
		t.Fatalf("LoadState(node-a prepared rotate): %v", err)
	}
	preparedB, err := rtB.LoadState()
	if err != nil {
		t.Fatalf("LoadState(node-b prepared rotate): %v", err)
	}
	instA := preparedA.LinkInstances[ipsec.LinkInstanceID(specA)]
	if instA.RotatePhase != ipsec.RotatePhaseTestingNew || instA.StagedGeneration != 2 {
		t.Fatalf("prepared rotate instance A = %+v, want testing_new generation 2", instA)
	}
	instB := preparedB.LinkInstances[ipsec.LinkInstanceID(specB)]
	if instB.RotatePhase != ipsec.RotatePhaseTestingNew || instB.StagedGeneration != 2 {
		t.Fatalf("prepared rotate instance B = %+v, want testing_new generation 2", instB)
	}
	stagedIKEA := ipsec.RuntimeConnectionID(instA.LinkID, 2, instA.TransportKind)
	stagedIKEB := ipsec.RuntimeConnectionID(instB.LinkID, 2, instB.TransportKind)
	if instA.StagedIKEName != stagedIKEA {
		t.Fatalf("staged ike A = %q, want %q", instA.StagedIKEName, stagedIKEA)
	}
	if instB.StagedIKEName != stagedIKEB {
		t.Fatalf("staged ike B = %q, want %q", instB.StagedIKEName, stagedIKEB)
	}
	if err := waitDaemonTestSA(ctx, clientA, stagedIKEA); err != nil {
		t.Fatalf("wait for staged daemon SA on A: %v", err)
	}
	if err := waitDaemonTestSA(ctx, clientB, stagedIKEB); err != nil {
		t.Fatalf("wait for staged daemon SA on B: %v", err)
	}

	// Simulate that the staged SAs have been observed and the rotate retention
	// window has expired, so the next reconcile commits the rotation.
	for id, inst := range preparedA.LinkInstances {
		inst.RotatePhase = ipsec.RotatePhaseDualRunning
		inst.RotateDeadline = now.Add(-time.Second).Unix()
		preparedA.LinkInstances[id] = inst
	}
	for id, inst := range preparedB.LinkInstances {
		inst.RotatePhase = ipsec.RotatePhaseDualRunning
		inst.RotateDeadline = now.Add(-time.Second).Unix()
		preparedB.LinkInstances[id] = inst
	}
	serviceA.setState(preparedA)
	serviceA.recoverIPsecLinksOnStart(ctx)
	serviceB.setState(preparedB)
	serviceB.recoverIPsecLinksOnStart(ctx)
	committedA, err := rtA.LoadState()
	if err != nil {
		t.Fatalf("LoadState(node-a committed rotate): %v", err)
	}
	committedB, err := rtB.LoadState()
	if err != nil {
		t.Fatalf("LoadState(node-b committed rotate): %v", err)
	}
	rotatedSpecA := daemonSystemDesiredSpec(t, committedA, groupA, now.Add(time.Minute))
	rotatedSpecB := daemonSystemDesiredSpec(t, committedB, groupB, now.Add(time.Minute))
	// After commit the active XFRM interface and IKE name are the staged ones;
	// update the spec to match the committed instance before checking link state.
	committedInstA := committedA.LinkInstances[ipsec.LinkInstanceID(rotatedSpecA)]
	rotatedSpecA.InterfaceName = committedInstA.InterfaceName
	rotatedSpecA.XFRMIfID = committedInstA.XFRMIfID
	committedInstB := committedB.LinkInstances[ipsec.LinkInstanceID(rotatedSpecB)]
	rotatedSpecB.InterfaceName = committedInstB.InterfaceName
	rotatedSpecB.XFRMIfID = committedInstB.XFRMIfID
	assertDaemonSystemLinkUp(t, committedA, rotatedSpecA)
	assertDaemonSystemLinkUp(t, committedB, rotatedSpecB)
	if committedInstA.RotatePhase != ipsec.RotatePhaseIdle || committedInstA.StagedGeneration != 0 {
		t.Fatalf("committed rotate instance A = %+v, want idle with no staged generation", committedInstA)
	}
	if committedInstA.IKEName != stagedIKEA || committedInstA.RemoteGeneration != 2 {
		t.Fatalf("committed rotate instance A = %+v, want ike=%s remote_generation=2", committedInstA, stagedIKEA)
	}
	if committedInstB.RotatePhase != ipsec.RotatePhaseIdle || committedInstB.StagedGeneration != 0 {
		t.Fatalf("committed rotate instance B = %+v, want idle with no staged generation", committedInstB)
	}
	if committedInstB.IKEName != stagedIKEB || committedInstB.RemoteGeneration != 2 {
		t.Fatalf("committed rotate instance B = %+v, want ike=%s remote_generation=2", committedInstB, stagedIKEB)
	}
	if err := waitDaemonTestNoSA(ctx, clientA, specA.TransportID); err != nil {
		t.Fatalf("old daemon SA on A after rotate commit: %v", err)
	}
	if err := waitDaemonTestNoSA(ctx, clientB, specB.TransportID); err != nil {
		t.Fatalf("old daemon SA on B after rotate commit: %v", err)
	}
	if count, err := daemonTestEstablishedSACount(ctx, clientA, stagedIKEA); err != nil {
		t.Fatalf("count staged SA on A after commit: %v", err)
	} else if count != 1 {
		t.Fatalf("staged SA count on A after commit = %d, want 1", count)
	}
	if count, err := daemonTestEstablishedSACount(ctx, clientB, stagedIKEB); err != nil {
		t.Fatalf("count staged SA on B after commit: %v", err)
	} else if count != 1 {
		t.Fatalf("staged SA count on B after commit = %d, want 1", count)
	}
	addTunnelRoute(t, ctx, nsA, rotatedSpecA)
	addTunnelRoute(t, ctx, nsB, rotatedSpecB)
	pingTunnelAddr(t, ctx, nsA, rotatedSpecA.PeerTunnelAddr, rotatedSpecA.InterfaceName)
	pingTunnelAddr(t, ctx, nsB, rotatedSpecB.PeerTunnelAddr, rotatedSpecB.InterfaceName)
}

func TestDaemonRunGossipStrongSwanBringupSmoke(t *testing.T) {
	if os.Getenv("HIGGS_IPSEC_XFRM_SMOKE") != "1" {
		t.Skip("set HIGGS_IPSEC_XFRM_SMOKE=1 to run the root/system daemon gossip StrongSwan smoke")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	suffix := time.Now().UTC().Format("20060102150405")
	nsA := "higgs-daemon-run-a-" + suffix
	nsB := "higgs-daemon-run-b-" + suffix
	viciA := "/tmp/charon-" + nsA + ".vici"
	viciB := "/tmp/charon-" + nsB + ".vici"
	t.Cleanup(func() {
		_, _ = appExecCommand(context.Background(), "ip", "netns", "delete", nsA)
		_, _ = appExecCommand(context.Background(), "ip", "netns", "delete", nsB)
		_ = os.Remove(viciA)
		_ = os.Remove(viciB)
	})

	runAppCommand(t, ctx, "ip", "netns", "add", nsA)
	runAppCommand(t, ctx, "ip", "netns", "add", nsB)
	runAppCommand(t, ctx, "ip", "link", "add", "hgdruna", "type", "veth", "peer", "name", "hgdrunb")
	runAppCommand(t, ctx, "ip", "link", "set", "hgdruna", "netns", nsA)
	runAppCommand(t, ctx, "ip", "link", "set", "hgdrunb", "netns", nsB)
	for _, args := range [][]string{
		{"netns", "exec", nsA, "ip", "link", "set", "lo", "up"},
		{"netns", "exec", nsB, "ip", "link", "set", "lo", "up"},
		{"netns", "exec", nsA, "ip", "addr", "add", "192.0.2.1/30", "dev", "hgdruna"},
		{"netns", "exec", nsB, "ip", "addr", "add", "192.0.2.2/30", "dev", "hgdrunb"},
		{"netns", "exec", nsA, "ip", "link", "set", "hgdruna", "up"},
		{"netns", "exec", nsB, "ip", "link", "set", "hgdrunb", "up"},
	} {
		runAppCommand(t, ctx, "ip", args...)
	}

	confA, err := writeDaemonStrongSwanConf(viciA)
	if err != nil {
		t.Fatalf("write strongswan.conf A: %v", err)
	}
	confB, err := writeDaemonStrongSwanConf(viciB)
	if err != nil {
		t.Fatalf("write strongswan.conf B: %v", err)
	}
	piddirA := t.TempDir()
	piddirB := t.TempDir()
	logA, err := os.CreateTemp("", "higgs-daemon-run-charon-a-*.log")
	if err != nil {
		t.Fatalf("create charon A log: %v", err)
	}
	logB, err := os.CreateTemp("", "higgs-daemon-run-charon-b-*.log")
	if err != nil {
		t.Fatalf("create charon B log: %v", err)
	}
	charonA := startDaemonTestCharonInNetNS(ctx, t, nsA, piddirA, confA, logA)
	charonB := startDaemonTestCharonInNetNS(ctx, t, nsB, piddirB, confB, logB)
	defer func() {
		_ = charonA.Process.Kill()
		_ = charonB.Process.Kill()
		_ = charonA.Wait()
		_ = charonB.Wait()
		_ = os.Remove(confA)
		_ = os.Remove(confB)
		_ = logA.Close()
		_ = logB.Close()
		_ = os.Remove(logA.Name())
		_ = os.Remove(logB.Name())
	}()
	defer func() {
		if t.Failed() {
			dumpCtx, dumpCancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer dumpCancel()
			logDaemonTestFile(t, "charon A", logA.Name())
			logDaemonTestFile(t, "charon B", logB.Name())
			dumpDaemonSystemState(t, dumpCtx, nsA, nsB)
		}
	}()

	clientA, err := waitDaemonTestVICI(ctx, viciA)
	if err != nil {
		t.Fatalf("connect to charon A VICI: %v", err)
	}
	defer clientA.Close()
	clientB, err := waitDaemonTestVICI(ctx, viciB)
	if err != nil {
		t.Fatalf("connect to charon B VICI: %v", err)
	}
	defer clientB.Close()

	stateA, configA, stateB, configB := buildTestABDaemonStates(t)
	now := time.Now()
	keyA, _ := daemonTestTransportKey(t, now)
	keyB, _ := daemonTestTransportKey(t, now)
	stateA.IPsecTransportKey = keyA
	stateB.IPsecTransportKey = keyB
	gossipA := freeDaemonTestUDPAddr(t)
	gossipB := freeDaemonTestUDPAddr(t)
	configA.ListenAddr = gossipA
	configB.ListenAddr = gossipB
	configA.Bootstrap = []syncConfigPeer{{ID: configB.PeerID, Addr: gossipB}}
	configB.Bootstrap = []syncConfigPeer{{ID: configA.PeerID, Addr: gossipA}}

	groupA := testIPsecLinkGroup()
	groupA.ConnectRules = nil
	groupA.NetNS = ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: nsA, Create: false}
	groupA.TunnelAddressSpec = ipsec.TunnelAddressSpec{Mode: ipsec.TunnelAddressDerivedLinkLocal, Family: ipsec.FamilyIPv6}
	groupB := testIPsecLinkGroup()
	groupB.ConnectRules = nil
	groupB.NetNS = ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: nsB, Create: false}
	groupB.TunnelAddressSpec = ipsec.TunnelAddressSpec{Mode: ipsec.TunnelAddressDerivedLinkLocal, Family: ipsec.FamilyIPv6}
	rtA := &Runtime{
		Config:    testDaemonIPsecAppConfig(t.TempDir(), "192.0.2.1:4500", groupA),
		StatePath: filepath.Join(t.TempDir(), "node-a.db"),
		Clock:     time.Now,
	}
	rtA.Config.IPsec.Accept = ipsec.AcceptNone
	rtA.Config.ListenAddr = gossipA
	rtB := &Runtime{
		Config:    testDaemonIPsecAppConfig(t.TempDir(), "192.0.2.2:4500", groupB),
		StatePath: filepath.Join(t.TempDir(), "node-b.db"),
		Clock:     time.Now,
	}
	rtB.Config.IPsec.Accept = ipsec.AcceptInbound
	rtB.Config.ListenAddr = gossipB
	if err := rtA.SaveState(stateA); err != nil {
		t.Fatalf("SaveState(node-a): %v", err)
	}
	if err := rtB.SaveState(stateB); err != nil {
		t.Fatalf("SaveState(node-b): %v", err)
	}

	serviceA := newDaemonService(rtA, stateA, configA, 200*time.Millisecond)
	serviceA.IPsecDriver = newDaemonTestStrongSwanDriver(t, viciA, clientA)
	serviceA.XFRMDriver = daemonTestXFRMDriver(groupA.NetNS, nsA)
	serviceB := newDaemonService(rtB, stateB, configB, 200*time.Millisecond)
	serviceB.IPsecDriver = newDaemonTestStrongSwanDriver(t, viciB, clientB)
	serviceB.XFRMDriver = daemonTestXFRMDriver(groupB.NetNS, nsB)

	runCtx, stopDaemons := context.WithCancel(ctx)
	defer stopDaemons()
	errCh := make(chan error, 2)
	go func() { errCh <- serviceA.Run(runCtx) }()
	go func() { errCh <- serviceB.Run(runCtx) }()
	defer func() {
		stopDaemons()
		for i := 0; i < 2; i++ {
			if err := <-errCh; err != nil {
				t.Fatalf("daemon Run returned error: %v", err)
			}
		}
	}()

	latestA, latestB := waitDaemonRunGossipStrongSwanUp(ctx, t, rtA, rtB, groupA, groupB)
	specA := daemonSystemDesiredSpec(t, latestA, groupA, time.Now())
	specB := daemonSystemDesiredSpec(t, latestB, groupB, time.Now())
	assertGossipedIPsecRecords(t, latestA, "node-b.catofes.")
	assertGossipedIPsecRecords(t, latestB, "node-a.catofes.")
	assertDaemonSystemLinkUp(t, latestA, specA)
	assertDaemonSystemLinkUp(t, latestB, specB)

	addTunnelRoute(t, ctx, nsA, specA)
	addTunnelRoute(t, ctx, nsB, specB)
	pingTunnelAddr(t, ctx, nsA, specA.PeerTunnelAddr, specA.InterfaceName)
	pingTunnelAddr(t, ctx, nsB, specB.PeerTunnelAddr, specB.InterfaceName)
}

func TestDaemonStateChangedRemovesTeardownIPsecLinks(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(4050, 0)
	addTestIPsecRecords(t, state.Network.Zones["node-b.catofes."], "node-b.catofes.", now, ipsec.AcceptInbound)
	appConfig := defaultAppConfig()
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{{
		ID:                 "main",
		Provider:           ipsec.ProviderStrongSwan,
		NetNS:              ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: "h2", Create: true},
		DefaultPathMode:    ipsec.PathModeFamilyRedundant,
		AddressSourceOrder: []string{ipsec.SourceManualAddress},
		ConnectRules:       []string{"strongswan://*.catofes.?accept=inbound"},
	}}
	rt := &Runtime{
		Config:    appConfig,
		StatePath: filepath.Join(t.TempDir(), "higgs.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	service := newDaemonService(rt, state, config, time.Second)

	service.notifyStateChanged()
	latest, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if len(latest.LinkInstances) != 1 {
		t.Fatalf("link instances len = %d, want 1", len(latest.LinkInstances))
	}

	appConfig.IPsec.LinkGroups = nil
	service.setState(latest)
	service.notifyStateChanged()
	removed, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState(after teardown): %v", err)
	}
	if len(removed.LinkInstances) != 0 {
		t.Fatalf("link instances after teardown = %+v, want none", removed.LinkInstances)
	}
	if len(removed.IPsecReconcile.Actions) != 1 || removed.IPsecReconcile.Actions[0].Action != ipsec.ReconcileActionTeardown {
		t.Fatalf("teardown actions = %+v, want one teardown", removed.IPsecReconcile.Actions)
	}

	service.setState(removed)
	service.notifyStateChanged()
	stable, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState(stable): %v", err)
	}
	if len(stable.LinkInstances) != 0 {
		t.Fatalf("stable link instances = %+v, want none", stable.LinkInstances)
	}
	if len(stable.IPsecReconcile.Actions) != 0 {
		t.Fatalf("stable actions = %+v, want no repeated teardown", stable.IPsecReconcile.Actions)
	}
}

func TestDaemonStateChangedAdoptsObservedIPsecSA(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(4100, 0)
	addTestIPsecRecords(t, state.Network.Zones["node-b.catofes."], "node-b.catofes.", now, ipsec.AcceptInbound)
	appConfig := defaultAppConfig()
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{{
		ID:                 "main",
		Provider:           ipsec.ProviderStrongSwan,
		NetNS:              ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: "h2", Create: true},
		DefaultPathMode:    ipsec.PathModeFamilyRedundant,
		AddressSourceOrder: []string{ipsec.SourceManualAddress},
		ConnectRules:       []string{"strongswan://*.catofes.?accept=inbound"},
	}}
	plan, err := ipsec.PlanTransportLinks(context.Background(), state.Network, state.ManagedZone, appConfig.IPsec.LinkGroups, ipsec.LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks: %v", err)
	}
	if len(plan.Desired) != 1 {
		t.Fatalf("desired links = %d, want 1", len(plan.Desired))
	}
	spec := plan.Desired[0]
	driver := &observedIPsecDriver{
		sas: []ipsec.SAState{{
			Name:        spec.TransportID,
			ChildSA:     ipsec.ChildSAName(spec),
			XFRMIfID:    spec.XFRMIfID,
			Endpoint:    "198.51.100.20",
			Established: true,
		}},
	}
	rt := &Runtime{
		Config:    appConfig,
		StatePath: filepath.Join(t.TempDir(), "higgs.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	service := newDaemonService(rt, state, config, time.Second)
	service.IPsecDriver = driver
	service.XFRMDriver = driver

	service.notifyStateChanged()

	latest, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if len(latest.IPsecReconcile.Actions) != 1 || latest.IPsecReconcile.Actions[0].Action != ipsec.ReconcileActionAdopt {
		t.Fatalf("actions = %+v, want adopt", latest.IPsecReconcile.Actions)
	}
	inst := latest.LinkInstances[ipsec.LinkInstanceID(spec)]
	if inst.ActualState != ipsec.LinkStateUp || inst.Endpoint != "198.51.100.20" {
		t.Fatalf("instance = %+v, want up adopted endpoint", inst)
	}
	if latest.IPsecReconcile == nil || len(latest.IPsecReconcile.Desired) != 1 || len(latest.IPsecReconcile.ActualSAs) != 1 {
		t.Fatalf("ipsec reconcile detail = %+v, want desired and actual sa snapshots", latest.IPsecReconcile)
	}
	var out bytes.Buffer
	if err := writeDebugLinks(&out, rt, latest, ""); err != nil {
		t.Fatalf("writeDebugLinks: %v", err)
	}
	output := out.String()
	for _, want := range []string{
		"planned_desired_links: 1",
		"actual_sas: 1",
		"  planner:\n",
		"    desired_hash: ",
		"  xfrm:\n",
		"    interface: ",
		"  strongswan:\n",
		"    sa_state: established",
		"    remote_endpoint: 198.51.100.20",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("debug links output missing %q:\n%s", want, output)
		}
	}
	if len(driver.Connections) != 0 || len(driver.Interfaces) != 0 {
		t.Fatalf("adopt should not apply resources: connections=%d interfaces=%d", len(driver.Connections), len(driver.Interfaces))
	}
}

func TestDaemonStartupRecoversIPsecLinkState(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(4125, 0)
	addTestIPsecRecords(t, state.Network.Zones["node-b.catofes."], "node-b.catofes.", now, ipsec.AcceptInbound)
	appConfig := defaultAppConfig()
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{{
		ID:                 "main",
		Provider:           ipsec.ProviderStrongSwan,
		NetNS:              ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: "h2", Create: true},
		DefaultPathMode:    ipsec.PathModeFamilyRedundant,
		AddressSourceOrder: []string{ipsec.SourceManualAddress},
		ConnectRules:       []string{"strongswan://*.catofes.?accept=inbound"},
	}}
	plan, err := ipsec.PlanTransportLinks(context.Background(), state.Network, state.ManagedZone, appConfig.IPsec.LinkGroups, ipsec.LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks: %v", err)
	}
	if len(plan.Desired) != 1 {
		t.Fatalf("desired links = %d, want 1", len(plan.Desired))
	}
	spec := plan.Desired[0]
	persisted := ipsec.NewLinkInstance(spec, ipsec.LinkStateConnecting, now.Add(-time.Minute))
	state.LinkInstances = linkInstancesFromIPsec(map[string]ipsec.LinkInstance{
		persisted.ID: persisted,
	})
	driver := &observedIPsecDriver{
		sas: []ipsec.SAState{{
			Name:        spec.TransportID,
			ChildSA:     ipsec.ChildSAName(spec),
			XFRMIfID:    spec.XFRMIfID,
			Endpoint:    "198.51.100.20",
			Established: true,
		}},
	}
	rt := &Runtime{
		Config:    appConfig,
		StatePath: filepath.Join(t.TempDir(), "higgs.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	service := newDaemonService(rt, state, config, time.Second)
	service.IPsecDriver = driver
	service.XFRMDriver = driver

	service.recoverIPsecLinksOnStart(context.Background())

	if driver.listCalls != 1 {
		t.Fatalf("ListSAs calls = %d, want 1", driver.listCalls)
	}
	latest, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	inst := latest.LinkInstances[ipsec.LinkInstanceID(spec)]
	if inst.ActualState != ipsec.LinkStateUp || inst.Endpoint != "198.51.100.20" {
		t.Fatalf("startup recovered instance = %+v, want up adopted endpoint", inst)
	}
	if latest.IPsecReconcile == nil || len(latest.IPsecReconcile.Actions) != 1 || latest.IPsecReconcile.Actions[0].Action != ipsec.ReconcileActionAdopt {
		t.Fatalf("startup reconcile = %+v, want adopt", latest.IPsecReconcile)
	}
	if len(driver.Connections) != 0 || len(driver.Interfaces) != 0 {
		t.Fatalf("startup adopt should not apply resources: connections=%d interfaces=%d", len(driver.Connections), len(driver.Interfaces))
	}
}

func TestDaemonStartupRepairsEstablishedSAWhenXFRMLinkMissing(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(4126, 0)
	addTestIPsecRecords(t, state.Network.Zones["node-b.catofes."], "node-b.catofes.", now, ipsec.AcceptInbound)
	group := testIPsecLinkGroup()
	setTestIPsecOverlayIntent(t, state.Network.Zones["node-b.catofes."], "node-b.catofes.", group, now)
	appConfig := defaultAppConfig()
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{group}
	plan, err := ipsec.PlanTransportLinks(context.Background(), state.Network, state.ManagedZone, appConfig.IPsec.LinkGroups, ipsec.LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks: %v", err)
	}
	if len(plan.Desired) != 1 {
		t.Fatalf("desired links = %d, want 1", len(plan.Desired))
	}
	spec := plan.Desired[0]
	persisted := ipsec.NewLinkInstance(spec, ipsec.LinkStateUp, now.Add(-time.Minute))
	state.LinkInstances = linkInstancesFromIPsec(map[string]ipsec.LinkInstance{
		persisted.ID: persisted,
	})
	driver := &observedIPsecDriver{
		sas: []ipsec.SAState{{
			Name:        spec.TransportID,
			ChildSA:     ipsec.ChildSAName(spec),
			XFRMIfID:    spec.XFRMIfID,
			Endpoint:    "198.51.100.20",
			Established: true,
		}},
		linkState: &ipsec.XFRMLinkState{
			NetNS:           group.NetNS,
			NamespaceExists: false,
			InterfaceExists: false,
		},
	}
	rt := &Runtime{
		Config:    appConfig,
		StatePath: filepath.Join(t.TempDir(), "higgs.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	service := newDaemonService(rt, state, config, time.Second)
	service.IPsecDriver = driver
	service.XFRMDriver = driver

	service.recoverIPsecLinksOnStart(context.Background())

	latest, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if latest.IPsecReconcile == nil || len(latest.IPsecReconcile.Actions) != 1 || latest.IPsecReconcile.Actions[0].Action != ipsec.ReconcileActionRepair {
		t.Fatalf("startup reconcile = %+v, want repair", latest.IPsecReconcile)
	}
	inst := latest.LinkInstances[ipsec.LinkInstanceID(spec)]
	if inst.ActualState != ipsec.LinkStateConnecting {
		t.Fatalf("instance = %+v, want connecting after repair apply", inst)
	}
	assertDryRunApply(t, driver, spec, group.NetNS)
	if len(latest.IPsecReconcile.ActualSAs) != 0 {
		t.Fatalf("actual SAs = %+v, want missing xfrm link to suppress matching SA", latest.IPsecReconcile.ActualSAs)
	}
}

func TestDaemonStartupKeepsRotatedRuntimeSAWhenActiveXFRMLinkExists(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(4128, 0)
	addTestIPsecRecords(t, state.Network.Zones["node-b.catofes."], "node-b.catofes.", now, ipsec.AcceptInbound)
	group := testIPsecLinkGroup()
	setTestIPsecOverlayIntent(t, state.Network.Zones["node-b.catofes."], "node-b.catofes.", group, now)
	appConfig := defaultAppConfig()
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{group}
	plan, err := ipsec.PlanTransportLinks(context.Background(), state.Network, state.ManagedZone, appConfig.IPsec.LinkGroups, ipsec.LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks: %v", err)
	}
	if len(plan.Desired) != 1 {
		t.Fatalf("desired links = %d, want 1", len(plan.Desired))
	}
	baseSpec := plan.Desired[0]
	updateDaemonTestPortRecord(t, state.Network.Zones["node-b.catofes."], "node-b.catofes.", 2, ipsec.DefaultNATTPort, now.Add(time.Minute))
	rotatedPlan, err := ipsec.PlanTransportLinks(context.Background(), state.Network, state.ManagedZone, appConfig.IPsec.LinkGroups, ipsec.LinkPlannerOptions{Now: now.Add(time.Minute)})
	if err != nil {
		t.Fatalf("PlanTransportLinks(rotated): %v", err)
	}
	if len(rotatedPlan.Desired) != 1 {
		t.Fatalf("rotated desired links = %d, want 1", len(rotatedPlan.Desired))
	}
	rotatedDesired := rotatedPlan.Desired[0]
	rotatedIKE := ipsec.RuntimeConnectionID(ipsec.LinkInstanceID(rotatedDesired), 2, rotatedDesired.Provider)
	rotatedIfID := ipsec.RuntimeXFRMIfID(ipsec.LinkInstanceID(rotatedDesired), 2, rotatedDesired.Provider)
	rotatedInterface := ipsec.StableInterfaceName(rotatedIfID)
	persisted := ipsec.NewLinkInstance(rotatedDesired, ipsec.LinkStateUp, now)
	persisted.RemoteGeneration = 2
	persisted.IKEName = rotatedIKE
	persisted.ChildSAName = rotatedIKE + "-child"
	persisted.InterfaceName = rotatedInterface
	persisted.XFRMIfID = rotatedIfID
	state.LinkInstances = linkInstancesFromIPsec(map[string]ipsec.LinkInstance{
		persisted.ID: persisted,
	})
	driver := &observedIPsecDriver{
		sas: []ipsec.SAState{{
			Name:        rotatedIKE,
			ChildSA:     rotatedIKE + "-child",
			XFRMIfID:    rotatedIfID,
			Endpoint:    "203.0.113.10",
			Established: true,
		}},
		linkStates: map[string]ipsec.XFRMLinkState{
			baseSpec.InterfaceName: {
				NetNS:           group.NetNS,
				NamespaceExists: true,
				InterfaceExists: false,
			},
			rotatedInterface: {
				NetNS:           group.NetNS,
				NamespaceExists: true,
				InterfaceExists: true,
				Addresses:       []netip.Prefix{netip.PrefixFrom(rotatedDesired.LocalTunnelAddr, 128)},
			},
		},
	}
	rt := &Runtime{
		Config:    appConfig,
		StatePath: filepath.Join(t.TempDir(), "higgs.db"),
		Clock:     func() time.Time { return now.Add(time.Minute) },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	service := newDaemonService(rt, state, config, time.Second)
	service.IPsecDriver = driver
	service.XFRMDriver = driver

	service.recoverIPsecLinksOnStart(context.Background())

	latest, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if latest.IPsecReconcile == nil || len(latest.IPsecReconcile.ActualSAs) != 1 {
		t.Fatalf("startup reconcile actual SAs = %+v, want rotated SA retained", latest.IPsecReconcile)
	}
	for _, action := range latest.IPsecReconcile.Actions {
		if action.Action == ipsec.ReconcileActionRepair {
			t.Fatalf("startup reconcile action = %+v, want no repair for existing rotated xfrm link", action)
		}
	}
	inst := latest.LinkInstances[ipsec.LinkInstanceID(rotatedDesired)]
	if inst.InterfaceName != rotatedInterface || inst.XFRMIfID != rotatedIfID || inst.RemoteGeneration != 2 {
		t.Fatalf("instance = %+v, want rotated runtime interface %s/%d generation 2", inst, rotatedInterface, rotatedIfID)
	}
	if len(driver.Interfaces) != 0 {
		t.Fatalf("interfaces applied = %+v, want no repair apply", driver.Interfaces)
	}
}

func TestDaemonDryRunABIPsecSmokeCoversBringupAndSAObservation(t *testing.T) {
	now := time.Unix(4130, 0)
	stateA, configA := buildTestNetworkState(t)
	stateA.Network.Zones["node-a.catofes."] = zone.NewZoneState("node-a.catofes.", nil)
	addTestIPsecRecords(t, stateA.Network.Zones["node-a.catofes."], "node-a.catofes.", now, ipsec.AcceptBidirectional)
	addTestIPsecRecords(t, stateA.Network.Zones["node-b.catofes."], "node-b.catofes.", now, ipsec.AcceptInbound)
	group := testIPsecLinkGroup()
	group.ConnectRules = nil
	setTestIPsecOverlayIntent(t, stateA.Network.Zones["node-a.catofes."], "node-a.catofes.", group, now)
	setTestIPsecOverlayIntent(t, stateA.Network.Zones["node-b.catofes."], "node-b.catofes.", group, now)
	appConfigA := defaultAppConfig()
	appConfigA.IPsec.LinkGroups = []ipsec.LinkGroupSpec{group}
	rtA := &Runtime{
		Config:    appConfigA,
		StatePath: filepath.Join(t.TempDir(), "node-a.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rtA.SaveState(stateA); err != nil {
		t.Fatalf("SaveState(node-a): %v", err)
	}
	driverA := &observedIPsecDriver{}
	serviceA := newDaemonService(rtA, stateA, configA, time.Second)
	serviceA.IPsecDriver = driverA
	serviceA.XFRMDriver = driverA

	stateB := cloneStateFile(stateA)
	stateB.ManagedZone = "node-b.catofes."
	stateB.LinkInstances = nil
	stateB.IPsecReconcile = nil
	configB := *configA
	configB.PeerID = "node-b.catofes."
	appConfigB := defaultAppConfig()
	appConfigB.IPsec.LinkGroups = []ipsec.LinkGroupSpec{group}
	rtB := &Runtime{
		Config:    appConfigB,
		StatePath: filepath.Join(t.TempDir(), "node-b.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rtB.SaveState(stateB); err != nil {
		t.Fatalf("SaveState(node-b): %v", err)
	}
	driverB := &observedIPsecDriver{}
	serviceB := newDaemonService(rtB, stateB, &configB, time.Second)
	serviceB.IPsecDriver = driverB
	serviceB.XFRMDriver = driverB

	serviceA.notifyStateChanged()
	serviceB.notifyStateChanged()

	latestA, err := rtA.LoadState()
	if err != nil {
		t.Fatalf("LoadState(node-a): %v", err)
	}
	latestB, err := rtB.LoadState()
	if err != nil {
		t.Fatalf("LoadState(node-b): %v", err)
	}
	specA := singleDesiredSpec(t, latestA)
	specB := singleDesiredSpec(t, latestB)
	assertDryRunApply(t, driverA, specA, group.NetNS)
	assertDryRunApply(t, driverB, specB, group.NetNS)
	assertStrongSwanLoadConnMatchesSpec(t, specA)
	if specA.PeerZone != "node-b.catofes." || specB.PeerZone != "node-a.catofes." {
		t.Fatalf("A/B peer zones = %s/%s", specA.PeerZone, specB.PeerZone)
	}
	if specA.LinkID == "" || specA.LinkID != specB.LinkID {
		t.Fatalf("A/B links should share stable link identity: A=%+v B=%+v", specA, specB)
	}
	if specA.TransportID != specB.TransportID || specA.XFRMIfID != specB.XFRMIfID {
		t.Fatalf("A/B runtime ids should be mirrored per host namespace: A=%+v B=%+v", specA, specB)
	}

	driverA.sas = []ipsec.SAState{observedSAForSpec(specA, "10.44.0.1:500", "203.0.113.10:500", 1001)}
	driverB.sas = []ipsec.SAState{observedSAForSpec(specB, "10.44.0.2:500", "203.0.113.20:500", 1002)}
	serviceA.setState(latestA)
	serviceB.setState(latestB)
	serviceA.notifyStateChanged()
	serviceB.notifyStateChanged()

	latestA, err = rtA.LoadState()
	if err != nil {
		t.Fatalf("LoadState(node-a up): %v", err)
	}
	latestB, err = rtB.LoadState()
	if err != nil {
		t.Fatalf("LoadState(node-b up): %v", err)
	}
	assertSingleLinkUpFromSA(t, latestA, specA, driverA.sas[0])
	assertSingleLinkUpFromSA(t, latestB, specB, driverB.sas[0])
	var out bytes.Buffer
	if err := writeDebugLinks(&out, rtA, latestA, ""); err != nil {
		t.Fatalf("writeDebugLinks(node-a): %v", err)
	}
	output := out.String()
	for _, want := range []string{
		"  state: up",
		"    sa_state: established",
		"    local_identity: node-a.catofes.",
		"    remote_identity: node-b.catofes.",
		"    reqid: 1001",
		"    config:\n",
		"      connection: ",
		"      local_id: node-a.catofes.",
		"      remote_id: node-b.catofes.",
		"      peer_public_key: ",
		"      child_start_action: trap",
		"      child_if_id_out: ",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("debug links output missing %q:\n%s", want, output)
		}
	}
}

func TestDaemonABPublishesGossipsAndReconcilesIPsecRecords(t *testing.T) {
	stateA, configA, stateB, configB := buildTestABDaemonStates(t)
	group := testIPsecLinkGroup()

	transportA, err := gossip.Listen(gossip.Config{
		PeerID:     configA.PeerID,
		ListenAddr: configA.ListenAddr,
	})
	if err != nil {
		skipRestrictedSocket(t, err)
		t.Fatalf("Listen(A): %v", err)
	}
	defer transportA.Close()
	transportB, err := gossip.Listen(gossip.Config{
		PeerID:     configB.PeerID,
		ListenAddr: configB.ListenAddr,
	})
	if err != nil {
		skipRestrictedSocket(t, err)
		t.Fatalf("Listen(B): %v", err)
	}
	defer transportB.Close()
	transportA.AddPeer(configB.PeerID, transportB.LocalAddr())
	transportB.AddPeer(configA.PeerID, transportA.LocalAddr())
	configA.ListenAddr = transportA.LocalAddr().String()
	configB.ListenAddr = transportB.LocalAddr().String()
	configA.Bootstrap = []syncConfigPeer{{ID: configB.PeerID, Addr: transportB.LocalAddr().String()}}
	configB.Bootstrap = []syncConfigPeer{{ID: configA.PeerID, Addr: transportA.LocalAddr().String()}}

	rtA := &Runtime{
		Config:    testDaemonIPsecAppConfig(filepath.Join(t.TempDir(), "a"), "198.51.100.10:4500", group),
		StatePath: filepath.Join(t.TempDir(), "node-a.db"),
		Clock:     time.Now,
	}
	rtA.Config.IPsec.Accept = ipsec.AcceptInbound
	rtB := &Runtime{
		Config:    testDaemonIPsecAppConfig(filepath.Join(t.TempDir(), "b"), "198.51.100.20:4500", group),
		StatePath: filepath.Join(t.TempDir(), "node-b.db"),
		Clock:     time.Now,
	}
	rtB.Config.IPsec.Accept = ipsec.AcceptInbound
	if err := rtA.SaveState(stateA); err != nil {
		t.Fatalf("SaveState(node-a): %v", err)
	}
	if err := rtB.SaveState(stateB); err != nil {
		t.Fatalf("SaveState(node-b): %v", err)
	}

	driverA := &observedIPsecDriver{}
	driverB := &observedIPsecDriver{}
	serviceA := newDaemonService(rtA, stateA, configA, time.Second)
	serviceB := newDaemonService(rtB, stateB, configB, time.Second)
	serviceA.Sync.Transport = transportA
	serviceB.Sync.Transport = transportB
	// This test exercises the synchronous syncRound path; disable the event-loop
	// path so handleSyncTimerEvent drives the round directly.
	serviceA.eventLoopSync = false
	serviceB.eventLoopSync = false
	serviceA.IPsecDriver = driverA
	serviceA.XFRMDriver = driverA
	serviceB.IPsecDriver = driverB
	serviceB.XFRMDriver = driverB

	tcpAddrA := objectPullTCPAddr(transportA.LocalAddr().String())
	listenerA, err := objectPullTCPServe(tcpAddrA, objectPullLookup(func() *stateFile { return serviceA.Sync.State }))
	if err != nil {
		t.Fatalf("objectPullTCPServe(A): %v", err)
	}
	if listenerA != nil {
		defer listenerA.Close()
	}
	tcpAddrB := objectPullTCPAddr(transportB.LocalAddr().String())
	listenerB, err := objectPullTCPServe(tcpAddrB, objectPullLookup(func() *stateFile { return serviceB.Sync.State }))
	if err != nil {
		t.Fatalf("objectPullTCPServe(B): %v", err)
	}
	if listenerB != nil {
		defer listenerB.Close()
	}

	if err := serviceA.handleEndpointTimerEvent(); err != nil {
		t.Fatalf("publish node-a ipsec records: %v", err)
	}
	if err := serviceB.handleEndpointTimerEvent(); err != nil {
		t.Fatalf("publish node-b ipsec records: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// Run the legacy synchronous rounds one direction at a time. A concurrent
	// bidirectional syncRound can deadlock object pull: each side holds its own
	// state write lock while waiting for the peer's TCP object-pull handler,
	// which needs that peer's read lock to serve the snapshot.
	serveA, stopA := serveDaemonPackets(ctx, serviceA, transportA)
	err = serviceB.handleSyncTimerEvent(ctx, true)
	stopA()
	<-serveA
	if err != nil {
		t.Fatalf("sync node-b from node-a: %v", err)
	}

	serveB, stopB := serveDaemonPackets(ctx, serviceB, transportB)
	err = serviceA.handleSyncTimerEvent(ctx, true)
	stopB()
	<-serveB
	if err != nil {
		t.Fatalf("sync node-a from node-b: %v", err)
	}

	if err := serviceA.reconcileIPsecLinks(ctx); err != nil {
		t.Fatalf("reconcile node-a ipsec links: %v", err)
	}
	if err := serviceB.reconcileIPsecLinks(ctx); err != nil {
		t.Fatalf("reconcile node-b ipsec links: %v", err)
	}

	latestA, err := rtA.LoadState()
	if err != nil {
		t.Fatalf("LoadState(node-a): %v", err)
	}
	latestB, err := rtB.LoadState()
	if err != nil {
		t.Fatalf("LoadState(node-b): %v", err)
	}
	assertGossipedIPsecRecords(t, latestA, "node-b.catofes.")
	assertGossipedIPsecRecords(t, latestB, "node-a.catofes.")
	specA := singleDesiredSpec(t, latestA)
	specB := singleDesiredSpec(t, latestB)
	if specA.PeerZone != "node-b.catofes." || specB.PeerZone != "node-a.catofes." {
		t.Fatalf("planned peer zones = %s/%s, want node-b/node-a", specA.PeerZone, specB.PeerZone)
	}
	assertDryRunApply(t, driverA, specA, group.NetNS)
	assertDryRunApply(t, driverB, specB, group.NetNS)
	if latestA.IPsecReconcile == nil || latestA.IPsecReconcile.DesiredLinks != 1 || len(latestA.IPsecReconcile.Actions) == 0 {
		t.Fatalf("node-a reconcile = %+v, want desired link and action", latestA.IPsecReconcile)
	}
	if latestB.IPsecReconcile == nil || latestB.IPsecReconcile.DesiredLinks != 1 || len(latestB.IPsecReconcile.Actions) == 0 {
		t.Fatalf("node-b reconcile = %+v, want desired link and action", latestB.IPsecReconcile)
	}
}

func TestDaemonStartupRepairsMissingObservedSA(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(4135, 0)
	addTestIPsecRecords(t, state.Network.Zones["node-b.catofes."], "node-b.catofes.", now, ipsec.AcceptInbound)
	group := testIPsecLinkGroup()
	setTestIPsecOverlayIntent(t, state.Network.Zones["node-b.catofes."], "node-b.catofes.", group, now)
	appConfig := defaultAppConfig()
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{group}
	plan, err := ipsec.PlanTransportLinks(context.Background(), state.Network, state.ManagedZone, appConfig.IPsec.LinkGroups, ipsec.LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks: %v", err)
	}
	if len(plan.Desired) != 1 {
		t.Fatalf("desired links = %d, want 1", len(plan.Desired))
	}
	spec := plan.Desired[0]
	persisted := ipsec.NewLinkInstance(spec, ipsec.LinkStateUp, now.Add(-time.Minute))
	state.LinkInstances = linkInstancesFromIPsec(map[string]ipsec.LinkInstance{
		persisted.ID: persisted,
	})
	rt := &Runtime{
		Config:    appConfig,
		StatePath: filepath.Join(t.TempDir(), "higgs.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	driver := &observedIPsecDriver{}
	service := newDaemonService(rt, state, config, time.Second)
	service.IPsecDriver = driver
	service.XFRMDriver = driver

	service.recoverIPsecLinksOnStart(context.Background())

	if driver.listCalls != 1 {
		t.Fatalf("ListSAs calls = %d, want 1", driver.listCalls)
	}
	assertDryRunApply(t, driver, spec, group.NetNS)
	latest, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	inst := latest.LinkInstances[ipsec.LinkInstanceID(spec)]
	if inst.ActualState != ipsec.LinkStateConnecting {
		t.Fatalf("startup repaired instance = %+v, want connecting", inst)
	}
	if latest.IPsecReconcile == nil || len(latest.IPsecReconcile.Actions) != 1 || latest.IPsecReconcile.Actions[0].Action != ipsec.ReconcileActionRepair {
		t.Fatalf("startup reconcile = %+v, want repair", latest.IPsecReconcile)
	}
}

func TestDaemonStartupRetriesConnectingWithoutObservedSA(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(4137, 0)
	addTestIPsecRecords(t, state.Network.Zones["node-b.catofes."], "node-b.catofes.", now, ipsec.AcceptInbound)
	group := testIPsecLinkGroup()
	group.Reconcile.Backoff = ipsec.BackoffPolicy{InitialSeconds: 1, MaxSeconds: 1}
	setTestIPsecOverlayIntent(t, state.Network.Zones["node-b.catofes."], "node-b.catofes.", group, now)
	appConfig := defaultAppConfig()
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{group}
	plan, err := ipsec.PlanTransportLinks(context.Background(), state.Network, state.ManagedZone, appConfig.IPsec.LinkGroups, ipsec.LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks: %v", err)
	}
	if len(plan.Desired) != 1 {
		t.Fatalf("desired links = %d, want 1", len(plan.Desired))
	}
	spec := plan.Desired[0]
	persisted := ipsec.NewLinkInstance(spec, ipsec.LinkStateConnecting, now.Add(-time.Minute))
	persisted = ipsec.MarkLinkApplyFailure(persisted, group.Reconcile.Backoff, now.Add(-2*time.Second), errors.New("waiting for established SA"))
	state.LinkInstances = linkInstancesFromIPsec(map[string]ipsec.LinkInstance{
		persisted.ID: persisted,
	})
	rt := &Runtime{
		Config:    appConfig,
		StatePath: filepath.Join(t.TempDir(), "higgs.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	driver := &observedIPsecDriver{}
	service := newDaemonService(rt, state, config, time.Second)
	service.IPsecDriver = driver
	service.XFRMDriver = driver

	service.recoverIPsecLinksOnStart(context.Background())

	if driver.listCalls != 1 {
		t.Fatalf("ListSAs calls = %d, want 1", driver.listCalls)
	}
	assertDryRunApply(t, driver, spec, group.NetNS)
	latest, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	inst := latest.LinkInstances[ipsec.LinkInstanceID(spec)]
	if inst.ActualState != ipsec.LinkStateConnecting || inst.FailureCount != 0 || inst.BackoffUntil != 0 {
		t.Fatalf("startup retried instance = %+v, want connecting with cleared backoff", inst)
	}
	if latest.IPsecReconcile == nil || len(latest.IPsecReconcile.Actions) != 1 || latest.IPsecReconcile.Actions[0].Action != ipsec.ReconcileActionRepair {
		t.Fatalf("startup reconcile = %+v, want repair", latest.IPsecReconcile)
	}
}

func TestDaemonRevocationTearsDownIPsecLinkAndBlocksRecreate(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(4140, 0)
	addTestIPsecRecords(t, state.Network.Zones["node-b.catofes."], "node-b.catofes.", now, ipsec.AcceptInbound)
	group := testIPsecLinkGroup()
	setTestIPsecOverlayIntent(t, state.Network.Zones["node-b.catofes."], "node-b.catofes.", group, now)
	appConfig := defaultAppConfig()
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{group}
	rt := &Runtime{
		Config:    appConfig,
		StatePath: filepath.Join(t.TempDir(), "higgs.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	driver := &observedIPsecDriver{}
	service := newDaemonService(rt, state, config, time.Second)
	service.IPsecDriver = driver
	service.XFRMDriver = driver

	service.notifyStateChanged()
	latest, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState(create): %v", err)
	}
	spec := singleDesiredSpec(t, latest)
	if len(latest.LinkInstances) != 1 {
		t.Fatalf("link instances after create = %+v, want one", latest.LinkInstances)
	}

	parent := latest.Network.Zones["catofes."]
	delegation := parent.Delegations["node-b.catofes."]
	parent.Revocations["node-b.catofes."] = &zone.DelegationRevocation{
		ChildZone:             "node-b.catofes.",
		ParentZone:            "catofes.",
		RevokedAuthorityEpoch: delegation.AuthorityEpoch,
		RevokedAuthorityHash:  delegation.AuthorityHash,
		Reason:                "ipsec smoke revoke",
		RevokedAt:             now.Add(-time.Second).Unix(),
	}
	if err := rt.SaveState(latest); err != nil {
		t.Fatalf("SaveState(revoked): %v", err)
	}
	service.setState(latest)
	service.notifyStateChanged()

	revoked, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState(revoked): %v", err)
	}
	if len(revoked.LinkInstances) != 0 {
		t.Fatalf("link instances after revoke = %+v, want none", revoked.LinkInstances)
	}
	if revoked.IPsecReconcile == nil || len(revoked.IPsecReconcile.Actions) != 1 || revoked.IPsecReconcile.Actions[0].Action != ipsec.ReconcileActionTeardown {
		t.Fatalf("revoke reconcile = %+v, want teardown", revoked.IPsecReconcile)
	}
	if len(driver.Terminated) != 1 || driver.Terminated[0] != spec.TransportID || len(driver.Unloaded) != 1 || driver.Unloaded[0] != spec.TransportID || len(driver.DeletedIFs) != 1 || driver.DeletedIFs[0] != spec.InterfaceName {
		t.Fatalf("teardown driver state terminated=%+v unloaded=%+v deleted=%+v", driver.Terminated, driver.Unloaded, driver.DeletedIFs)
	}
	if !hasDebugSkip(revoked.IPsecReconcile.Skipped, "node-b.catofes.", ipsec.SkipRevokedZone) {
		t.Fatalf("skips = %+v, want revoked zone", revoked.IPsecReconcile.Skipped)
	}

	service.setState(revoked)
	service.notifyStateChanged()
	stable, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState(stable): %v", err)
	}
	if len(stable.LinkInstances) != 0 || len(stable.IPsecReconcile.Actions) != 0 || stable.IPsecReconcile.DesiredLinks != 0 {
		t.Fatalf("stable revoked reconcile = %+v instances=%+v, want no recreate", stable.IPsecReconcile, stable.LinkInstances)
	}
}

func TestDaemonProcessEventsCoalescesIPsecReconcile(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(4150, 0)
	addTestIPsecRecords(t, state.Network.Zones["node-b.catofes."], "node-b.catofes.", now, ipsec.AcceptInbound)
	appConfig := defaultAppConfig()
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{{
		ID:                 "main",
		Provider:           ipsec.ProviderStrongSwan,
		NetNS:              ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: "h2", Create: true},
		DefaultPathMode:    ipsec.PathModeFamilyRedundant,
		AddressSourceOrder: []string{ipsec.SourceManualAddress},
		ConnectRules:       []string{"strongswan://*.catofes.?accept=inbound"},
	}}
	rt := &Runtime{
		Config:    appConfig,
		StatePath: filepath.Join(t.TempDir(), "higgs.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	driver := &countingIPsecDriver{}
	service := newDaemonService(rt, state, config, time.Second)
	service.IPsecDriver = driver
	service.XFRMDriver = driver

	service.Events <- daemonEvent{
		Type: daemonEventRecordPut,
		RecordPut: &daemonRecordPut{
			Zone:  "node-b.catofes.",
			Key:   "coalesce-a",
			Value: []byte("a"),
			Type:  "policy.string",
		},
	}
	service.Events <- daemonEvent{
		Type: daemonEventRecordPut,
		RecordPut: &daemonRecordPut{
			Zone:  "node-b.catofes.",
			Key:   "coalesce-b",
			Value: []byte("b"),
			Type:  "policy.string",
		},
	}

	syncNow, shutdown, ipsecFlushed, _, _ := service.processEvents(context.Background())
	if !syncNow || shutdown {
		t.Fatalf("syncNow/shutdown = %v/%v, want true/false", syncNow, shutdown)
	}
	if !ipsecFlushed {
		t.Fatalf("ipsecFlushed = false, want true")
	}
	if driver.listCalls != 1 {
		t.Fatalf("ListSAs calls = %d, want 1", driver.listCalls)
	}
	if len(driver.Connections) != 1 {
		t.Fatalf("connections = %d, want one coalesced apply", len(driver.Connections))
	}
	latest, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if latest.Network.Zones["node-b.catofes."].Records["coalesce-a"] == nil || latest.Network.Zones["node-b.catofes."].Records["coalesce-b"] == nil {
		t.Fatalf("queued record puts were not both persisted")
	}
	if latest.IPsecReconcile == nil || len(latest.IPsecReconcile.Actions) != 1 || latest.IPsecReconcile.Actions[0].Action != ipsec.ReconcileActionCreate {
		t.Fatalf("ipsec reconcile = %+v, want one create", latest.IPsecReconcile)
	}
}

func TestDaemonVICILifecycleEventsOnlyTriggerCoalescedIPsecReconcile(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(4160, 0)
	addTestIPsecRecords(t, state.Network.Zones["node-b.catofes."], "node-b.catofes.", now, ipsec.AcceptInbound)
	appConfig := defaultAppConfig()
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{{
		ID:                 "main",
		Provider:           ipsec.ProviderStrongSwan,
		NetNS:              ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: "h2", Create: true},
		DefaultPathMode:    ipsec.PathModeFamilyRedundant,
		AddressSourceOrder: []string{ipsec.SourceManualAddress},
		ConnectRules:       []string{"strongswan://*.catofes.?accept=inbound"},
	}}
	rt := &Runtime{
		Config:    appConfig,
		StatePath: filepath.Join(t.TempDir(), "higgs.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	driver := &countingIPsecDriver{}
	service := newDaemonService(rt, state, config, time.Second)
	service.IPsecDriver = driver
	service.XFRMDriver = driver

	service.Events <- daemonEvent{Type: daemonEventIPsecLifecycle, VICIEvent: ipsec.VICIEvent{Name: "child-updown", Connection: "ipsec-main-ab", ChildSA: "ipsec-main-ab-child", Up: true, XFRMIfID: 77}}
	service.Events <- daemonEvent{Type: daemonEventIPsecLifecycle, VICIEvent: ipsec.VICIEvent{Name: "child-updown", Connection: "ipsec-main-ab", ChildSA: "ipsec-main-ab-child", Up: false, XFRMIfID: 77}}

	syncNow, shutdown, ipsecFlushed, _, _ := service.processEvents(context.Background())
	if syncNow || shutdown {
		t.Fatalf("syncNow/shutdown = %v/%v, want false/false", syncNow, shutdown)
	}
	if !ipsecFlushed {
		t.Fatalf("ipsecFlushed = false, want true")
	}
	if driver.listCalls != 1 {
		t.Fatalf("ListSAs calls = %d, want one coalesced reconcile", driver.listCalls)
	}
	if len(driver.Connections) != 1 {
		t.Fatalf("connections = %d, want one apply through reconcile", len(driver.Connections))
	}
	if len(driver.Interfaces) != 1 {
		t.Fatalf("interfaces = %d, want one apply through xfrm reconcile", len(driver.Interfaces))
	}
}

func TestDaemonIPsecReconcileInterval(t *testing.T) {
	state, config := buildTestNetworkState(t)
	appConfig := defaultAppConfig()
	service := newDaemonService(&Runtime{Config: appConfig}, state, config, time.Second)
	if interval := service.ipsecReconcileInterval(); interval != 0 {
		t.Fatalf("interval without link groups = %s, want 0", interval)
	}

	state.LinkInstances = map[string]linkInstanceState{"stale": {ID: "stale"}}
	if interval := service.ipsecReconcileInterval(); interval != defaultIPsecReconcileInterval {
		t.Fatalf("interval with stale instances = %s, want %s", interval, defaultIPsecReconcileInterval)
	}
	state.LinkInstances = nil

	defaultGroup := testIPsecLinkGroup()
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{defaultGroup}
	if interval := service.ipsecReconcileInterval(); interval != defaultIPsecReconcileInterval {
		t.Fatalf("default interval = %s, want %s", interval, defaultIPsecReconcileInterval)
	}

	fastGroup := testIPsecLinkGroup()
	fastGroup.ID = "fast"
	fastGroup.Reconcile.IntervalSeconds = 5
	slowGroup := testIPsecLinkGroup()
	slowGroup.ID = "slow"
	slowGroup.Reconcile.IntervalSeconds = 60
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{slowGroup, fastGroup}
	if interval := service.ipsecReconcileInterval(); interval != 5*time.Second {
		t.Fatalf("minimum interval = %s, want 5s", interval)
	}
}

func TestNextIPsecReconcileTime(t *testing.T) {
	now := time.Unix(4200, 0)
	if next := nextIPsecReconcileTime(now, 0); !next.IsZero() {
		t.Fatalf("next disabled = %s, want zero", next)
	}
	if next := nextIPsecReconcileTime(now, 30*time.Second); !next.Equal(now.Add(30 * time.Second)) {
		t.Fatalf("next = %s, want %s", next, now.Add(30*time.Second))
	}
}

func TestDaemonReloadConfigReconcilesIPsecLinkGroups(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(4200, 0)
	addTestIPsecRecords(t, state.Network.Zones["node-b.catofes."], "node-b.catofes.", now, ipsec.AcceptInbound)
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "data")
	statePath := filepath.Join(dataDir, "higgs.db")
	configPath := filepath.Join(dir, "config.yaml")
	t.Setenv("HIGGS_CONFIG", configPath)
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatalf("MkdirAll(dataDir): %v", err)
	}
	if err := os.WriteFile(configPath, []byte("data_dir: "+dataDir+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(initial config): %v", err)
	}
	appConfig := defaultAppConfig()
	appConfig.DataDir = dataDir
	appConfig.StatePath = statePath
	rt := &Runtime{
		Config:    appConfig,
		StatePath: statePath,
		Clock:     func() time.Time { return now },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	service := newDaemonService(rt, state, config, time.Second)

	result, syncNow, shutdown := service.handleEvent(daemonEvent{Type: daemonEventReloadConfig})
	if result.Error != nil {
		t.Fatalf("handleEvent(reload initial): %v", result.Error)
	}
	if !syncNow || shutdown {
		t.Fatalf("initial reload syncNow/shutdown = %v/%v, want true/false", syncNow, shutdown)
	}
	latest, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState(initial): %v", err)
	}
	if len(latest.LinkInstances) != 0 {
		t.Fatalf("initial link instances = %+v, want none", latest.LinkInstances)
	}

	reloadedConfig := strings.Join([]string{
		"data_dir: " + dataDir,
		"ipsec:",
		"  driver: dry-run",
		"overlays:",
		"  - id: main",
		"    provider: strongswan",
		"    netns:",
		"      name: h2",
		"      create: true",
		"    default_path_mode: family-redundant",
		"    address_source_order: [manual-address]",
		"    connect:",
		"      - strongswan://*.catofes.?accept=inbound",
		"",
	}, "\n")
	if err := os.WriteFile(configPath, []byte(reloadedConfig), 0o600); err != nil {
		t.Fatalf("WriteFile(reloaded config): %v", err)
	}

	result, syncNow, shutdown = service.handleEvent(daemonEvent{Type: daemonEventReloadConfig})
	if result.Error != nil {
		t.Fatalf("handleEvent(reload overlay): %v", result.Error)
	}
	if !syncNow || shutdown {
		t.Fatalf("overlay reload syncNow/shutdown = %v/%v, want true/false", syncNow, shutdown)
	}
	latest, err = rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState(reloaded): %v", err)
	}
	if len(latest.LinkInstances) != 1 {
		t.Fatalf("link instances after reload = %d, want 1", len(latest.LinkInstances))
	}
	if latest.IPsecReconcile == nil || len(latest.IPsecReconcile.Actions) != 1 || latest.IPsecReconcile.Actions[0].Action != ipsec.ReconcileActionCreate {
		t.Fatalf("ipsec reconcile after reload = %+v, want create", latest.IPsecReconcile)
	}
	if len(service.Sync.App.Config.IPsec.LinkGroups) != 1 || service.Sync.Config.PeerID != config.PeerID {
		t.Fatalf("daemon config was not refreshed: app=%+v sync=%+v", service.Sync.App.Config.IPsec.LinkGroups, service.Sync.Config)
	}
}

func TestDaemonReloadConfigRejectsStatePathSwitch(t *testing.T) {
	state, config := buildTestNetworkState(t)
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	dataDir := filepath.Join(dir, "data")
	otherDir := filepath.Join(dir, "other")
	t.Setenv("HIGGS_CONFIG", configPath)
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatalf("MkdirAll(dataDir): %v", err)
	}
	if err := os.WriteFile(configPath, []byte("data_dir: "+otherDir+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(config): %v", err)
	}
	rt := &Runtime{
		Config:    defaultAppConfig(),
		StatePath: filepath.Join(dataDir, "higgs.db"),
		Clock:     func() time.Time { return time.Unix(4300, 0) },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	service := newDaemonService(rt, state, config, time.Second)

	result, syncNow, shutdown := service.handleEvent(daemonEvent{Type: daemonEventReloadConfig})
	if result.Error == nil || !strings.Contains(result.Error.Error(), "restart daemon to switch state") {
		t.Fatalf("reload error = %v, want state path switch rejection", result.Error)
	}
	if syncNow || shutdown {
		t.Fatalf("syncNow/shutdown = %v/%v, want false/false", syncNow, shutdown)
	}
}

func TestRootCommandIncludesDaemon(t *testing.T) {
	for _, command := range rootCommand().Commands {
		if command.Name == "daemon" {
			return
		}
	}
	t.Fatal("root command does not include daemon")
}

type observedIPsecDriver struct {
	ipsec.DryRunDriver
	sas        []ipsec.SAState
	linkState  *ipsec.XFRMLinkState
	linkStates map[string]ipsec.XFRMLinkState
	listCalls  int
}

func (d *observedIPsecDriver) ListSAs(context.Context) ([]ipsec.SAState, error) {
	d.listCalls++
	return d.sas, nil
}

func (d *observedIPsecDriver) InspectLink(_ context.Context, spec ipsec.TransportLinkSpec) (ipsec.XFRMLinkState, error) {
	if d.linkStates != nil {
		if state, ok := d.linkStates[spec.InterfaceName]; ok {
			return state, nil
		}
		return ipsec.XFRMLinkState{
			NetNS:           ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: spec.NetNS}.Normalized(),
			NamespaceExists: true,
			InterfaceExists: false,
		}, nil
	}
	if d.linkState != nil {
		return *d.linkState, nil
	}
	state := ipsec.XFRMLinkState{
		NetNS:           ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: spec.NetNS}.Normalized(),
		NamespaceExists: true,
		InterfaceExists: true,
	}
	if spec.LocalTunnelAddr.IsValid() {
		state.Addresses = []netip.Prefix{netip.PrefixFrom(spec.LocalTunnelAddr, 128)}
	}
	return state, nil
}

func (d *observedIPsecDriver) FilterSAsWithMissingLinks(ctx context.Context, desired []ipsec.TransportLinkSpec, sas []ipsec.SAState) ([]ipsec.SAState, map[string]ipsec.TransportLinkSpec, error) {
	missing := make(map[string]ipsec.TransportLinkSpec)
	for _, spec := range desired {
		state, err := d.InspectLink(ctx, spec)
		if err != nil {
			return nil, nil, err
		}
		if xfrmLinkStateMatchesCandidate(state, spec) {
			continue
		}
		missing[ipsec.LinkInstanceID(spec)] = spec
	}
	if len(missing) == 0 {
		return sas, missing, nil
	}
	filtered := sas[:0]
	for _, sa := range sas {
		drop := false
		for _, spec := range missing {
			if sa.Name == spec.TransportID || sa.ChildSA == ipsec.ChildSAName(spec) || sa.XFRMIfID == spec.XFRMIfID {
				drop = true
				break
			}
		}
		if !drop {
			filtered = append(filtered, sa)
		}
	}
	return filtered, missing, nil
}

type countingIPsecDriver struct {
	ipsec.DryRunDriver
	listCalls int
}

func (d *countingIPsecDriver) ListSAs(context.Context) ([]ipsec.SAState, error) {
	d.listCalls++
	return d.DryRunDriver.ListSAs(context.Background())
}

func testIPsecLinkGroup() ipsec.LinkGroupSpec {
	return ipsec.LinkGroupSpec{
		ID:                 "main",
		Provider:           ipsec.ProviderStrongSwan,
		NetNS:              ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: "h2", Create: true},
		DefaultPathMode:    ipsec.PathModeFamilyRedundant,
		AddressSourceOrder: []string{ipsec.SourceManualAddress},
		TunnelAddressSpec: ipsec.TunnelAddressSpec{
			Mode:   ipsec.TunnelAddressSequentialPool,
			Family: ipsec.FamilyIPv4,
			Pool:   netip.MustParsePrefix("10.44.0.0/29"),
		},
		ConnectRules: []string{"strongswan://node-*.catofes.?accept=inbound"},
	}
}

func singleDesiredSpec(t *testing.T, state *stateFile) ipsec.TransportLinkSpec {
	t.Helper()
	if state == nil || state.IPsecReconcile == nil || len(state.IPsecReconcile.Desired) != 1 {
		t.Fatalf("desired snapshot = %+v, want one desired link", state.IPsecReconcile)
	}
	desired := state.IPsecReconcile.Desired[0]
	localTunnel := netip.MustParseAddr("10.44.0.1")
	peerTunnel := netip.MustParseAddr("10.44.0.2")
	if desired.PeerZone < state.ManagedZone {
		localTunnel, peerTunnel = peerTunnel, localTunnel
	}
	return ipsec.TransportLinkSpec{
		LocalZone:       state.ManagedZone,
		PeerZone:        desired.PeerZone,
		OverlayID:       desired.GroupID,
		Provider:        ipsec.ProviderStrongSwan,
		LinkID:          desired.LinkID,
		PathKey:         desired.PathKey,
		TransportID:     desired.TransportID,
		InterfaceName:   desired.InterfaceName,
		XFRMIfID:        desired.XFRMIfID,
		LocalTunnelAddr: localTunnel,
		PeerTunnelAddr:  peerTunnel,
		NetNS:           "h2",
		ContactPoints: []ipsec.ContactPoint{{
			Address:  desired.Endpoint,
			IKEPort:  ipsec.DefaultIKEPort,
			NATTPort: ipsec.DefaultNATTPort,
		}},
	}
}

func assertDryRunApply(t *testing.T, driver *observedIPsecDriver, spec ipsec.TransportLinkSpec, netns ipsec.NetNSSpec) {
	t.Helper()
	if len(driver.Namespaces) != 1 || driver.Namespaces[0] != netns.Normalized() {
		t.Fatalf("namespaces = %+v, want %s", driver.Namespaces, netns.Target())
	}
	if len(driver.Connections) != 1 || driver.Connections[0].TransportID != spec.TransportID {
		t.Fatalf("connections = %+v, want one %s", driver.Connections, spec.TransportID)
	}
	if len(driver.Interfaces) != 1 || driver.Interfaces[0].InterfaceName != spec.InterfaceName || driver.Interfaces[0].XFRMIfID != spec.XFRMIfID {
		t.Fatalf("interfaces = %+v, want %s/%d", driver.Interfaces, spec.InterfaceName, spec.XFRMIfID)
	}
	wantAddr := spec.InterfaceName + "=" + netip.PrefixFrom(spec.LocalTunnelAddr, 32).String()
	if len(driver.Addresses) != 1 || driver.Addresses[0] != wantAddr {
		t.Fatalf("addresses = %+v, want %s", driver.Addresses, wantAddr)
	}
}

func assertStrongSwanLoadConnMatchesSpec(t *testing.T, spec ipsec.TransportLinkSpec) {
	t.Helper()
	msg, err := ipsec.BuildLoadConnMessage(spec)
	if err != nil {
		t.Fatalf("BuildLoadConnMessage: %v", err)
	}
	raw := msg[spec.TransportID]
	conn, ok := raw.(map[string]any)
	if !ok {
		t.Fatalf("load-conn message = %#v", msg)
	}
	if got := conn["remote_port"]; got != "4500" {
		t.Fatalf("remote_port = %#v, want 4500", got)
	}
	if got := conn["encap"]; got != "yes" {
		t.Fatalf("encap = %#v, want yes", got)
	}
	if got := conn["local_port"]; got != "4500" {
		t.Fatalf("local_port = %#v, want 4500", got)
	}
	children, _ := conn["children"].(map[string]any)
	child, _ := children[ipsec.ChildSAName(spec)].(map[string]any)
	if child["if_id_in"] != fmt.Sprintf("%d", spec.XFRMIfID) || child["if_id_out"] != fmt.Sprintf("%d", spec.XFRMIfID) {
		t.Fatalf("child if_id = %#v, want %d", child, spec.XFRMIfID)
	}
	local, _ := conn["local"].(map[string]any)
	remote, _ := conn["remote"].(map[string]any)
	if local["id"] != string(spec.LocalZone) || remote["id"] != string(spec.PeerZone) {
		t.Fatalf("conn identities local=%#v remote=%#v spec=%+v", local["id"], remote["id"], spec)
	}
}

func observedSAForSpec(spec ipsec.TransportLinkSpec, localEndpoint, remoteEndpoint string, reqID uint32) ipsec.SAState {
	return ipsec.SAState{
		Name:           spec.TransportID,
		Peer:           remoteEndpoint,
		ChildSA:        ipsec.ChildSAName(spec),
		XFRMIfID:       spec.XFRMIfID,
		ReqID:          reqID,
		LocalIdentity:  string(spec.LocalZone),
		RemoteIdentity: string(spec.PeerZone),
		LocalEndpoint:  localEndpoint,
		RemoteEndpoint: remoteEndpoint,
		Endpoint:       remoteEndpoint,
		Established:    true,
	}
}

func buildTestABDaemonStates(t *testing.T) (*stateFile, *syncConfigFile, *stateFile, *syncConfigFile) {
	t.Helper()
	rootPub, rootPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(root): %v", err)
	}
	catofesPub, catofesPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(catofes): %v", err)
	}
	nodeAPub, nodeAPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(node-a): %v", err)
	}
	nodeBPub, nodeBPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(node-b): %v", err)
	}

	rootAuthority := &zone.ZoneAuthority{
		Zone:      zone.RootZone,
		Epoch:     1,
		Threshold: 1,
		Keys: []zone.AuthorizedKey{{
			Key: rootPub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermDelegate},
			}},
		}},
	}
	catofesAuthority := &zone.ZoneAuthority{
		Zone:      "catofes.",
		Epoch:     1,
		Threshold: 1,
		Keys: []zone.AuthorizedKey{{
			Key: catofesPub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermDelegate},
			}},
		}},
	}
	nodeAAuthority := testWriteAuthority("node-a.catofes.", nodeAPub)
	nodeBAuthority := testWriteAuthority("node-b.catofes.", nodeBPub)
	catofesDelegation := testSignedDelegation(t, "catofes.", *catofesAuthority, zone.RootZone, rootPriv)
	nodeADelegation := testSignedDelegation(t, "node-a.catofes.", *nodeAAuthority, "catofes.", catofesPriv)
	nodeBDelegation := testSignedDelegation(t, "node-b.catofes.", *nodeBAuthority, "catofes.", catofesPriv)

	buildNetwork := func(managed zone.ZonePath) *zone.NetworkState {
		ns := zone.NewNetworkState()
		ns.Zones[zone.RootZone] = zone.NewZoneState(zone.RootZone, rootAuthority)
		ns.Zones["catofes."] = zone.NewZoneState("catofes.", catofesAuthority)
		ns.Zones[zone.RootZone].Delegations["catofes."] = catofesDelegation
		ns.Zones["catofes."].Delegations["node-a.catofes."] = nodeADelegation
		ns.Zones["catofes."].Delegations["node-b.catofes."] = nodeBDelegation
		switch managed {
		case "node-a.catofes.":
			ns.Zones["node-a.catofes."] = zone.NewZoneState("node-a.catofes.", nodeAAuthority)
		case "node-b.catofes.":
			ns.Zones["node-b.catofes."] = zone.NewZoneState("node-b.catofes.", nodeBAuthority)
		default:
			t.Fatalf("unexpected managed zone %s", managed)
		}
		configureValidation(ns)
		for _, path := range []zone.ZonePath{"catofes.", managed} {
			if err := higgscrypto.VerifyChain(ns, path, time.Unix(123, 0)); err != nil {
				t.Fatalf("VerifyChain(%s): %v", path, err)
			}
		}
		return ns
	}

	stateA := &stateFile{
		ManagedZone:    "node-a.catofes.",
		Network:        buildNetwork("node-a.catofes."),
		ZonePrivateKey: nodeAPriv,
	}
	stateB := &stateFile{
		ManagedZone:    "node-b.catofes.",
		Network:        buildNetwork("node-b.catofes."),
		ZonePrivateKey: nodeBPriv,
	}
	configA := &syncConfigFile{PeerID: "node-a.catofes.", ListenAddr: "127.0.0.1:0"}
	configB := &syncConfigFile{PeerID: "node-b.catofes.", ListenAddr: "127.0.0.1:0"}
	return stateA, configA, stateB, configB
}

func testWriteAuthority(path zone.ZonePath, pub ed25519.PublicKey) *zone.ZoneAuthority {
	return &zone.ZoneAuthority{
		Zone:      path,
		Epoch:     1,
		Threshold: 1,
		Keys: []zone.AuthorizedKey{{
			Key: pub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermWrite},
			}},
		}},
	}
}

func testSignedDelegation(t *testing.T, path zone.ZonePath, authority zone.ZoneAuthority, parent zone.ZonePath, priv ed25519.PrivateKey) *zone.Delegation {
	t.Helper()
	delegation := &zone.Delegation{
		ZoneName:  path,
		Scope:     zone.DelegationScopeDirectChild,
		Authority: authority,
	}
	if err := higgscrypto.SignDelegation(delegation, parent, priv); err != nil {
		t.Fatalf("SignDelegation(%s): %v", path, err)
	}
	return delegation
}

func testDaemonIPsecAppConfig(dataDir, advertiseAddr string, group ipsec.LinkGroupSpec) *appConfig {
	config := defaultAppConfig()
	config.DataDir = dataDir
	config.StatePath = filepath.Join(dataDir, "higgs.db")
	config.ListenAddr = advertiseAddr
	config.AdvertiseAddrs = []string{advertiseAddr}
	config.PublishEndpoints = false
	config.IPsec.LinkGroups = []ipsec.LinkGroupSpec{group}
	return config
}

func serveDaemonPackets(ctx context.Context, service *DaemonService, transport *gossip.Transport) (<-chan struct{}, context.CancelFunc) {
	serveCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-serveCtx.Done():
				return
			default:
			}
			packet, err := receiveWithContext(serveCtx, transport, time.Now().Add(100*time.Millisecond))
			if err != nil {
				continue
			}
			_ = service.processPacketEvent(packet, serveCtx)
		}
	}()
	return done, cancel
}

func assertGossipedIPsecRecords(t *testing.T, state *stateFile, peer zone.ZonePath) {
	t.Helper()
	zs := state.Network.Zones[peer]
	if zs == nil {
		t.Fatalf("zone %s missing after gossip", peer)
	}
	for _, key := range []string{ipsec.RecordKeyProfile, ipsec.RecordKeyAddresses, ipsec.RecordKeyPorts, ipsec.RecordKeyTransportKey, ipsec.OverlayIntentRecordKey("main")} {
		if zs.Records[key] == nil {
			t.Fatalf("%s missing for %s after gossip", key, peer)
		}
	}
}

func assertSingleLinkUpFromSA(t *testing.T, state *stateFile, spec ipsec.TransportLinkSpec, sa ipsec.SAState) {
	t.Helper()
	if state.IPsecReconcile == nil || len(state.IPsecReconcile.Actions) != 1 || state.IPsecReconcile.Actions[0].Action != ipsec.ReconcileActionAdopt {
		t.Fatalf("reconcile = %+v, want adopt", state.IPsecReconcile)
	}
	inst := state.LinkInstances[ipsec.LinkInstanceID(spec)]
	if inst.ActualState != ipsec.LinkStateUp || inst.Endpoint != sa.Endpoint {
		t.Fatalf("instance = %+v, want up endpoint %s", inst, sa.Endpoint)
	}
	if len(state.IPsecReconcile.ActualSAs) != 1 || state.IPsecReconcile.ActualSAs[0].ReqID != sa.ReqID || state.IPsecReconcile.ActualSAs[0].RemoteIdentity != sa.RemoteIdentity {
		t.Fatalf("actual SAs = %+v, want reqid=%d remote_id=%s", state.IPsecReconcile.ActualSAs, sa.ReqID, sa.RemoteIdentity)
	}
}

func hasDebugSkip(skips []linkSkipState, peer zone.ZonePath, reason string) bool {
	for _, skip := range skips {
		if skip.Peer == peer && skip.Reason == reason {
			return true
		}
	}
	return false
}

func appExecCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

func runAppCommand(t *testing.T, ctx context.Context, name string, args ...string) {
	t.Helper()
	if out, err := appExecCommand(ctx, name, args...); err != nil {
		t.Fatalf("%s %s failed: %v\n%s", name, strings.Join(args, " "), err, string(out))
	}
}

func addTunnelRoute(t *testing.T, ctx context.Context, ns string, spec ipsec.TransportLinkSpec) {
	t.Helper()
	bits := 32
	if spec.PeerTunnelAddr.Is6() {
		bits = 128
	}
	args := []string{"netns", "exec", ns, "ip", "route", "replace", netip.PrefixFrom(spec.PeerTunnelAddr, bits).String(), "dev", spec.InterfaceName}
	if spec.PeerTunnelAddr.Is4() {
		args = append(args, "src", spec.LocalTunnelAddr.String())
	}
	runAppCommand(t, ctx, "ip", args...)
}

func pingTunnelAddr(t *testing.T, ctx context.Context, ns string, target netip.Addr, iface string) {
	t.Helper()
	if target.Is4() {
		runAppCommand(t, ctx, "ip", "netns", "exec", ns, "ping", "-c", "1", "-W", "3", target.String())
		return
	}
	runAppCommand(t, ctx, "ip", "netns", "exec", ns, "ping", "-6", "-c", "1", "-W", "3", target.String()+"%"+iface)
}

func pingTunnelAddrShouldFail(t *testing.T, ctx context.Context, ns string, target netip.Addr, iface string) []byte {
	t.Helper()
	var cmdArgs []string
	if target.Is4() {
		cmdArgs = []string{"netns", "exec", ns, "ping", "-c", "1", "-W", "1", target.String()}
	} else {
		cmdArgs = []string{"netns", "exec", ns, "ping", "-6", "-c", "1", "-W", "1", target.String() + "%" + iface}
	}
	out, err := appExecCommand(ctx, "ip", cmdArgs...)
	if err == nil {
		t.Fatalf("ping unexpectedly succeeded to %s", target)
	}
	return out
}

func writeDaemonStrongSwanConf(viciSocket string) (string, error) {
	f, err := os.CreateTemp("", "higgs-daemon-strongswan-*.conf")
	if err != nil {
		return "", err
	}
	defer f.Close()
	_, err = fmt.Fprintf(f, `charon {
	install_routes = no
	install_virtual_ip = no
	uniqueids = no
	stderr {
		default = 2
	}
	plugins {
		vici {
			socket = unix://%s
		}
	}
}
`, viciSocket)
	if err != nil {
		return "", err
	}
	return f.Name(), nil
}

func daemonTestXFRMDriver(defaultNetNS ipsec.NetNSSpec, stateNetNS string) ipsec.SystemXFRMDriver {
	driver := ipsec.NewSystemXFRMDriver(defaultNetNS)
	driver.StateNetNS = ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: stateNetNS, Create: false}
	return driver
}

func startDaemonTestCharonInNetNS(ctx context.Context, t *testing.T, ns, piddir, conf string, logFile *os.File) *exec.Cmd {
	t.Helper()
	script := fmt.Sprintf("mkdir -p /run && mount --bind %s /run && STRONGSWAN_CONF=%s exec charon --debug-cfg 2 --debug-ike 2 --debug-mgr 2", piddir, conf)
	cmd := exec.CommandContext(ctx, "unshare", "-m", "ip", "netns", "exec", ns, "bash", "-c", script)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		t.Fatalf("start charon in %s: %v", ns, err)
	}
	return cmd
}

func waitDaemonTestVICI(ctx context.Context, socket string) (*ipsec.GoviciClient, error) {
	for {
		if _, err := os.Stat(socket); err == nil {
			break
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("timeout waiting for vici socket %s", socket)
		default:
			time.Sleep(50 * time.Millisecond)
		}
	}
	var lastErr error
	for {
		client, err := ipsec.NewGoviciClient(socket)
		if err == nil {
			return client, nil
		}
		lastErr = err
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("connect to %s: %w", socket, lastErr)
		default:
			time.Sleep(100 * time.Millisecond)
		}
	}
}

func waitDaemonTestSA(ctx context.Context, client *ipsec.GoviciClient, name string) error {
	for {
		events, err := client.CallStreaming(ctx, "list-sas", "list-sa", map[string]any{"ike": name})
		if err != nil {
			return err
		}
		for _, event := range events {
			if daemonTestSAEstablished(event) {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for SA %s", name)
		default:
			time.Sleep(200 * time.Millisecond)
		}
	}
}

func waitDaemonTestNoSA(ctx context.Context, client *ipsec.GoviciClient, name string) error {
	for {
		count, err := daemonTestEstablishedSACount(ctx, client, name)
		if err != nil {
			return err
		}
		if count == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for SA %s teardown; established count=%d", name, count)
		default:
			time.Sleep(200 * time.Millisecond)
		}
	}
}

func daemonTestEstablishedSACount(ctx context.Context, client *ipsec.GoviciClient, name string) (int, error) {
	events, err := client.CallStreaming(ctx, "list-sas", "list-sa", map[string]any{"ike": name})
	if err != nil {
		return 0, err
	}
	count := 0
	for _, event := range events {
		if daemonTestSAEstablished(event) {
			count++
		}
	}
	return count, nil
}

func daemonTestSAEstablished(raw map[string]any) bool {
	for _, v := range raw {
		sa, ok := v.(map[string]any)
		if !ok {
			continue
		}
		if strings.EqualFold(daemonTestString(sa["state"]), "ESTABLISHED") {
			return true
		}
		children, _ := sa["child-sas"].(map[string]any)
		for _, cv := range children {
			child, ok := cv.(map[string]any)
			if ok && daemonTestString(child["state"]) == "INSTALLED" {
				return true
			}
		}
	}
	return false
}

func daemonTestString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case fmt.Stringer:
		return x.String()
	default:
		return fmt.Sprint(v)
	}
}

func daemonTestTransportKey(t *testing.T, now time.Time) (*ipsecTransportKeyState, *ipsec.TransportKeyRecord) {
	t.Helper()
	key, record, err := ipsec.GenerateTransportKeyRecord(ipsec.AlgorithmECDSAP256, now, 0)
	if err != nil {
		t.Fatalf("GenerateTransportKeyRecord: %v", err)
	}
	return &ipsecTransportKeyState{
		Kind:        key.Kind,
		Algorithm:   key.Algorithm,
		PublicKey:   append([]byte(nil), key.PublicKey...),
		PrivateKey:  append([]byte(nil), key.PrivateKey...),
		Fingerprint: record.Fingerprint,
		NotBefore:   record.NotBefore,
		NotAfter:    record.NotAfter,
		UpdatedAt:   record.UpdatedAt,
	}, record
}

func addDaemonTestIPsecRecords(t *testing.T, zs *zone.ZoneState, peer zone.ZonePath, address string, key *ipsec.TransportKeyRecord, accept string, now time.Time) {
	t.Helper()
	if zs == nil {
		t.Fatalf("missing zone state for %s", peer)
	}
	zs.Records[ipsec.RecordKeyProfile] = unsignedIPsecRecord(t, peer, ipsec.RecordKeyProfile, ipsec.RecordTypeProfile, ipsec.ProfileRecord{
		Version:                 1,
		Enabled:                 true,
		Provider:                ipsec.ProviderStrongSwan,
		IKEIdentity:             string(peer),
		TransportKeyFingerprint: key.Fingerprint,
		Accept:                  accept,
		AddressFamilies:         []string{ipsec.FamilyIPv4},
		PathModes:               []string{ipsec.PathModeFamilyRedundant},
		UpdatedAt:               now.Unix(),
	})
	zs.Records[ipsec.RecordKeyAddresses] = unsignedIPsecRecord(t, peer, ipsec.RecordKeyAddresses, ipsec.RecordTypeAddresses, ipsec.AddressRecord{
		Version: 1,
		Addresses: []ipsec.AddressAdvertisement{{
			ID:           "underlay-v4",
			Source:       ipsec.SourceManualAddress,
			Address:      address,
			Family:       ipsec.FamilyIPv4,
			Reachability: ipsec.ReachabilityPublic,
		}},
		UpdatedAt: now.Unix(),
	})
	zs.Records[ipsec.RecordKeyPorts] = unsignedIPsecRecord(t, peer, ipsec.RecordKeyPorts, ipsec.RecordTypePorts, ipsec.PortRecord{
		Version: 1,
		Mode:    ipsec.PortModeFixed,
		Current: &ipsec.PortSelection{
			Generation: 1,
			IKE:        ipsec.PortBinding{Advertised: ipsec.DefaultIKEPort},
			NATT:       ipsec.PortBinding{Advertised: ipsec.DefaultNATTPort},
			ValidUntil: now.Add(time.Hour).Unix(),
		},
		UpdatedAt: now.Unix(),
	})
	zs.Records[ipsec.RecordKeyTransportKey] = unsignedIPsecRecord(t, peer, ipsec.RecordKeyTransportKey, ipsec.RecordTypeTransportKey, *key)
	zs.Records[ipsec.OverlayIntentRecordKey("main")] = unsignedIPsecRecord(t, peer, ipsec.OverlayIntentRecordKey("main"), ipsec.RecordTypeOverlayIntent, ipsec.OverlayIntentRecord{
		Version:       1,
		OverlayID:     "main",
		Provider:      ipsec.ProviderStrongSwan,
		PathKeys:      []string{"family:ipv4"},
		TunnelAddress: ipsec.TunnelAddressSpec{Mode: ipsec.TunnelAddressDerivedLinkLocal, Family: ipsec.FamilyIPv6},
		UpdatedAt:     now.Unix(),
	})
}

func setTestIPsecOverlayIntent(t *testing.T, zs *zone.ZoneState, peer zone.ZonePath, group ipsec.LinkGroupSpec, now time.Time) {
	t.Helper()
	if zs == nil {
		t.Fatalf("missing zone state for %s", peer)
	}
	group = group.Normalized()
	zs.Records[ipsec.OverlayIntentRecordKey(group.ID)] = unsignedIPsecRecord(t, peer, ipsec.OverlayIntentRecordKey(group.ID), ipsec.RecordTypeOverlayIntent, ipsec.OverlayIntentRecord{
		Version:       1,
		OverlayID:     group.ID,
		Provider:      group.Provider,
		PathKeys:      []string{"family:ipv4"},
		TunnelAddress: group.TunnelAddressSpec,
		UpdatedAt:     now.Unix(),
	})
}

func updateDaemonTestPortRecord(t *testing.T, zs *zone.ZoneState, peer zone.ZonePath, generation uint64, ikePort uint16, now time.Time) {
	t.Helper()
	if zs == nil {
		t.Fatalf("missing zone state for %s", peer)
	}
	if ikePort == 0 {
		ikePort = ipsec.DefaultIKEPort
	}
	nattPort := ikePort
	previous := ipsec.PortSelection{
		Generation: 1,
		IKE:        ipsec.PortBinding{Advertised: ipsec.DefaultIKEPort},
		NATT:       ipsec.PortBinding{Advertised: ipsec.DefaultNATTPort},
		ValidUntil: now.Add(time.Hour).Unix(),
	}
	zs.Records[ipsec.RecordKeyPorts] = unsignedIPsecRecord(t, peer, ipsec.RecordKeyPorts, ipsec.RecordTypePorts, ipsec.PortRecord{
		Version: 1,
		Mode:    ipsec.PortModeFixed,
		Current: &ipsec.PortSelection{
			Generation: generation,
			IKE:        ipsec.PortBinding{Local: ikePort, Advertised: ikePort},
			NATT:       ipsec.PortBinding{Local: nattPort, Advertised: nattPort},
			ValidUntil: now.Add(time.Hour).Unix(),
		},
		Previous:  []ipsec.PortSelection{previous},
		UpdatedAt: now.Unix(),
	})
}

func assertDaemonSystemLinkUp(t *testing.T, state *stateFile, spec ipsec.TransportLinkSpec) {
	t.Helper()
	inst := state.LinkInstances[ipsec.LinkInstanceID(spec)]
	if inst.ActualState != ipsec.LinkStateUp {
		t.Fatalf("link instance = %+v, want up", inst)
	}
	if state.IPsecReconcile == nil || len(state.IPsecReconcile.ActualSAs) == 0 {
		t.Fatalf("ipsec reconcile = %+v, want observed SAs", state.IPsecReconcile)
	}
	ikeName := inst.IKEName
	if ikeName == "" {
		ikeName = spec.TransportID
	}
	childName := inst.ChildSAName
	if childName == "" {
		childName = ipsec.ChildSAName(spec)
	}
	for _, sa := range state.IPsecReconcile.ActualSAs {
		// StrongSwan may append a rekey suffix (e.g. "-2") to IKE/child names.
		nameMatches := sa.Name == ikeName || strings.HasPrefix(sa.Name, ikeName+"-")
		childMatches := sa.ChildSA == childName || strings.HasPrefix(sa.ChildSA, childName+"-")
		if nameMatches && childMatches && (sa.XFRMIfID == 0 || sa.XFRMIfID == spec.XFRMIfID) && sa.Established {
			if sa.LocalIdentity != string(spec.LocalZone) || sa.RemoteIdentity != string(spec.PeerZone) {
				t.Fatalf("SA identities = %+v, want %s -> %s", sa, spec.LocalZone, spec.PeerZone)
			}
			return
		}
	}
	t.Fatalf("actual SAs = %+v, want established SA for %s", state.IPsecReconcile.ActualSAs, spec.TransportID)
}

func daemonSystemDesiredSpec(t *testing.T, state *stateFile, group ipsec.LinkGroupSpec, now time.Time) ipsec.TransportLinkSpec {
	t.Helper()
	plan, err := ipsec.PlanTransportLinks(context.Background(), state.Network, state.ManagedZone, []ipsec.LinkGroupSpec{group}, ipsec.LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks(%s): %v", state.ManagedZone, err)
	}
	if len(plan.Desired) != 1 {
		t.Fatalf("desired for %s = %+v, skips=%+v, want one", state.ManagedZone, plan.Desired, plan.Skipped)
	}
	return injectIPsecKeyMaterial(state, plan.Desired)[0]
}

func freeDaemonTestUDPAddr(t *testing.T) string {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		skipRestrictedSocket(t, err)
		t.Fatalf("ListenUDP(free port): %v", err)
	}
	addr := conn.LocalAddr().String()
	if err := conn.Close(); err != nil {
		t.Fatalf("close free UDP port: %v", err)
	}
	return addr
}

func waitDaemonRunGossipStrongSwanUp(ctx context.Context, t *testing.T, rtA, rtB *Runtime, groupA, groupB ipsec.LinkGroupSpec) (*stateFile, *stateFile) {
	t.Helper()
	var lastA, lastB *stateFile
	var lastErr error
	for {
		if stateA, err := rtA.LoadState(); err == nil {
			lastA = stateA
		} else {
			lastErr = err
		}
		if stateB, err := rtB.LoadState(); err == nil {
			lastB = stateB
		} else {
			lastErr = err
		}
		if lastA != nil && lastB != nil && daemonRunGossipStrongSwanReady(lastA, groupA) && daemonRunGossipStrongSwanReady(lastB, groupB) {
			return lastA, lastB
		}
		select {
		case <-ctx.Done():
			if lastA != nil {
				t.Logf("last node-a reconcile = %+v instances=%+v", lastA.IPsecReconcile, lastA.LinkInstances)
			}
			if lastB != nil {
				t.Logf("last node-b reconcile = %+v instances=%+v", lastB.IPsecReconcile, lastB.LinkInstances)
			}
			if lastErr != nil {
				t.Fatalf("timeout waiting for daemon gossip StrongSwan up; last load error: %v", lastErr)
			}
			t.Fatalf("timeout waiting for daemon gossip StrongSwan up")
		default:
			time.Sleep(250 * time.Millisecond)
		}
	}
}

func newDaemonTestStrongSwanDriver(t *testing.T, viciSocket string, client ipsec.VICIClient) *ipsec.StrongSwanDriver {
	t.Helper()
	return &ipsec.StrongSwanDriver{
		VICI:          client,
		KeyDir:        t.TempDir(),
		InitiateAsync: true,
		InitiateClientFactory: func() (ipsec.VICIClient, func() error, error) {
			initiateClient, err := ipsec.NewGoviciClient(viciSocket)
			if err != nil {
				return nil, nil, err
			}
			return initiateClient, initiateClient.Close, nil
		},
	}
}

func daemonRunGossipStrongSwanReady(state *stateFile, group ipsec.LinkGroupSpec) bool {
	if state == nil || state.IPsecReconcile == nil || len(state.IPsecReconcile.ActualSAs) == 0 || len(state.LinkInstances) == 0 {
		return false
	}
	if state.ManagedZone == "node-a.catofes." {
		if zs := state.Network.Zones["node-b.catofes."]; zs == nil || zs.Records[ipsec.RecordKeyTransportKey] == nil {
			return false
		}
	}
	if state.ManagedZone == "node-b.catofes." {
		if zs := state.Network.Zones["node-a.catofes."]; zs == nil || zs.Records[ipsec.RecordKeyTransportKey] == nil {
			return false
		}
	}
	plan, err := ipsec.PlanTransportLinks(context.Background(), state.Network, state.ManagedZone, []ipsec.LinkGroupSpec{group}, ipsec.LinkPlannerOptions{Now: time.Now()})
	if err != nil || len(plan.Desired) != 1 {
		return false
	}
	spec := injectIPsecKeyMaterial(state, plan.Desired)[0]
	inst, ok := state.LinkInstances[ipsec.LinkInstanceID(spec)]
	return ok && inst.ActualState == ipsec.LinkStateUp
}

func logDaemonTestFile(t *testing.T, label, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Logf("--- %s unavailable: %v ---", label, err)
		return
	}
	t.Logf("--- %s ---\n%s", label, string(data))
}

func dumpDaemonSystemState(t *testing.T, ctx context.Context, namespaces ...string) {
	t.Helper()
	for _, args := range [][]string{
		{"netns", "list"},
		{"link", "show", "type", "xfrm"},
		{"xfrm", "state"},
		{"xfrm", "policy"},
	} {
		if out, err := appExecCommand(ctx, "ip", args...); err == nil {
			t.Logf("ip %s\n%s", strings.Join(args, " "), string(out))
		} else {
			t.Logf("ip %s failed: %v\n%s", strings.Join(args, " "), err, string(out))
		}
	}
	for _, ns := range namespaces {
		for _, args := range [][]string{
			{"link"},
			{"addr"},
			{"route"},
			{"xfrm", "state"},
			{"xfrm", "policy"},
		} {
			full := append([]string{"netns", "exec", ns, "ip"}, args...)
			if out, err := appExecCommand(ctx, "ip", full...); err == nil {
				t.Logf("ip %s\n%s", strings.Join(full, " "), string(out))
			} else {
				t.Logf("ip %s failed: %v\n%s", strings.Join(full, " "), err, string(out))
			}
		}
	}
	if out, err := appExecCommand(ctx, "swanctl", "--list-sas"); err == nil {
		t.Logf("swanctl --list-sas\n%s", string(out))
	} else {
		t.Logf("swanctl --list-sas failed: %v\n%s", err, string(out))
	}
}

func dumpDaemonVICISAs(t *testing.T, ctx context.Context, viciSocket, label string) {
	t.Helper()
	client, err := ipsec.NewGoviciClient(viciSocket)
	if err != nil {
		t.Logf("vici connect %s: %v", label, err)
		return
	}
	defer client.Close()
	events, err := client.CallStreaming(ctx, "list-sas", "list-sa", nil)
	if err != nil {
		t.Logf("vici list-sas %s: %v", label, err)
		return
	}
	t.Logf("--- vici list-sas %s ---", label)
	for _, event := range events {
		t.Logf("%s", formatDaemonVICIEvent(event))
	}
}

func formatDaemonVICIEvent(event map[string]any) string {
	var parts []string
	for k, v := range event {
		parts = append(parts, fmt.Sprintf("%s=%v", k, v))
	}
	sort.Strings(parts)
	return strings.Join(parts, "; ")
}

func TestDaemonRecordPutEventSerializesWrite(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(2000, 0)
	rt := &Runtime{
		Config:    defaultAppConfig(),
		StatePath: filepath.Join(t.TempDir(), "higgs.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	service := newDaemonService(rt, state, config, time.Second)

	result, syncNow, shutdown := service.handleEvent(daemonEvent{
		Type: daemonEventRecordPut,
		RecordPut: &daemonRecordPut{
			Zone:  zone.ZonePath("node-b.catofes."),
			Key:   "identity",
			Value: []byte("node-b"),
			Type:  "policy.string",
		},
	})
	if result.Error != nil {
		t.Fatalf("handleEvent(record_put): %v", result.Error)
	}
	if !syncNow || shutdown {
		t.Fatalf("syncNow/shutdown = %v/%v, want true/false", syncNow, shutdown)
	}
	if result.Version != 1 {
		t.Fatalf("version = %d, want 1", result.Version)
	}
	latest, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if latest.Network.Zones["node-b.catofes."].Records["identity"] == nil {
		t.Fatalf("record was not persisted")
	}
}

func TestDaemonIPsecPortRotateEventTriggersDataPlaneReconcile(t *testing.T) {
	state, config := buildTestNetworkState(t)
	state.ManagedZone = "node-b.catofes."
	config.PeerID = string(state.ManagedZone)
	now := time.Unix(2000, 0)
	appConfig := defaultAppConfig()
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{testIPsecLinkGroup()}
	appConfig.IPsec.PortMode = ipsec.PortModeRange
	appConfig.IPsec.PortRange = ipsec.PortRange{From: 30000, To: 30099}
	appConfig.IPsec.PortPreviousGrace = 2 * time.Hour
	rt := &Runtime{
		Config:    appConfig,
		StatePath: filepath.Join(t.TempDir(), "higgs.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	sr := newSyncRuntime(state, config, nil, rt)
	if err := sr.publishIPsecRecords(); err != nil {
		t.Fatalf("publishIPsecRecords: %v", err)
	}
	first, err := ipsec.ParsePortRecord(state.Network.Zones[state.ManagedZone].Records[ipsec.RecordKeyPorts])
	if err != nil {
		t.Fatalf("ParsePortRecord(first): %v", err)
	}
	latest, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	driver := &countingIPsecDriver{}
	service := newDaemonService(rt, latest, config, time.Second)
	service.IPsecDriver = driver
	service.XFRMDriver = driver
	reply := make(chan daemonEventResult, 1)
	service.Events <- daemonEvent{Type: daemonEventIPsecPortRotate, Reply: reply}

	syncNow, shutdown, ipsecFlushed, _, firewallFlushed := service.processEvents(context.Background())
	if !syncNow || shutdown {
		t.Fatalf("syncNow/shutdown = %v/%v, want true/false", syncNow, shutdown)
	}
	if !firewallFlushed || !ipsecFlushed {
		t.Fatalf("firewallFlushed/ipsecFlushed = %v/%v, want true/true", firewallFlushed, ipsecFlushed)
	}
	result := <-reply
	if result.Error != nil {
		t.Fatalf("ipsec port rotate event: %v", result.Error)
	}
	if result.PortRotate == nil || result.PortRotate.CurrentGeneration != first.Current.Generation+1 {
		t.Fatalf("port rotate result = %+v, want generation %d", result.PortRotate, first.Current.Generation+1)
	}
	if driver.listCalls != 1 {
		t.Fatalf("ListSAs calls = %d, want 1", driver.listCalls)
	}
	rotatedState, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState(rotated): %v", err)
	}
	rotated, err := ipsec.ParsePortRecord(rotatedState.Network.Zones[rotatedState.ManagedZone].Records[ipsec.RecordKeyPorts])
	if err != nil {
		t.Fatalf("ParsePortRecord(rotated): %v", err)
	}
	if rotated.Current.Generation != first.Current.Generation+1 {
		t.Fatalf("generation = %d, want %d", rotated.Current.Generation, first.Current.Generation+1)
	}
	if len(rotated.Previous) != 1 || rotated.Previous[0].Generation != first.Current.Generation {
		t.Fatalf("previous grace = %+v, want generation %d", rotated.Previous, first.Current.Generation)
	}
}

func TestDaemonConcurrentRecordPutEventsAreSerialized(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(3000, 0)
	rt := &Runtime{
		Config:    defaultAppConfig(),
		StatePath: filepath.Join(t.TempDir(), "higgs.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	service := newDaemonService(rt, state, config, time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go pumpDaemonEvents(ctx, service)

	const writes = 8
	var wg sync.WaitGroup
	errs := make(chan error, writes)
	for i := 0; i < writes; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			result := service.enqueueEvent(ctx, daemonEvent{
				Type: daemonEventRecordPut,
				RecordPut: &daemonRecordPut{
					Zone:  zone.ZonePath("node-b.catofes."),
					Key:   "identity",
					Value: []byte{byte('a' + i)},
					Type:  "policy.string",
				},
			})
			errs <- result.Error
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("record_put event failed: %v", err)
		}
	}
	latest, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	record := latest.Network.Zones["node-b.catofes."].Records["identity"]
	if record == nil {
		t.Fatal("identity record missing")
	}
	if record.Version != writes {
		t.Fatalf("latest version = %d, want %d", record.Version, writes)
	}
	if history := latest.Network.Zones["node-b.catofes."].RecordHistory["identity"]; len(history) != writes-1 {
		t.Fatalf("history length = %d, want %d", len(history), writes-1)
	}
}

func addTestIPsecRecords(t *testing.T, zs *zone.ZoneState, peer zone.ZonePath, now time.Time, accept string) {
	t.Helper()
	if zs == nil {
		t.Fatalf("missing zone state for %s", peer)
	}
	fingerprint := "fp-" + string(peer)
	zs.Records[ipsec.RecordKeyProfile] = unsignedIPsecRecord(t, peer, ipsec.RecordKeyProfile, ipsec.RecordTypeProfile, ipsec.ProfileRecord{
		Version:                 1,
		Enabled:                 true,
		Provider:                ipsec.ProviderStrongSwan,
		IKEIdentity:             string(peer),
		TransportKeyFingerprint: fingerprint,
		Accept:                  accept,
		AddressFamilies:         []string{ipsec.FamilyIPv4},
		PathModes:               []string{ipsec.PathModeFamilyRedundant},
		UpdatedAt:               now.Unix(),
	})
	zs.Records[ipsec.RecordKeyAddresses] = unsignedIPsecRecord(t, peer, ipsec.RecordKeyAddresses, ipsec.RecordTypeAddresses, ipsec.AddressRecord{
		Version: 1,
		Addresses: []ipsec.AddressAdvertisement{{
			ID:           "public-v4",
			Source:       ipsec.SourceManualAddress,
			Address:      "203.0.113.10",
			Family:       ipsec.FamilyIPv4,
			Reachability: ipsec.ReachabilityPublic,
		}},
		UpdatedAt: now.Unix(),
	})
	zs.Records[ipsec.RecordKeyPorts] = unsignedIPsecRecord(t, peer, ipsec.RecordKeyPorts, ipsec.RecordTypePorts, ipsec.PortRecord{
		Version: 1,
		Mode:    ipsec.PortModeFixed,
		Current: &ipsec.PortSelection{
			Generation: 1,
			IKE:        ipsec.PortBinding{Advertised: ipsec.DefaultIKEPort},
			NATT:       ipsec.PortBinding{Advertised: ipsec.DefaultNATTPort},
			ValidUntil: now.Add(time.Hour).Unix(),
		},
		UpdatedAt: now.Unix(),
	})
	zs.Records[ipsec.RecordKeyTransportKey] = unsignedIPsecRecord(t, peer, ipsec.RecordKeyTransportKey, ipsec.RecordTypeTransportKey, ipsec.TransportKeyRecord{
		Version:     1,
		Kind:        ipsec.TransportKeyRawPublicKey,
		Algorithm:   ipsec.AlgorithmEd25519,
		PublicKey:   "base64",
		Fingerprint: fingerprint,
		UpdatedAt:   now.Unix(),
	})
	zs.Records[ipsec.OverlayIntentRecordKey("main")] = unsignedIPsecRecord(t, peer, ipsec.OverlayIntentRecordKey("main"), ipsec.RecordTypeOverlayIntent, ipsec.OverlayIntentRecord{
		Version:       1,
		OverlayID:     "main",
		Provider:      ipsec.ProviderStrongSwan,
		PathKeys:      []string{"family:ipv4"},
		TunnelAddress: ipsec.TunnelAddressSpec{Mode: ipsec.TunnelAddressDerivedLinkLocal, Family: ipsec.FamilyIPv6},
		UpdatedAt:     now.Unix(),
	})
}

func unsignedIPsecRecord(t *testing.T, peer zone.ZonePath, key, recordType string, value any) *zone.Record {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("Marshal(%s): %v", key, err)
	}
	return &zone.Record{
		Zone:      peer,
		Key:       key,
		Type:      recordType,
		Value:     data,
		Version:   1,
		Timestamp: time.Unix(4000, 0).Unix(),
	}
}

func TestDaemonRecordPutReloadsLatestStateBeforeSave(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(4000, 0)
	rt := &Runtime{
		Config:    defaultAppConfig(),
		StatePath: filepath.Join(t.TempDir(), "higgs.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	service := newDaemonService(rt, state, config, time.Second)

	external, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState(external): %v", err)
	}
	externalRecord, err := buildSignedRecordAt(external, "node-b.catofes.", "external", []byte("kept"), "policy.string", now)
	if err != nil {
		t.Fatalf("buildSignedRecordAt(external): %v", err)
	}
	if err := external.Network.Put(externalRecord); err != nil {
		t.Fatalf("Put(external): %v", err)
	}
	if err := rt.SaveState(external); err != nil {
		t.Fatalf("SaveState(external): %v", err)
	}

	result, _, _ := service.handleEvent(daemonEvent{
		Type: daemonEventRecordPut,
		RecordPut: &daemonRecordPut{
			Zone:  zone.ZonePath("node-b.catofes."),
			Key:   "daemon",
			Value: []byte("new"),
			Type:  "policy.string",
		},
	})
	if result.Error != nil {
		t.Fatalf("handleEvent(record_put): %v", result.Error)
	}
	latest, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState(latest): %v", err)
	}
	records := latest.Network.Zones["node-b.catofes."].Records
	if records["external"] == nil {
		t.Fatalf("external record was overwritten by stale daemon state")
	}
	if records["daemon"] == nil {
		t.Fatalf("daemon record missing")
	}
}

func TestBuildSignedRecordReturnsErrorWithoutLocalSigner(t *testing.T) {
	state, _ := buildTestNetworkState(t)
	state.ManagedZone = "node-a.catofes."
	state.ZonePrivateKey = nil

	_, err := buildSignedRecordAt(state, "node-b.catofes.", "identity", []byte("node-b"), "policy.string", time.Unix(1, 0))
	if err == nil || !strings.Contains(err.Error(), "no local signing key") {
		t.Fatalf("buildSignedRecordAt error = %v, want missing signer", err)
	}
}

func TestDaemonAdminEventsIssueAcceptAndRevoke(t *testing.T) {
	now := time.Unix(6000, 0)
	rootRT := &Runtime{
		Config:    defaultAppConfig(),
		StatePath: filepath.Join(t.TempDir(), "root.db"),
		Clock:     func() time.Time { return now },
	}
	if _, err := initRootStateInRuntime(rootRT); err != nil {
		t.Fatalf("initRootStateInRuntime: %v", err)
	}
	rootState, err := rootRT.LoadState()
	if err != nil {
		t.Fatalf("LoadState(root): %v", err)
	}
	service := newDaemonService(rootRT, rootState, &syncConfigFile{PeerID: "node-admin", ListenAddr: "127.0.0.1:0"}, time.Second)

	catofesPub, catofesPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(catofes): %v", err)
	}
	catofesRequest := &joinRequest{Version: 1, Zone: "catofes.", PublicKey: catofesPub}
	result, syncNow, shutdown := service.handleEvent(daemonEvent{Type: daemonEventDelegateIssue, JoinRequest: catofesRequest})
	if result.Error != nil {
		t.Fatalf("handleEvent(delegate_issue catofes): %v", result.Error)
	}
	if !syncNow || shutdown {
		t.Fatalf("delegate_issue syncNow/shutdown = %v/%v, want true/false", syncNow, shutdown)
	}
	if result.JoinBundle == nil || result.JoinBundle.Zone != "catofes." {
		t.Fatalf("delegate_issue bundle = %#v", result.JoinBundle)
	}

	catofesKey := &privateKeyFile{Type: "higgs.ed25519.private.v1", PublicKey: catofesPub, PrivateKey: catofesPriv}
	result, syncNow, shutdown = service.handleEvent(daemonEvent{
		Type:       daemonEventJoinAccept,
		JoinBundle: result.JoinBundle,
		PrivateKey: catofesKey,
	})
	if result.Error != nil {
		t.Fatalf("handleEvent(join_accept catofes): %v", result.Error)
	}
	if !syncNow || shutdown {
		t.Fatalf("join_accept syncNow/shutdown = %v/%v, want true/false", syncNow, shutdown)
	}
	if result.Zone != "catofes." {
		t.Fatalf("join_accept zone = %s, want catofes.", result.Zone)
	}

	nodePub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(node-b): %v", err)
	}
	nodeRequest := &joinRequest{Version: 1, Zone: "node-b.catofes.", PublicKey: nodePub}
	result, _, _ = service.handleEvent(daemonEvent{Type: daemonEventDelegateIssue, JoinRequest: nodeRequest})
	if result.Error != nil {
		t.Fatalf("handleEvent(delegate_issue node-b): %v", result.Error)
	}
	if result.JoinBundle == nil || result.JoinBundle.Zone != "node-b.catofes." {
		t.Fatalf("node-b bundle = %#v", result.JoinBundle)
	}

	result, syncNow, shutdown = service.handleEvent(daemonEvent{
		Type:   daemonEventDelegateRevoke,
		Zone:   "node-b.catofes.",
		Reason: "test revoke",
	})
	if result.Error != nil {
		t.Fatalf("handleEvent(delegate_revoke): %v", result.Error)
	}
	if !syncNow || shutdown {
		t.Fatalf("delegate_revoke syncNow/shutdown = %v/%v, want true/false", syncNow, shutdown)
	}
	latest, err := rootRT.LoadState()
	if err != nil {
		t.Fatalf("LoadState(latest): %v", err)
	}
	parent := latest.Network.Zones[zone.ZonePath("catofes.")]
	if parent == nil || parent.Revocations["node-b.catofes."] == nil {
		t.Fatalf("node-b revocation was not persisted")
	}
	if parent.Delegations["node-b.catofes."] != nil {
		t.Fatalf("node-b delegation still active after revoke")
	}
}

func TestDaemonConcurrentAdminAndRecordEventsPreserveState(t *testing.T) {
	now := time.Unix(7000, 0)
	rt := &Runtime{
		Config:    defaultAppConfig(),
		StatePath: filepath.Join(t.TempDir(), "catofes.db"),
		Clock:     func() time.Time { return now },
	}
	if _, err := initRootStateInRuntime(rt); err != nil {
		t.Fatalf("initRootStateInRuntime: %v", err)
	}
	state, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState(root): %v", err)
	}
	service := newDaemonService(rt, state, &syncConfigFile{PeerID: "zone-catofes-admin", ListenAddr: "127.0.0.1:0"}, time.Second)

	catofesPub, catofesPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(catofes): %v", err)
	}
	catofesIssue, err := service.handleDelegateIssueEvent(&joinRequest{Version: 1, Zone: "catofes.", PublicKey: catofesPub}, nil)
	if err != nil {
		t.Fatalf("handleDelegateIssueEvent(catofes): %v", err)
	}
	if _, err := service.handleJoinAcceptEvent(catofesIssue.Bundle, &privateKeyFile{Type: "higgs.ed25519.private.v1", PublicKey: catofesPub, PrivateKey: catofesPriv}); err != nil {
		t.Fatalf("handleJoinAcceptEvent(catofes): %v", err)
	}

	nodeBPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(node-b): %v", err)
	}
	if _, err := service.handleDelegateIssueEvent(&joinRequest{Version: 1, Zone: "node-b.catofes.", PublicKey: nodeBPub}, nil); err != nil {
		t.Fatalf("handleDelegateIssueEvent(node-b): %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go pumpDaemonEvents(ctx, service)

	nodeCPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(node-c): %v", err)
	}
	events := []daemonEvent{
		{
			Type: daemonEventRecordPut,
			RecordPut: &daemonRecordPut{
				Zone:  "catofes.",
				Key:   "admin-note",
				Value: []byte("kept"),
				Type:  "policy.string",
			},
		},
		{
			Type:        daemonEventDelegateIssue,
			JoinRequest: &joinRequest{Version: 1, Zone: "node-c.catofes.", PublicKey: nodeCPub},
		},
		{
			Type:   daemonEventDelegateRevoke,
			Zone:   "node-b.catofes.",
			Reason: "concurrent test",
		},
	}
	errs := make(chan error, len(events))
	var wg sync.WaitGroup
	for _, event := range events {
		wg.Add(1)
		go func(event daemonEvent) {
			defer wg.Done()
			errs <- service.enqueueEvent(ctx, event).Error
		}(event)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent daemon event failed: %v", err)
		}
	}

	latest, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState(latest): %v", err)
	}
	catofes := latest.Network.Zones[zone.ZonePath("catofes.")]
	if catofes.Records["admin-note"] == nil {
		t.Fatalf("record_put result missing after concurrent admin events")
	}
	if catofes.Delegations["node-c.catofes."] == nil {
		t.Fatalf("delegate_issue result missing after concurrent record_put")
	}
	if catofes.Revocations["node-b.catofes."] == nil {
		t.Fatalf("delegate_revoke result missing after concurrent record_put")
	}
}

func TestDaemonRemoteAppliedEventUpdatesPeerState(t *testing.T) {
	state, config := buildTestNetworkState(t)
	rt := &Runtime{
		Config:    defaultAppConfig(),
		StatePath: filepath.Join(t.TempDir(), "higgs.db"),
		Clock:     func() time.Time { return time.Unix(5000, 0) },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	service := newDaemonService(rt, state, config, time.Second)
	var hookCalled bool
	service.Hooks.OnStateChanged = func(*stateFile) {
		hookCalled = true
	}

	result, syncNow, shutdown := service.handleEvent(daemonEvent{
		Type:         daemonEventRemoteApplied,
		SourcePeerID: "node-a.catofes.",
	})
	if result.Error != nil {
		t.Fatalf("handleEvent(remote_applied): %v", result.Error)
	}
	if syncNow || shutdown {
		t.Fatalf("syncNow/shutdown = %v/%v, want false/false", syncNow, shutdown)
	}
	if !hookCalled {
		t.Fatal("state changed hook was not called")
	}
	latest, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if got := latest.SyncPeers["node-a.catofes."].LastUpdateSource; got != "node-a.catofes." {
		t.Fatalf("LastUpdateSource = %q, want node-a.catofes.", got)
	}
}

func TestCleanupIPsecLinkInstancesTearsDownManagedLinks(t *testing.T) {
	state, _ := buildTestNetworkState(t)
	now := time.Unix(5100, 0)
	spec := ipsec.TransportLinkSpec{
		LocalZone:     "node-a.catofes.",
		PeerZone:      "node-b.catofes.",
		OverlayID:     "main",
		TransportID:   "ipsec-cleanup",
		InterfaceName: "hgs-clean0",
		XFRMIfID:      5100,
	}
	inst := ipsec.NewLinkInstance(spec, ipsec.LinkStateUp, now)
	state.LinkInstances = linkInstancesFromIPsec(map[string]ipsec.LinkInstance{inst.ID: inst})
	driver := &ipsec.DryRunDriver{}

	cleaned, err := cleanupIPsecLinkInstances(context.Background(), state, driver, driver, now)
	if err != nil {
		t.Fatalf("cleanupIPsecLinkInstances: %v", err)
	}
	if cleaned != 1 {
		t.Fatalf("cleaned = %d, want 1", cleaned)
	}
	if len(state.LinkInstances) != 0 {
		t.Fatalf("link instances = %+v, want empty", state.LinkInstances)
	}
	if len(driver.Terminated) != 1 || driver.Terminated[0] != spec.TransportID {
		t.Fatalf("terminated = %+v, want %s", driver.Terminated, spec.TransportID)
	}
	if len(driver.Unloaded) != 1 || driver.Unloaded[0] != spec.TransportID {
		t.Fatalf("unloaded = %+v, want %s", driver.Unloaded, spec.TransportID)
	}
	if len(driver.DeletedIFs) != 1 || driver.DeletedIFs[0] != spec.InterfaceName {
		t.Fatalf("deleted interfaces = %+v, want %s", driver.DeletedIFs, spec.InterfaceName)
	}
	if state.IPsecReconcile == nil || state.IPsecReconcile.LastRunUnix != now.Unix() || state.IPsecReconcile.LastError != "" {
		t.Fatalf("ipsec reconcile = %+v, want cleanup timestamp and no error", state.IPsecReconcile)
	}
}

func TestRecoveryPurgeRevokedApplyCleansIPsecLinksBeforeDeletingState(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(5101, 0)
	addRevocationTombstoneForTest(t, state, "node-b.catofes.", "catofes.")
	spec := ipsec.TransportLinkSpec{
		LocalZone:     state.ManagedZone,
		PeerZone:      "node-b.catofes.",
		OverlayID:     "main",
		TransportID:   "ipsec-purge-revoked",
		InterfaceName: "hgs-purge0",
		XFRMIfID:      5101,
	}
	inst := ipsec.NewLinkInstance(spec, ipsec.LinkStateUp, now)
	state.LinkInstances = linkInstancesFromIPsec(map[string]ipsec.LinkInstance{inst.ID: inst})
	state.SyncPeers = map[string]syncPeerState{"node-b.catofes.": {}}
	rt := &Runtime{
		Config:    defaultAppConfig(),
		StatePath: filepath.Join(t.TempDir(), "higgs.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	driver := &ipsec.DryRunDriver{}
	service := newDaemonService(rt, state, config, time.Second)
	service.IPsecDriver = driver
	service.XFRMDriver = driver

	plan, err := service.handleRecoveryPurgeRevokedEvent(context.Background(), "", true)
	if err != nil {
		t.Fatalf("handleRecoveryPurgeRevokedEvent: %v", err)
	}
	if len(plan.LinkInstances) != 1 || plan.LinkInstances[0] != inst.ID {
		t.Fatalf("plan link instances = %+v, want %s", plan.LinkInstances, inst.ID)
	}
	if len(driver.Terminated) != 1 || driver.Terminated[0] != spec.TransportID {
		t.Fatalf("terminated = %+v, want %s", driver.Terminated, spec.TransportID)
	}
	if len(driver.Unloaded) != 1 || driver.Unloaded[0] != spec.TransportID {
		t.Fatalf("unloaded = %+v, want %s", driver.Unloaded, spec.TransportID)
	}
	if len(driver.DeletedIFs) != 1 || driver.DeletedIFs[0] != spec.InterfaceName {
		t.Fatalf("deleted interfaces = %+v, want %s", driver.DeletedIFs, spec.InterfaceName)
	}
	latest, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if latest.Network.Zones["node-b.catofes."] != nil {
		t.Fatalf("revoked zone still present after purge")
	}
	if _, ok := latest.LinkInstances[inst.ID]; ok {
		t.Fatalf("revoked link instance still present after purge")
	}
	if _, ok := latest.SyncPeers["node-b.catofes."]; ok {
		t.Fatalf("revoked sync peer still present after purge")
	}
	if latest.IPsecReconcile == nil || latest.IPsecReconcile.LastRunUnix != now.Unix() {
		t.Fatalf("ipsec cleanup snapshot = %+v, want timestamp", latest.IPsecReconcile)
	}
}

func TestMarkIPsecActionSucceededKeepsSecondaryStandbyDownAfterUpdate(t *testing.T) {
	now := time.Unix(5102, 0)
	spec := ipsec.TransportLinkSpec{
		LocalZone:     "node-b.catofes.",
		PeerZone:      "node-a.catofes.",
		OverlayID:     "main",
		TransportID:   "ipsec-standby",
		InterfaceName: "hgs-standby",
		XFRMIfID:      5102,
	}
	inst := ipsec.NewLinkInstance(spec, ipsec.LinkStateDegraded, now)
	inst.InitiatorRole = ipsec.InitiatorRoleSecondaryStandby
	instances := map[string]ipsec.LinkInstance{inst.ID: inst}

	markIPsecActionSucceeded(instances, ipsec.ReconcileAction{
		Action:   ipsec.ReconcileActionUpdate,
		Spec:     &spec,
		Instance: &inst,
	}, now.Add(time.Second))

	got := instances[inst.ID]
	if got.ActualState != ipsec.LinkStateDown {
		t.Fatalf("state = %q, want down for standby update", got.ActualState)
	}
}

func TestRecoveryCleanupIPsecDirectNoLinksDoesNotRequireVICI(t *testing.T) {
	state, _ := buildTestNetworkState(t)
	state.LinkInstances = nil
	now := time.Unix(5105, 0)
	rt := &Runtime{
		Config:    defaultAppConfig(),
		StatePath: filepath.Join(t.TempDir(), "higgs.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	cleaned, orphans, err := recoveryCleanupIPsecDirect(context.Background(), rt, false)
	if err != nil {
		t.Fatalf("recoveryCleanupIPsecDirect: %v", err)
	}
	if cleaned != 0 {
		t.Fatalf("cleaned = %d, want 0", cleaned)
	}
	if orphans != 0 {
		t.Fatalf("orphans = %d, want 0", orphans)
	}
	latest, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if latest.IPsecReconcile == nil || latest.IPsecReconcile.LastRunUnix != now.Unix() {
		t.Fatalf("ipsec reconcile = %+v, want cleanup timestamp", latest.IPsecReconcile)
	}
}

func TestCleanupIPsecOrphanConnectionsOnlyRemovesUnreferencedHiggsConnections(t *testing.T) {
	state, _ := buildTestNetworkState(t)
	now := time.Unix(5111, 0)
	spec := ipsec.TransportLinkSpec{
		LocalZone:     "node-a.catofes.",
		PeerZone:      "node-b.catofes.",
		OverlayID:     "main",
		TransportID:   "ipsec-managed",
		InterfaceName: "hgs-managed",
		XFRMIfID:      5111,
	}
	inst := ipsec.NewLinkInstance(spec, ipsec.LinkStateUp, now)
	state.LinkInstances = linkInstancesFromIPsec(map[string]ipsec.LinkInstance{inst.ID: inst})
	driver := &ipsec.DryRunDriver{
		LoadedConnections: []ipsec.ConnectionState{
			{Name: "ipsec-managed"},
			{Name: "ipsec-orphan-r3"},
			{Name: "manual-vpn"},
		},
	}

	cleaned, err := cleanupIPsecOrphanConnections(context.Background(), state, driver)
	if err != nil {
		t.Fatalf("cleanupIPsecOrphanConnections: %v", err)
	}
	if cleaned != 1 {
		t.Fatalf("cleaned = %d, want 1", cleaned)
	}
	if len(driver.Terminated) != 1 || driver.Terminated[0] != "ipsec-orphan-r3" {
		t.Fatalf("terminated = %+v, want orphan only", driver.Terminated)
	}
	if len(driver.Unloaded) != 1 || driver.Unloaded[0] != "ipsec-orphan-r3" {
		t.Fatalf("unloaded = %+v, want orphan only", driver.Unloaded)
	}
}

func TestDaemonIPsecCleanupEventTearsDownManagedLinks(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(5110, 0)
	addTestIPsecRecords(t, state.Network.Zones["node-b.catofes."], "node-b.catofes.", now, ipsec.AcceptInbound)
	appConfig := defaultAppConfig()
	group := testIPsecLinkGroup()
	setTestIPsecOverlayIntent(t, state.Network.Zones["node-b.catofes."], "node-b.catofes.", group, now)
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{group}
	plan, err := ipsec.PlanTransportLinks(context.Background(), state.Network, state.ManagedZone, appConfig.IPsec.LinkGroups, ipsec.LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks: %v", err)
	}
	if len(plan.Desired) != 1 {
		t.Fatalf("desired links = %d, want 1", len(plan.Desired))
	}
	spec := plan.Desired[0]
	inst := ipsec.NewLinkInstance(spec, ipsec.LinkStateUp, now)
	state.LinkInstances = linkInstancesFromIPsec(map[string]ipsec.LinkInstance{inst.ID: inst})
	rt := &Runtime{
		Config:    appConfig,
		StatePath: filepath.Join(t.TempDir(), "higgs.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	driver := &observedIPsecDriver{}
	service := newDaemonService(rt, state, config, time.Second)
	service.IPsecDriver = driver
	service.XFRMDriver = driver

	reply := make(chan daemonEventResult, 1)
	service.Events <- daemonEvent{Type: daemonEventIPsecCleanup, Reply: reply}
	syncNow, shutdown, ipsecFlushed, _, _ := service.processEvents(context.Background())
	result := <-reply
	if result.Error != nil {
		t.Fatalf("processEvents(ipsec_cleanup): %v", result.Error)
	}
	if result.CleanedLinks != 1 || syncNow || shutdown {
		t.Fatalf("result=%+v syncNow=%v shutdown=%v, want one cleaned and no sync/shutdown", result, syncNow, shutdown)
	}
	if !ipsecFlushed {
		t.Fatal("ipsec cleanup did not flush reconcile")
	}
	latest, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if len(latest.LinkInstances) != 1 {
		t.Fatalf("persisted link instances = %+v, want recreated link", latest.LinkInstances)
	}
	recreated := latest.LinkInstances[ipsec.LinkInstanceID(spec)]
	if recreated.ActualState != ipsec.LinkStateConnecting {
		t.Fatalf("recreated instance = %+v, want connecting", recreated)
	}
	if len(driver.Terminated) != 1 || driver.Terminated[0] != spec.TransportID || len(driver.Unloaded) != 1 || driver.Unloaded[0] != spec.TransportID || len(driver.DeletedIFs) != 1 || driver.DeletedIFs[0] != spec.InterfaceName {
		t.Fatalf("driver cleanup: terminated=%+v unloaded=%+v deleted=%+v", driver.Terminated, driver.Unloaded, driver.DeletedIFs)
	}
	if len(driver.Connections) != 1 || driver.Connections[0].TransportID != spec.TransportID || len(driver.Interfaces) != 1 || driver.Interfaces[0].InterfaceName != spec.InterfaceName {
		t.Fatalf("driver recreate: connections=%+v interfaces=%+v", driver.Connections, driver.Interfaces)
	}
}

func TestDaemonIPsecCleanupEventCanCleanOrphanConnections(t *testing.T) {
	state, config := buildTestNetworkState(t)
	state.LinkInstances = nil
	now := time.Unix(5112, 0)
	rt := &Runtime{
		Config:    defaultAppConfig(),
		StatePath: filepath.Join(t.TempDir(), "higgs.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	driver := &ipsec.DryRunDriver{
		LoadedConnections: []ipsec.ConnectionState{{Name: "ipsec-orphan-r3"}},
	}
	service := newDaemonService(rt, state, config, time.Second)
	service.IPsecDriver = driver
	service.XFRMDriver = driver

	reply := make(chan daemonEventResult, 1)
	service.Events <- daemonEvent{Type: daemonEventIPsecCleanup, Orphans: true, Reply: reply}
	_, _, ipsecFlushed, _, _ := service.processEvents(context.Background())
	result := <-reply
	if result.Error != nil {
		t.Fatalf("processEvents(ipsec_cleanup --orphans): %v", result.Error)
	}
	if result.CleanedLinks != 0 || result.CleanedOrphans != 1 {
		t.Fatalf("result = %+v, want one orphan only", result)
	}
	if !ipsecFlushed {
		t.Fatal("ipsec cleanup did not flush reconcile")
	}
	if len(driver.Terminated) != 1 || driver.Terminated[0] != "ipsec-orphan-r3" || len(driver.Unloaded) != 1 || driver.Unloaded[0] != "ipsec-orphan-r3" {
		t.Fatalf("driver cleanup: terminated=%+v unloaded=%+v", driver.Terminated, driver.Unloaded)
	}
}

func TestDaemonControlErrorResponses(t *testing.T) {
	state, config := buildTestNetworkState(t)
	service := newDaemonService(&Runtime{Config: defaultAppConfig()}, state, config, time.Second)

	response := controlRequestViaPipe(t, service, controlRequest{Method: "record_put", Zone: "node-b.catofes."})
	if response.OK || response.Error == "" {
		t.Fatalf("invalid record_put response = %#v, want error", response)
	}

	response = controlRequestViaPipe(t, service, controlRequest{Method: "record_get", Zone: "node-b.catofes."})
	if response.OK || response.Error == "" {
		t.Fatalf("invalid record_get response = %#v, want error", response)
	}

	response = controlRequestViaPipe(t, service, controlRequest{Method: "bogus"})
	if response.OK || response.Error == "" {
		t.Fatalf("unknown method response = %#v, want error", response)
	}

	response = controlRequestViaPipe(t, service, controlRequest{Method: "root_init"})
	if response.OK || response.Error == "" {
		t.Fatalf("root_init response = %#v, want error", response)
	}
}

func TestDaemonControlStatus(t *testing.T) {
	state, config := buildTestNetworkState(t)
	service := newDaemonService(&Runtime{Config: defaultAppConfig()}, state, config, time.Second)
	service.ControlSocketPath = filepath.Join(t.TempDir(), "higgs.sock")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stop, err := service.startControlServer(ctx)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			t.Skipf("Unix sockets are not permitted in this environment: %v", err)
		}
		t.Fatalf("startControlServer: %v", err)
	}
	defer stop()

	response, err := sendControlRequest(service.ControlSocketPath, controlRequest{Method: "status"})
	if err != nil {
		t.Fatalf("sendControlRequest(status): %v", err)
	}
	if response.PeerID != config.PeerID || response.Message != "daemon online" {
		t.Fatalf("status response = %#v", response)
	}
}

func TestDaemonControlLinksStatusUsesReconcileSnapshot(t *testing.T) {
	state, config := buildTestNetworkState(t)
	state.LinkInstances = map[string]linkInstanceState{
		"link-1": {
			ID:            "link-1",
			GroupID:       "main",
			PeerZone:      "node-b.catofes.",
			TransportKind: "ipsec",
			LinkID:        "stable-link",
			TransportID:   "runtime-r3",
			ActualState:   "up",
			InterfaceName: "hgsabc123",
			XFRMIfID:      42,
			IKEName:       "runtime-r3",
			ChildSAName:   "runtime-r3-child",
			Endpoint:      "198.51.100.2:4500",
		},
	}
	state.IPsecReconcile = &ipsecReconcileState{
		LastRunUnix:  1234,
		DesiredLinks: 1,
		Desired: []desiredLinkState{{
			InstanceID:      "link-1",
			GroupID:         "main",
			PeerZone:        "node-b.catofes.",
			LinkID:          "stable-link",
			TransportID:     "runtime-r3",
			DesiredSpecHash: "desired-hash",
			InterfaceName:   "hgsabc123",
			XFRMIfID:        42,
			Endpoint:        "203.0.113.9:33403",
			LocalTunnelAddr: "fd00::1%hgsabc123",
			PeerTunnelAddr:  "fd00::2%hgsabc123",
		}},
		ActualSAs: []linkSAState{{
			Name:           "runtime-r3",
			ChildSA:        "runtime-r3-child",
			RemoteEndpoint: "203.0.113.9:33403",
			Established:    true,
		}},
	}
	service := newDaemonService(&Runtime{Config: defaultAppConfig()}, state, config, time.Second)

	response := controlRequestViaPipe(t, service, controlRequest{Method: "links_status"})
	if !response.OK || response.Links == nil {
		t.Fatalf("links_status response = %#v", response)
	}
	if response.Links.DesiredPlanSource != "last_reconcile" || response.Links.ReplannedDesired != 1 {
		t.Fatalf("links_status source/count = %q/%d, want last_reconcile/1", response.Links.DesiredPlanSource, response.Links.ReplannedDesired)
	}
	if len(response.Links.ActualSAs) != 1 {
		t.Fatalf("links_status actual_sas = %d, want 1", len(response.Links.ActualSAs))
	}
	links := response.Links.Inspection.Links
	if len(links) != 1 || links[0].Desired == nil {
		t.Fatalf("links_status links = %+v, want desired snapshot", links)
	}
	if got := links[0].Desired.Endpoint; got != "203.0.113.9:33403" {
		t.Fatalf("links_status desired endpoint = %q, want reconcile snapshot endpoint", got)
	}
}

func TestDaemonControlRecordGet(t *testing.T) {
	state, config := buildTestNetworkState(t)
	record, err := buildSignedRecordAt(state, "node-b.catofes.", "site/name", []byte(`{"name":"node-b"}`), "policy.json", time.Unix(1000, 0))
	if err != nil {
		t.Fatalf("buildSignedRecordAt: %v", err)
	}
	if err := state.Network.Put(record); err != nil {
		t.Fatalf("Put(record): %v", err)
	}
	record, err = buildSignedRecordAt(state, "node-b.catofes.", "site/name", []byte(`{"name":"node-b-2"}`), "policy.json", time.Unix(1001, 0))
	if err != nil {
		t.Fatalf("buildSignedRecordAt(second): %v", err)
	}
	if err := state.Network.Put(record); err != nil {
		t.Fatalf("Put(second record): %v", err)
	}
	service := newDaemonService(&Runtime{Config: defaultAppConfig()}, state, config, time.Second)

	response := controlRequestViaPipe(t, service, controlRequest{
		Method:  "record_get",
		Zone:    "node-b.catofes.",
		Key:     "site/name",
		History: 1,
	})
	if !response.OK {
		t.Fatalf("record_get response = %#v", response)
	}
	if response.Record["key"] != "site/name" || response.Record["value"] != `{"name":"node-b-2"}` || response.Record["record_hash"] == "" {
		t.Fatalf("record_get record = %#v", response.Record)
	}
	history := response.Record["record_history"].([]any)
	if len(history) != 1 {
		t.Fatalf("record_get history len = %d, want 1", len(history))
	}
	if item := history[0].(map[string]any); item["value"] != `{"name":"node-b"}` {
		t.Fatalf("record_get history = %#v", history)
	}

	response = controlRequestViaPipe(t, service, controlRequest{
		Method: "record_get",
		Zone:   "node-b.catofes.",
		Key:    "missing",
	})
	if response.OK || response.Error == "" {
		t.Fatalf("missing record_get response = %#v, want error", response)
	}
}

func pumpDaemonEvents(ctx context.Context, service *DaemonService) {
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			service.processEvents(ctx)
		}
	}
}

func controlRequestViaPipe(t *testing.T, service *DaemonService, request controlRequest) controlResponse {
	t.Helper()
	client, server := net.Pipe()
	defer client.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		service.handleControlConn(context.Background(), server)
	}()
	if err := json.NewEncoder(client).Encode(request); err != nil {
		t.Fatalf("Encode(request): %v", err)
	}
	var response controlResponse
	if err := json.NewDecoder(client).Decode(&response); err != nil {
		t.Fatalf("Decode(response): %v", err)
	}
	<-done
	return response
}

func TestDaemonEventLoopSyncSession(t *testing.T) {
	stateA, configA, stateB, configB := buildTestABDaemonStates(t)
	now := time.Now()

	recordA, err := buildSignedRecordAt(stateA, "node-a.catofes.", "event-loop-test", []byte("from-a"), "policy.string", now)
	if err != nil {
		t.Fatalf("build record for A: %v", err)
	}
	if err := stateA.Network.Put(recordA); err != nil {
		t.Fatalf("put record on A: %v", err)
	}
	recordB, err := buildSignedRecordAt(stateB, "node-b.catofes.", "event-loop-test", []byte("from-b"), "policy.string", now)
	if err != nil {
		t.Fatalf("build record for B: %v", err)
	}
	if err := stateB.Network.Put(recordB); err != nil {
		t.Fatalf("put record on B: %v", err)
	}

	transportA, err := gossip.Listen(gossip.Config{PeerID: configA.PeerID, ListenAddr: configA.ListenAddr})
	if err != nil {
		t.Fatalf("Listen(A): %v", err)
	}
	defer transportA.Close()
	transportB, err := gossip.Listen(gossip.Config{PeerID: configB.PeerID, ListenAddr: configB.ListenAddr})
	if err != nil {
		t.Fatalf("Listen(B): %v", err)
	}
	defer transportB.Close()
	transportA.AddPeer(configB.PeerID, transportB.LocalAddr())
	transportB.AddPeer(configA.PeerID, transportA.LocalAddr())
	configA.ListenAddr = transportA.LocalAddr().String()
	configB.ListenAddr = transportB.LocalAddr().String()
	configA.Bootstrap = []syncConfigPeer{{ID: configB.PeerID, Addr: transportB.LocalAddr().String()}}
	configB.Bootstrap = []syncConfigPeer{{ID: configA.PeerID, Addr: transportA.LocalAddr().String()}}

	rtA := &Runtime{
		Config:    defaultAppConfig(),
		StatePath: filepath.Join(t.TempDir(), "node-a.db"),
		Clock:     func() time.Time { return now },
	}
	rtB := &Runtime{
		Config:    defaultAppConfig(),
		StatePath: filepath.Join(t.TempDir(), "node-b.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rtA.SaveState(stateA); err != nil {
		t.Fatalf("SaveState(A): %v", err)
	}
	if err := rtB.SaveState(stateB); err != nil {
		t.Fatalf("SaveState(B): %v", err)
	}

	serviceA := newDaemonService(rtA, stateA, configA, time.Second)
	serviceA.Sync.Transport = transportA
	serviceB := newDaemonService(rtB, stateB, configB, time.Second)
	serviceB.Sync.Transport = transportB

	fc := newFakeClock(now)
	serviceA.EnableEventLoopSync(fc)
	serviceB.EnableEventLoopSync(fc)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	listenerA, err := startObjectPullServer(serviceA)
	if err != nil {
		t.Fatalf("startObjectPullServer(A): %v", err)
	}
	if listenerA != nil {
		defer listenerA.Close()
	}
	listenerB, err := startObjectPullServer(serviceB)
	if err != nil {
		t.Fatalf("startObjectPullServer(B): %v", err)
	}
	if listenerB != nil {
		defer listenerB.Close()
	}
	serviceA.objectPullPool.Start(ctx)
	defer serviceA.objectPullPool.Stop()
	serviceB.objectPullPool.Start(ctx)
	defer serviceB.objectPullPool.Stop()

	// Start sessions in both directions through the event-loop timer handler.
	if err := serviceA.handleSyncTimerEvent(ctx, true); err != nil {
		t.Fatalf("handleSyncTimerEvent(A): %v", err)
	}
	if err := serviceB.handleSyncTimerEvent(ctx, true); err != nil {
		t.Fatalf("handleSyncTimerEvent(B): %v", err)
	}

	// Pump events, then advance the fake clock to fire any pending timers
	// (e.g. packet-quiet timeouts that trigger object pull). Repeat until all
	// sessions have completed.
	for {
		pumpEventLoopSync(ctx, []*DaemonService{serviceA, serviceB}, []*gossip.Transport{transportA, transportB})
		aActive := false
		if s, ok := serviceA.syncSessions[configB.PeerID]; ok && !s.Done() {
			aActive = true
		}
		bActive := false
		if s, ok := serviceB.syncSessions[configA.PeerID]; ok && !s.Done() {
			bActive = true
		}
		if !aActive && !bActive {
			break
		}
		fc.Advance(5 * time.Second)
	}

	if _, ok := serviceA.syncSessions[configB.PeerID]; ok {
		t.Fatalf("session for B still active on A")
	}
	if _, ok := serviceB.syncSessions[configA.PeerID]; ok {
		t.Fatalf("session for A still active on B")
	}

	latestA, err := rtA.LoadState()
	if err != nil {
		t.Fatalf("LoadState(A): %v", err)
	}
	latestB, err := rtB.LoadState()
	if err != nil {
		t.Fatalf("LoadState(B): %v", err)
	}
	if latestA.Network.Zones["node-b.catofes."] == nil || latestA.Network.Zones["node-b.catofes."].Records["event-loop-test"] == nil {
		t.Fatalf("record from B did not appear on A")
	}
	if latestB.Network.Zones["node-a.catofes."] == nil || latestB.Network.Zones["node-a.catofes."].Records["event-loop-test"] == nil {
		t.Fatalf("record from A did not appear on B")
	}
}

func TestDaemonEventLoopResponderDoesNotStealActiveSession(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(1000, 0)
	rt := &Runtime{
		Config:    defaultAppConfig(),
		StatePath: filepath.Join(t.TempDir(), "state.db"),
		Clock:     func() time.Time { return now },
	}
	service := newDaemonService(rt, state, config, time.Second)
	service.EnableEventLoopSync(newFakeClock(now))

	peerID := "peer-a"
	session := NewSyncSession(peerID)
	_, _ = session.OnEvent(&SyncTimerEvent{
		PeerID:       peerID,
		LocalSummary: &gossip.CatalogSummary{CatalogRoot: gossip.CatalogRoot(nil), ZoneCount: 0},
	}, now)
	if session.State != SyncSessionSummarySent {
		t.Fatalf("expected setup state summary_sent, got %s", session.State)
	}
	service.syncSessions[peerID] = session

	err := service.processPacketEvent(&gossip.Packet{Message: &gossip.Message{
		Type:             gossip.MessageFetchCatalogPage,
		PeerID:           peerID,
		FetchCatalogPage: &gossip.FetchCatalogPage{},
	}}, context.Background())
	if err != nil {
		t.Fatalf("process fetch catalog page: %v", err)
	}
	if session.State != SyncSessionSummarySent {
		t.Fatalf("fetch catalog page changed active session state to %s", session.State)
	}
	if got := len(service.syncEvents); got != 0 {
		t.Fatalf("fetch catalog page queued %d sync events, want none", got)
	}

	err = service.processPacketEvent(&gossip.Packet{Message: &gossip.Message{
		Type:      gossip.MessageFetchZone,
		PeerID:    peerID,
		FetchZone: &gossip.FetchZone{Zone: "catofes."},
	}}, context.Background())
	if err != nil {
		t.Fatalf("process fetch zone: %v", err)
	}
	if session.State != SyncSessionSummarySent {
		t.Fatalf("fetch zone changed active session state to %s", session.State)
	}
	if got := len(service.syncEvents); got != 0 {
		t.Fatalf("fetch zone queued %d sync events, want none", got)
	}
}

func TestDaemonEventLoopAnnounceIsHint(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(1000, 0)
	rt := &Runtime{
		Config:    defaultAppConfig(),
		StatePath: filepath.Join(t.TempDir(), "state.db"),
		Clock:     func() time.Time { return now },
	}
	service := newDaemonService(rt, state, config, time.Second)
	service.EnableEventLoopSync(newFakeClock(now))

	record, err := buildSignedRecordAt(state, "node-b.catofes.", "announce-hint-test", []byte("do-not-apply-directly"), "policy.string", now)
	if err != nil {
		t.Fatalf("buildSignedRecordAt: %v", err)
	}
	err = service.processPacketEvent(&gossip.Packet{Message: &gossip.Message{
		Type:   gossip.MessageAnnounce,
		PeerID: "peer-a",
		Announce: &gossip.Announce{Records: []gossip.RecordSnapshot{{
			Zone:   "node-b.catofes.",
			Record: record,
		}}},
	}}, context.Background())
	if err != nil {
		t.Fatalf("process announce: %v", err)
	}
	if state.Network.Zones["node-b.catofes."].Records["announce-hint-test"] != nil {
		t.Fatal("announce record was applied directly; want hint-only ingress")
	}
	session := service.syncSessions["peer-a"]
	if session == nil || session.State != SyncSessionIdle {
		t.Fatalf("announce hint session = %+v, want idle session queued for active pull", session)
	}
	if got := len(service.syncEvents); got != 1 {
		t.Fatalf("announce hint queued %d events, want one sync timer", got)
	}
	ev := <-service.syncEvents
	timer, ok := ev.(*SyncTimerEvent)
	if !ok {
		t.Fatalf("announce hint event = %T, want SyncTimerEvent", ev)
	}
	if timer.PeerID != "peer-a" || timer.LocalSummary == nil {
		t.Fatalf("announce hint timer = %+v, want peer-a with local summary", timer)
	}
}

func TestDaemonEventLoopAnnounceDoesNotStealActiveSession(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(1000, 0)
	rt := &Runtime{
		Config:    defaultAppConfig(),
		StatePath: filepath.Join(t.TempDir(), "state.db"),
		Clock:     func() time.Time { return now },
	}
	service := newDaemonService(rt, state, config, time.Second)
	service.EnableEventLoopSync(newFakeClock(now))

	peerID := "peer-a"
	session := NewSyncSession(peerID)
	_, _ = session.OnEvent(&SyncTimerEvent{
		PeerID:       peerID,
		LocalSummary: &gossip.CatalogSummary{CatalogRoot: gossip.CatalogRoot(nil), ZoneCount: 0},
	}, now)
	if session.State != SyncSessionSummarySent {
		t.Fatalf("expected setup state summary_sent, got %s", session.State)
	}
	service.syncSessions[peerID] = session

	err := service.processPacketEvent(&gossip.Packet{Message: &gossip.Message{
		Type:     gossip.MessageAnnounce,
		PeerID:   peerID,
		Announce: &gossip.Announce{},
	}}, context.Background())
	if err != nil {
		t.Fatalf("process announce: %v", err)
	}
	if session.State != SyncSessionSummarySent {
		t.Fatalf("announce changed active session state to %s", session.State)
	}
	if got := len(service.syncEvents); got != 0 {
		t.Fatalf("active announce queued %d sync events, want none", got)
	}
	if !service.pendingSyncHints[peerID] {
		t.Fatal("active announce did not record a follow-up hint")
	}
	session.State = SyncSessionCompleted
	service.completeSyncSession(session, false)
	if service.pendingSyncHints[peerID] {
		t.Fatal("follow-up hint was not consumed after session completion")
	}
	if got := len(service.syncEvents); got != 1 {
		t.Fatalf("follow-up hint queued %d sync events, want one", got)
	}
	ev := <-service.syncEvents
	timer, ok := ev.(*SyncTimerEvent)
	if !ok {
		t.Fatalf("follow-up hint event = %T, want SyncTimerEvent", ev)
	}
	if timer.PeerID != peerID || timer.LocalSummary == nil {
		t.Fatalf("follow-up hint timer = %+v, want peer with local summary", timer)
	}
}

func pumpEventLoopSync(ctx context.Context, services []*DaemonService, transports []*gossip.Transport) {
	for {
		processed := false
		for _, svc := range services {
			if !svc.eventLoopSync {
				continue
			}
			select {
			case ev := <-svc.syncEvents:
				svc.handleSyncEvent(ctx, ev)
				processed = true
			default:
			}
			select {
			case res := <-svc.objectPullResults:
				_ = svc.postSyncEvent(objectPullResultToEvent(res))
				processed = true
			default:
			}
		}
		for i, tr := range transports {
			packet, err := receiveWithContext(ctx, tr, time.Now().Add(10*time.Millisecond))
			if err == nil {
				services[i].handlePacketEvent(packet, ctx)
				processed = true
			}
		}
		if !processed {
			return
		}
	}
}
