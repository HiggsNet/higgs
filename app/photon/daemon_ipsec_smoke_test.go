package main

import (
	"bytes"
	"context"
	"github.com/HiggsNet/photon/pkg/core/gossip"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDaemonReconcileUsesSystemXFRMDriverSmoke(t *testing.T) {
	if os.Getenv("PHOTON_IPSEC_XFRM_SMOKE") != "1" {
		t.Skip("set PHOTON_IPSEC_XFRM_SMOKE=1 to run the root/system XFRM smoke")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	state, config := buildTestNetworkState(t)
	now := time.Unix(4060, 0)
	addTestIPsecRecords(t, state.Network.Zones["node-b.catofes."], "node-b.catofes.", now, ipsec.RoleIn)

	ns := "photon-daemon-xfrm-" + time.Now().UTC().Format("20060102150405")
	group := testIPsecLinkGroup()
	group.NetNS = ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: ns, Create: true}
	setTestIPsecOverlayIntent(t, state.Network.Zones["node-b.catofes."], "node-b.catofes.", group, now)
	appConfig := defaultAppConfig()
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{group}
	rt := &Runtime{
		Config:    appConfig,
		StatePath: filepath.Join(t.TempDir(), "photon.db"),
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
	if os.Getenv("PHOTON_IPSEC_XFRM_SMOKE") != "1" {
		t.Skip("set PHOTON_IPSEC_XFRM_SMOKE=1 to run the root/system StrongSwan daemon smoke")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 70*time.Second)
	defer cancel()

	suffix := time.Now().UTC().Format("20060102150405")
	nsA := "photon-daemon-ike-a-" + suffix
	nsB := "photon-daemon-ike-b-" + suffix
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
	logA, err := os.CreateTemp("", "photon-daemon-charon-a-*.log")
	if err != nil {
		t.Fatalf("create charon A log: %v", err)
	}
	logB, err := os.CreateTemp("", "photon-daemon-charon-b-*.log")
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
	addDaemonTestIPsecRecords(t, stateA.Network.Zones["node-a.catofes."], "node-a.catofes.", "192.0.2.1", recordA, ipsec.RoleOut, now)
	addDaemonTestIPsecRecords(t, stateB.Network.Zones["node-b.catofes."], "node-b.catofes.", "192.0.2.2", recordB, ipsec.RoleIn, now)
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
	if os.Getenv("PHOTON_IPSEC_XFRM_SMOKE") != "1" {
		t.Skip("set PHOTON_IPSEC_XFRM_SMOKE=1 to run the root/system StrongSwan daemon smoke")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 70*time.Second)
	defer cancel()

	suffix := time.Now().UTC().Format("20060102150405")
	nsA := "photon-daemon-pool-a-" + suffix
	nsB := "photon-daemon-pool-b-" + suffix
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
	logA, err := os.CreateTemp("", "photon-daemon-charon-pool-a-*.log")
	if err != nil {
		t.Fatalf("create charon A log: %v", err)
	}
	logB, err := os.CreateTemp("", "photon-daemon-charon-pool-b-*.log")
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
	addDaemonTestIPsecRecords(t, stateA.Network.Zones["node-a.catofes."], "node-a.catofes.", "192.0.2.1", recordA, ipsec.RoleOut, now)
	addDaemonTestIPsecRecords(t, stateB.Network.Zones["node-b.catofes."], "node-b.catofes.", "192.0.2.2", recordB, ipsec.RoleIn, now)
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
	if os.Getenv("PHOTON_IPSEC_XFRM_SMOKE") != "1" {
		t.Skip("set PHOTON_IPSEC_XFRM_SMOKE=1 to run the root/system StrongSwan port rotation smoke")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	suffix := time.Now().UTC().Format("20060102150405")
	nsA := "photon-daemon-rot-a-" + suffix
	nsB := "photon-daemon-rot-b-" + suffix
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
	logA, err := os.CreateTemp("", "photon-daemon-charon-rot-a-*.log")
	if err != nil {
		t.Fatalf("create charon A log: %v", err)
	}
	logB, err := os.CreateTemp("", "photon-daemon-charon-rot-b-*.log")
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
	addDaemonTestIPsecRecords(t, stateA.Network.Zones["node-a.catofes."], "node-a.catofes.", "192.0.2.1", recordA, ipsec.RoleOut, now)
	addDaemonTestIPsecRecords(t, stateB.Network.Zones["node-b.catofes."], "node-b.catofes.", "192.0.2.2", recordB, ipsec.RoleIn, now)
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
	if os.Getenv("PHOTON_IPSEC_XFRM_SMOKE") != "1" {
		t.Skip("set PHOTON_IPSEC_XFRM_SMOKE=1 to run the root/system daemon gossip StrongSwan smoke")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	suffix := time.Now().UTC().Format("20060102150405")
	nsA := "photon-daemon-run-a-" + suffix
	nsB := "photon-daemon-run-b-" + suffix
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
	logA, err := os.CreateTemp("", "photon-daemon-run-charon-a-*.log")
	if err != nil {
		t.Fatalf("create charon A log: %v", err)
	}
	logB, err := os.CreateTemp("", "photon-daemon-run-charon-b-*.log")
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
	rtA.Config.IPsec.Role = ipsec.RoleOut
	rtA.Config.ListenAddr = gossipA
	rtB := &Runtime{
		Config:    testDaemonIPsecAppConfig(t.TempDir(), "192.0.2.2:4500", groupB),
		StatePath: filepath.Join(t.TempDir(), "node-b.db"),
		Clock:     time.Now,
	}
	rtB.Config.IPsec.Role = ipsec.RoleIn
	rtB.Config.ListenAddr = gossipB
	if err := rtA.SaveState(stateA); err != nil {
		t.Fatalf("SaveState(node-a): %v", err)
	}
	if err := rtB.SaveState(stateB); err != nil {
		t.Fatalf("SaveState(node-b): %v", err)
	}

	serviceA := newDaemonService(rtA, stateA, configA, 200*time.Millisecond)
	serviceA.ControlSocketPath = filepath.Join(t.TempDir(), controlSocketName)
	serviceA.IPsecDriver = newDaemonTestStrongSwanDriver(t, viciA, clientA)
	serviceA.XFRMDriver = daemonTestXFRMDriver(groupA.NetNS, nsA)
	serviceB := newDaemonService(rtB, stateB, configB, 200*time.Millisecond)
	serviceB.ControlSocketPath = filepath.Join(t.TempDir(), controlSocketName)
	serviceB.IPsecDriver = newDaemonTestStrongSwanDriver(t, viciB, clientB)
	serviceB.XFRMDriver = daemonTestXFRMDriver(groupB.NetNS, nsB)

	runCtx, stopDaemons := context.WithCancel(ctx)
	defer stopDaemons()
	errCh := make(chan error, 2)
	go func() { errCh <- serviceA.Run(runCtx) }()
	go func() { errCh <- serviceB.Run(runCtx) }()
	defer func() {
		stopDaemons()
		for range 2 {
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

func TestDaemonDryRunABIPsecSmokeCoversBringupAndSAObservation(t *testing.T) {
	now := time.Unix(4130, 0)
	stateA, configA := buildTestNetworkState(t)
	stateA.Network.Zones["node-a.catofes."] = zone.NewZoneState("node-a.catofes.", nil)
	addTestIPsecRecords(t, stateA.Network.Zones["node-a.catofes."], "node-a.catofes.", now, ipsec.RoleBoth)
	addTestIPsecRecords(t, stateA.Network.Zones["node-b.catofes."], "node-b.catofes.", now, ipsec.RoleIn)
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
		"      child_start_action: none",
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
	rtA.Config.IPsec.Role = ipsec.RoleIn
	rtB := &Runtime{
		Config:    testDaemonIPsecAppConfig(filepath.Join(t.TempDir(), "b"), "198.51.100.20:4500", group),
		StatePath: filepath.Join(t.TempDir(), "node-b.db"),
		Clock:     time.Now,
	}
	rtB.Config.IPsec.Role = ipsec.RoleIn
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
	serviceA.IPsecDriver = driverA
	serviceA.XFRMDriver = driverA
	serviceB.IPsecDriver = driverB
	serviceB.XFRMDriver = driverB

	tcpAddrA := objectPullTCPAddr(transportA.LocalAddr().String())
	listenerA, err := objectPullTCPServe(tcpAddrA, serviceA.objectPullResponse)
	if err != nil {
		t.Fatalf("objectPullTCPServe(A): %v", err)
	}
	if listenerA != nil {
		defer listenerA.Close()
	}
	tcpAddrB := objectPullTCPAddr(transportB.LocalAddr().String())
	listenerB, err := objectPullTCPServe(tcpAddrB, serviceB.objectPullResponse)
	if err != nil {
		t.Fatalf("objectPullTCPServe(B): %v", err)
	}
	if listenerB != nil {
		defer listenerB.Close()
	}

	if _, err := serviceA.handleEndpointTimerEvent(); err != nil {
		t.Fatalf("publish node-a ipsec records: %v", err)
	}
	if _, err := serviceB.handleEndpointTimerEvent(); err != nil {
		t.Fatalf("publish node-b ipsec records: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	serviceA.objectPullPool.Start(ctx)
	defer serviceA.objectPullPool.Stop()
	serviceB.objectPullPool.Start(ctx)
	defer serviceB.objectPullPool.Stop()

	if err := serviceB.handleSyncTimerEvent(ctx, true); err != nil {
		t.Fatalf("start sync node-b from node-a: %v", err)
	}
	if err := serviceA.handleSyncTimerEvent(ctx, true); err != nil {
		t.Fatalf("start sync node-a from node-b: %v", err)
	}
	for {
		pumpEventLoopSync(ctx, []*DaemonService{serviceA, serviceB}, []*gossip.Transport{transportA, transportB})
		aActive := false
		if s := serviceA.syncEngine.Session(configB.PeerID); s != nil && !s.Done() {
			aActive = true
		}
		bActive := false
		if s := serviceB.syncEngine.Session(configA.PeerID); s != nil && !s.Done() {
			bActive = true
		}
		if !aActive && !bActive {
			break
		}
		if ctx.Err() != nil {
			t.Fatalf("event-loop sync timed out: %v", ctx.Err())
		}
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
