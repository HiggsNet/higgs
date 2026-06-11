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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Catofes/higgs/pkg/core/zone"
	"github.com/Catofes/higgs/pkg/transport/ipsec"
)

func TestNewDaemonServiceDefaultsInterval(t *testing.T) {
	service := newDaemonService(&Runtime{}, &stateFile{}, &syncConfigFile{}, 0)
	if service.Interval != 5*time.Second {
		t.Fatalf("default interval = %s, want 5s", service.Interval)
	}
	if service.Sync == nil {
		t.Fatal("sync runtime is nil")
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
	addTestIPsecRecords(t, state.Network.Zones["node-b.catofes."], "node-b.catofes.", now)
	appConfig := defaultAppConfig()
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{{
		ID:                 "main",
		Provider:           ipsec.ProviderStrongSwan,
		NetNS:              ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: "h2", Create: true},
		DefaultPathMode:    ipsec.PathModeFamilyRedundant,
		Direction:          ipsec.DirectionOutbound,
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

func TestDaemonReconcileUsesSystemXFRMDriverSmoke(t *testing.T) {
	if os.Getenv("HIGGS_IPSEC_XFRM_SMOKE") != "1" {
		t.Skip("set HIGGS_IPSEC_XFRM_SMOKE=1 to run the root/system XFRM smoke")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	state, config := buildTestNetworkState(t)
	now := time.Unix(4060, 0)
	addTestIPsecRecords(t, state.Network.Zones["node-b.catofes."], "node-b.catofes.", now)

	ns := "higgs-daemon-xfrm-" + time.Now().UTC().Format("20060102150405")
	group := testIPsecLinkGroup()
	group.NetNS = ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: ns, Create: true}
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
	service.flushIPsecReconcile(ctx)

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
	service.flushIPsecReconcile(ctx)
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

func TestDaemonStateChangedRemovesTeardownIPsecLinks(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(4050, 0)
	addTestIPsecRecords(t, state.Network.Zones["node-b.catofes."], "node-b.catofes.", now)
	appConfig := defaultAppConfig()
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{{
		ID:                 "main",
		Provider:           ipsec.ProviderStrongSwan,
		NetNS:              ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: "h2", Create: true},
		DefaultPathMode:    ipsec.PathModeFamilyRedundant,
		Direction:          ipsec.DirectionOutbound,
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
	addTestIPsecRecords(t, state.Network.Zones["node-b.catofes."], "node-b.catofes.", now)
	appConfig := defaultAppConfig()
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{{
		ID:                 "main",
		Provider:           ipsec.ProviderStrongSwan,
		NetNS:              ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: "h2", Create: true},
		DefaultPathMode:    ipsec.PathModeFamilyRedundant,
		Direction:          ipsec.DirectionOutbound,
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
	if err := writeDebugLinks(&out, rt, latest); err != nil {
		t.Fatalf("writeDebugLinks: %v", err)
	}
	output := out.String()
	for _, want := range []string{
		"planned_desired_links: 1",
		"actual_sas: 1",
		"desired_hash=",
		"if_id=",
		"sa=established",
		"sa_remote=198.51.100.20",
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
	addTestIPsecRecords(t, state.Network.Zones["node-b.catofes."], "node-b.catofes.", now)
	appConfig := defaultAppConfig()
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{{
		ID:                 "main",
		Provider:           ipsec.ProviderStrongSwan,
		NetNS:              ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: "h2", Create: true},
		DefaultPathMode:    ipsec.PathModeFamilyRedundant,
		Direction:          ipsec.DirectionOutbound,
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

func TestDaemonDryRunABIPsecSmokeCoversBringupAndSAObservation(t *testing.T) {
	now := time.Unix(4130, 0)
	stateA, configA := buildTestNetworkState(t)
	stateA.Network.Zones["node-a.catofes."] = zone.NewZoneState("node-a.catofes.", nil)
	addTestIPsecRecords(t, stateA.Network.Zones["node-a.catofes."], "node-a.catofes.", now)
	addTestIPsecRecords(t, stateA.Network.Zones["node-b.catofes."], "node-b.catofes.", now)
	group := testIPsecLinkGroup()
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

	stateB := *stateA
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
	if err := rtB.SaveState(&stateB); err != nil {
		t.Fatalf("SaveState(node-b): %v", err)
	}
	driverB := &observedIPsecDriver{}
	serviceB := newDaemonService(rtB, &stateB, &configB, time.Second)
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
	assertStrongSwanLoadConnMatchesSpec(t, specB)
	if specA.PeerZone != "node-b.catofes." || specB.PeerZone != "node-a.catofes." {
		t.Fatalf("A/B peer zones = %s/%s", specA.PeerZone, specB.PeerZone)
	}
	if specA.TransportID == specB.TransportID || specA.XFRMIfID == specB.XFRMIfID {
		t.Fatalf("A/B links should use direction-specific transport identity: A=%+v B=%+v", specA, specB)
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
	if err := writeDebugLinks(&out, rtA, latestA); err != nil {
		t.Fatalf("writeDebugLinks(node-a): %v", err)
	}
	output := out.String()
	for _, want := range []string{
		"state=up",
		"sa=established",
		"sa_local_id=node-a.catofes.",
		"sa_remote_id=node-b.catofes.",
		"sa_reqid=1001",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("debug links output missing %q:\n%s", want, output)
		}
	}
}

func TestDaemonStartupRepairsMissingObservedSA(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(4135, 0)
	addTestIPsecRecords(t, state.Network.Zones["node-b.catofes."], "node-b.catofes.", now)
	group := testIPsecLinkGroup()
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

func TestDaemonRevocationTearsDownIPsecLinkAndBlocksRecreate(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(4140, 0)
	addTestIPsecRecords(t, state.Network.Zones["node-b.catofes."], "node-b.catofes.", now)
	group := testIPsecLinkGroup()
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
	addTestIPsecRecords(t, state.Network.Zones["node-b.catofes."], "node-b.catofes.", now)
	appConfig := defaultAppConfig()
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{{
		ID:                 "main",
		Provider:           ipsec.ProviderStrongSwan,
		NetNS:              ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: "h2", Create: true},
		DefaultPathMode:    ipsec.PathModeFamilyRedundant,
		Direction:          ipsec.DirectionOutbound,
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

	syncNow, shutdown := service.processEvents(context.Background())
	if !syncNow || shutdown {
		t.Fatalf("syncNow/shutdown = %v/%v, want true/false", syncNow, shutdown)
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

func TestDaemonReloadConfigReconcilesIPsecLinkGroups(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(4200, 0)
	addTestIPsecRecords(t, state.Network.Zones["node-b.catofes."], "node-b.catofes.", now)
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
		"overlays:",
		"  - id: main",
		"    provider: strongswan",
		"    netns:",
		"      name: h2",
		"      create: true",
		"    default_path_mode: family-redundant",
		"    direction: outbound",
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
	sas       []ipsec.SAState
	listCalls int
}

func (d *observedIPsecDriver) ListSAs(context.Context) ([]ipsec.SAState, error) {
	d.listCalls++
	return d.sas, nil
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
		Direction:          ipsec.DirectionOutbound,
		AddressSourceOrder: []string{ipsec.SourceManualAddress},
		TunnelAddressPool:  netip.MustParsePrefix("10.44.0.0/29"),
		ConnectRules:       []string{"strongswan://node-*.catofes.?accept=inbound"},
	}
}

func singleDesiredSpec(t *testing.T, state *stateFile) ipsec.TransportLinkSpec {
	t.Helper()
	if state == nil || state.IPsecReconcile == nil || len(state.IPsecReconcile.Desired) != 1 {
		t.Fatalf("desired snapshot = %+v, want one desired link", state.IPsecReconcile)
	}
	desired := state.IPsecReconcile.Desired[0]
	return ipsec.TransportLinkSpec{
		LocalZone:       state.ManagedZone,
		PeerZone:        desired.PeerZone,
		OverlayID:       desired.GroupID,
		Provider:        ipsec.ProviderStrongSwan,
		TransportID:     desired.TransportID,
		InterfaceName:   desired.InterfaceName,
		XFRMIfID:        desired.XFRMIfID,
		LocalTunnelAddr: netip.MustParseAddr("10.44.0.1"),
		PeerTunnelAddr:  netip.MustParseAddr("10.44.0.2"),
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
	if got := conn["remote_port"]; got != "500" {
		t.Fatalf("remote_port = %#v, want 500", got)
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

func addTestIPsecRecords(t *testing.T, zs *zone.ZoneState, peer zone.ZonePath, now time.Time) {
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
		Accept:                  ipsec.AcceptInbound,
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
	catofesIssue, err := service.handleDelegateIssueEvent(&joinRequest{Version: 1, Zone: "catofes.", PublicKey: catofesPub})
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
	if _, err := service.handleDelegateIssueEvent(&joinRequest{Version: 1, Zone: "node-b.catofes.", PublicKey: nodeBPub}); err != nil {
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

func TestDaemonControlErrorResponses(t *testing.T) {
	state, config := buildTestNetworkState(t)
	service := newDaemonService(&Runtime{Config: defaultAppConfig()}, state, config, time.Second)

	response := controlRequestViaPipe(t, service, controlRequest{Method: "record_put", Zone: "node-b.catofes."})
	if response.OK || response.Error == "" {
		t.Fatalf("invalid record_put response = %#v, want error", response)
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
