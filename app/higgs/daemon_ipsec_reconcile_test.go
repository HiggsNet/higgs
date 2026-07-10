package main

import (
	"context"
	"github.com/Catofes/higgs/pkg/core/zone"
	"github.com/Catofes/higgs/pkg/transport/ipsec"
	"net/netip"
	"path/filepath"
	"testing"
	"time"
)

func TestDaemonStateChangedReconcilesIPsecLinks(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(4000, 0)
	addTestIPsecRecords(t, state.Network.Zones["node-b.catofes."], "node-b.catofes.", now, ipsec.RoleIn)
	appConfig := defaultAppConfig()
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{{
		ID:                 "main",
		Provider:           ipsec.ProviderStrongSwan,
		NetNS:              ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: "higgstesth2", Create: true},
		DefaultPathMode:    ipsec.PathModeFamilyRedundant,
		AddressSourceOrder: []string{ipsec.SourceManualAddress},
		ConnectRules:       []string{"strongswan://*.catofes.?role=in"},
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

func TestMaintainExistingXFRMInterfacesSkipsNoopUpLinkWhenMatched(t *testing.T) {
	spec := ipsec.TransportLinkSpec{
		TransportID:     "ipsec-main-ab",
		InterfaceName:   "hgs1",
		XFRMIfID:        42,
		NetNS:           "higgstesth2",
		LocalTunnelAddr: netip.MustParseAddr("fe80::1"),
	}
	inst := ipsec.NewLinkInstance(spec, ipsec.LinkStateUp, time.Unix(4000, 0))
	driver := &observedIPsecDriver{}
	service := &DaemonService{}

	if err := service.maintainExistingXFRMInterfaces(context.Background(), driver, []ipsec.TransportLinkSpec{spec}, map[string]ipsec.LinkInstance{inst.ID: inst}, []ipsec.ReconcileAction{{Action: ipsec.ReconcileActionNoop, Instance: &inst}}, nil, nil); err != nil {
		t.Fatalf("maintainExistingXFRMInterfaces: %v", err)
	}
	if len(driver.Interfaces) != 0 {
		t.Fatalf("interfaces = %+v, want no redundant maintenance when state matches", driver.Interfaces)
	}
	if len(driver.Addresses) != 0 {
		t.Fatalf("addresses = %+v, want no redundant maintenance when state matches", driver.Addresses)
	}
}

func TestMaintainExistingXFRMInterfacesUsesRuntimeAddressDuringRotate(t *testing.T) {
	group := ipsec.LinkGroupSpec{ID: "main"}
	base := ipsec.TransportLinkSpec{
		LocalZone: "node-a.catofes.",
		PeerZone:  "node-b.catofes.",
		OverlayID: "main",
		Provider:  ipsec.ProviderStrongSwan,
		LinkID:    "link-stable",
		NetNS:     "higgstesth2",
	}
	desired, err := ipsec.RuntimeSpecForPortGeneration(base, group, 2)
	if err != nil {
		t.Fatalf("RuntimeSpecForPortGeneration(desired): %v", err)
	}
	oldRuntime, err := ipsec.RuntimeSpecForPortGeneration(base, group, 1)
	if err != nil {
		t.Fatalf("RuntimeSpecForPortGeneration(old): %v", err)
	}
	inst := ipsec.NewLinkInstance(oldRuntime, ipsec.LinkStateUp, time.Unix(4000, 0))
	inst.RemoteGeneration = 1
	inst.RotatePhase = ipsec.RotatePhaseDualRunning
	inst.StagedIKEName = desired.TransportID
	inst.StagedInterfaceName = desired.InterfaceName
	inst.StagedXFRMIfID = desired.XFRMIfID
	inst.StagedLocalTunnelAddr = desired.LocalTunnelAddr
	inst.StagedPeerTunnelAddr = desired.PeerTunnelAddr
	inst.LocalTunnelAddr = desired.LocalTunnelAddr
	inst.PeerTunnelAddr = desired.PeerTunnelAddr
	driver := &observedIPsecDriver{
		linkState: &ipsec.XFRMLinkState{
			NetNS:           ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: "higgstesth2"}.Normalized(),
			NamespaceExists: true,
			InterfaceExists: true,
			FlagsKnown:      true,
			InterfaceUp:     false,
			Multicast:       true,
		},
	}
	service := &DaemonService{}

	if err := service.maintainExistingXFRMInterfaces(context.Background(), driver, []ipsec.TransportLinkSpec{desired}, map[string]ipsec.LinkInstance{inst.ID: inst}, []ipsec.ReconcileAction{{Action: ipsec.ReconcileActionNoop, Reason: "route_cutover_pending", Instance: &inst}}, []ipsec.LinkGroupSpec{group}, nil); err != nil {
		t.Fatalf("maintainExistingXFRMInterfaces: %v", err)
	}
	if len(driver.Interfaces) != 1 || driver.Interfaces[0].InterfaceName != oldRuntime.InterfaceName {
		t.Fatalf("interfaces = %+v, want old runtime interface maintenance", driver.Interfaces)
	}
	wantAddress := oldRuntime.InterfaceName + "=" + netip.PrefixFrom(oldRuntime.LocalTunnelAddr, 64).String()
	if len(driver.Addresses) != 1 || driver.Addresses[0] != wantAddress {
		t.Fatalf("addresses = %+v, want old runtime address preserved", driver.Addresses)
	}
}

func TestMaintainExistingXFRMInterfacesSkipsAdoptedLinkWhenMatched(t *testing.T) {
	spec := ipsec.TransportLinkSpec{
		TransportID:     "ipsec-main-ab",
		InterfaceName:   "hgs1",
		XFRMIfID:        42,
		NetNS:           "higgstesth2",
		LocalTunnelAddr: netip.MustParseAddr("fe80::1"),
	}
	inst := ipsec.NewLinkInstance(spec, ipsec.LinkStateUp, time.Unix(4000, 0))
	driver := &observedIPsecDriver{}
	service := &DaemonService{}

	if err := service.maintainExistingXFRMInterfaces(context.Background(), driver, []ipsec.TransportLinkSpec{spec}, map[string]ipsec.LinkInstance{inst.ID: inst}, []ipsec.ReconcileAction{{Action: ipsec.ReconcileActionAdopt, Spec: &spec, Instance: &inst}}, nil, nil); err != nil {
		t.Fatalf("maintainExistingXFRMInterfaces: %v", err)
	}
	if len(driver.Interfaces) != 0 {
		t.Fatalf("interfaces = %+v, want no redundant maintenance when state matches", driver.Interfaces)
	}
	if len(driver.Addresses) != 0 {
		t.Fatalf("addresses = %+v, want no redundant maintenance when state matches", driver.Addresses)
	}
}

func TestMaintainExistingXFRMInterfacesSkipsLinkWithActiveAction(t *testing.T) {
	spec := ipsec.TransportLinkSpec{
		TransportID:     "ipsec-main-ab",
		InterfaceName:   "hgs1",
		XFRMIfID:        42,
		NetNS:           "higgstesth2",
		LocalTunnelAddr: netip.MustParseAddr("fd00::1"),
	}
	inst := ipsec.NewLinkInstance(spec, ipsec.LinkStateConnecting, time.Unix(4000, 0))
	driver := &observedIPsecDriver{}
	service := &DaemonService{}

	if err := service.maintainExistingXFRMInterfaces(context.Background(), driver, []ipsec.TransportLinkSpec{spec}, map[string]ipsec.LinkInstance{inst.ID: inst}, []ipsec.ReconcileAction{{Action: ipsec.ReconcileActionCreate, Spec: &spec}}, nil, nil); err != nil {
		t.Fatalf("maintainExistingXFRMInterfaces: %v", err)
	}
	if len(driver.Interfaces) != 0 || len(driver.Addresses) != 0 {
		t.Fatalf("maintenance ran despite active action: interfaces=%+v addresses=%+v", driver.Interfaces, driver.Addresses)
	}
}

func TestDaemonIPsecReconcileMergesInstanceWhenRevisionChanged(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(4050, 0)
	addTestIPsecRecords(t, state.Network.Zones["node-b.catofes."], "node-b.catofes.", now, ipsec.RoleIn)
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
	service := newDaemonService(rt, state, config, time.Second)
	baseRev := service.StateStore.Meta().Revision
	driver := &staleCommitIPsecDriver{}
	driver.onLoadConnection = func(ipsec.TransportLinkSpec) {
		if _, err := service.StateStore.Update(func(state *stateFile) error {
			state.IdentityKeyPath = "newer-revision"
			return nil
		}); err != nil {
			t.Fatalf("advance state revision during apply: %v", err)
		}
	}
	service.IPsecDriver = driver
	service.XFRMDriver = driver

	if err := service.reconcileIPsecLinks(context.Background()); err != nil {
		t.Fatalf("reconcileIPsecLinks: %v", err)
	}
	if service.ipsecDirty {
		t.Fatal("ipsecDirty = true, want token-compatible instance merge to complete")
	}
	snapshot, _ := service.StateStore.Snapshot()
	if snapshot.IdentityKeyPath != "newer-revision" {
		t.Fatalf("identity key path = %q, want newer revision preserved", snapshot.IdentityKeyPath)
	}
	if len(snapshot.LinkInstances) != 1 {
		t.Fatalf("link instances = %+v, want stale-revision instance result merged", snapshot.LinkInstances)
	}
	if snapshot.IPsecReconcile == nil {
		t.Fatal("ipsec reconcile summary missing")
	}
	if snapshot.IPsecReconcile.SourceRevision != baseRev || snapshot.IPsecReconcile.Stale || !snapshot.IPsecReconcile.Committed {
		t.Fatalf("ipsec reconcile summary = %+v, want committed summary for source revision %d", snapshot.IPsecReconcile, baseRev)
	}
}

func TestDaemonIPsecReconcileStaleInstanceTokenDoesNotOverwriteCurrent(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(4055, 0)
	addTestIPsecRecords(t, state.Network.Zones["node-b.catofes."], "node-b.catofes.", now, ipsec.RoleIn)
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
	service := newDaemonService(rt, state, config, time.Second)
	baseRev := service.StateStore.Meta().Revision
	driver := &staleCommitIPsecDriver{}
	driver.onLoadConnection = func(spec ipsec.TransportLinkSpec) {
		id := ipsec.LinkInstanceID(spec)
		if _, err := service.StateStore.Update(func(state *stateFile) error {
			state.LinkInstances = map[string]linkInstanceState{
				id: {ID: id, Owner: linkOwnerState{Token: "new-owner-token"}},
			}
			return nil
		}); err != nil {
			t.Fatalf("advance state revision during apply: %v", err)
		}
	}
	service.IPsecDriver = driver
	service.XFRMDriver = driver

	if err := service.reconcileIPsecLinks(context.Background()); err != nil {
		t.Fatalf("reconcileIPsecLinks: %v", err)
	}
	if !service.ipsecDirty {
		t.Fatal("ipsecDirty = false, want stale token conflict to schedule another reconcile")
	}
	snapshot, _ := service.StateStore.Snapshot()
	if len(snapshot.LinkInstances) != 1 {
		t.Fatalf("link instances = %+v, want current conflicting instance preserved", snapshot.LinkInstances)
	}
	for _, inst := range snapshot.LinkInstances {
		if inst.Owner.Token != "new-owner-token" {
			t.Fatalf("link instance owner token = %q, want current conflicting token preserved", inst.Owner.Token)
		}
	}
	if snapshot.IPsecReconcile == nil {
		t.Fatal("ipsec reconcile summary missing, want stale diagnostic")
	}
	if snapshot.IPsecReconcile.SourceRevision != baseRev || !snapshot.IPsecReconcile.Stale || snapshot.IPsecReconcile.Committed {
		t.Fatalf("ipsec reconcile summary = %+v, want stale diagnostic for source revision %d", snapshot.IPsecReconcile, baseRev)
	}
}

func TestLongIPsecReconcileDoesNotBlockCommittedReaders(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(4060, 0)
	addTestIPsecRecords(t, state.Network.Zones["node-b.catofes."], "node-b.catofes.", now, ipsec.RoleIn)
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
	service := newDaemonService(rt, state, config, time.Second)
	started := make(chan struct{})
	unblock := make(chan struct{})
	driver := &staleCommitIPsecDriver{}
	driver.onLoadConnection = func(ipsec.TransportLinkSpec) {
		close(started)
		<-unblock
	}
	service.IPsecDriver = driver
	service.XFRMDriver = driver

	done := make(chan error, 1)
	go func() {
		done <- service.reconcileIPsecLinks(context.Background())
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		close(unblock)
		t.Fatal("ipsec reconcile did not enter blocking LoadConnection")
	}

	committedRev := service.StateStore.Meta().Revision
	statusDone := make(chan controlResponse, 1)
	go func() {
		statusDone <- controlRequestViaPipe(t, service, controlRequest{Method: "status"})
	}()
	select {
	case status := <-statusDone:
		if !status.OK || status.StateRevision != committedRev {
			close(unblock)
			t.Fatalf("status response = %#v, want committed revision %d", status, committedRev)
		}
	case <-time.After(time.Second):
		close(unblock)
		t.Fatal("control status blocked behind IPsec reconcile apply")
	}

	linksDone := make(chan controlResponse, 1)
	go func() {
		linksDone <- controlRequestViaPipe(t, service, controlRequest{Method: "links_status"})
	}()
	select {
	case links := <-linksDone:
		if !links.OK || links.StateRevision != committedRev {
			close(unblock)
			t.Fatalf("links_status response = %#v, want committed revision %d", links, committedRev)
		}
	case <-time.After(time.Second):
		close(unblock)
		t.Fatal("links_status blocked behind IPsec reconcile apply")
	}

	close(unblock)
	if err := <-done; err != nil {
		t.Fatalf("reconcileIPsecLinks: %v", err)
	}
}

func TestDaemonStateChangedReconcilesIPsecPortRotation(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(4000, 0)
	state.Network.Zones["node-a.catofes."] = zone.NewZoneState("node-a.catofes.", nil)
	addTestIPsecRecords(t, state.Network.Zones["node-a.catofes."], "node-a.catofes.", now, ipsec.RoleOut)
	addTestIPsecRecords(t, state.Network.Zones["node-b.catofes."], "node-b.catofes.", now, ipsec.RoleIn)
	appConfig := defaultAppConfig()
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{{
		ID:                 "main",
		Provider:           ipsec.ProviderStrongSwan,
		NetNS:              ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: "higgstesth2", Create: true},
		DefaultPathMode:    ipsec.PathModeFamilyRedundant,
		AddressSourceOrder: []string{ipsec.SourceManualAddress},
		ConnectRules:       []string{"strongswan://*.catofes.?role=in"},
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

func TestDaemonProcessEventsCoalescesIPsecReconcile(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(4150, 0)
	addTestIPsecRecords(t, state.Network.Zones["node-b.catofes."], "node-b.catofes.", now, ipsec.RoleIn)
	appConfig := defaultAppConfig()
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{{
		ID:                 "main",
		Provider:           ipsec.ProviderStrongSwan,
		NetNS:              ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: "higgstesth2", Create: true},
		DefaultPathMode:    ipsec.PathModeFamilyRedundant,
		AddressSourceOrder: []string{ipsec.SourceManualAddress},
		ConnectRules:       []string{"strongswan://*.catofes.?role=in"},
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
	addTestIPsecRecords(t, state.Network.Zones["node-b.catofes."], "node-b.catofes.", now, ipsec.RoleIn)
	appConfig := defaultAppConfig()
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{{
		ID:                 "main",
		Provider:           ipsec.ProviderStrongSwan,
		NetNS:              ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: "higgstesth2", Create: true},
		DefaultPathMode:    ipsec.PathModeFamilyRedundant,
		AddressSourceOrder: []string{ipsec.SourceManualAddress},
		ConnectRules:       []string{"strongswan://*.catofes.?role=in"},
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

	if _, err := service.StateStore.Update(func(state *stateFile) error {
		state.LinkInstances = map[string]linkInstanceState{"stale": {ID: "stale"}}
		return nil
	}); err != nil {
		t.Fatalf("StateStore.Update(stale links): %v", err)
	}
	if interval := service.ipsecReconcileInterval(); interval != defaultIPsecReconcileInterval {
		t.Fatalf("interval with stale instances = %s, want %s", interval, defaultIPsecReconcileInterval)
	}
	if _, err := service.StateStore.Update(func(state *stateFile) error {
		state.LinkInstances = nil
		return nil
	}); err != nil {
		t.Fatalf("StateStore.Update(clear links): %v", err)
	}

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
