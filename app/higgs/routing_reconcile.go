package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Catofes/higgs/pkg/core/zone"
	"github.com/Catofes/higgs/pkg/firewall"
	"github.com/Catofes/higgs/pkg/health"
	"github.com/Catofes/higgs/pkg/routing"
	"github.com/Catofes/higgs/pkg/routing/bird"
	"github.com/Catofes/higgs/pkg/transport/ipsec"
)

const (
	defaultRoutingReconcileInterval = 30 * time.Second
	birdHealthObservationTimeout    = 2 * time.Second
	birdInstanceStatePending        = "pending"
	birdInstanceStateRunning        = "running"
	birdInstanceStateDegraded       = "degraded"
	birdInstanceStateError          = "error"
	maxRoutingCrashBackoff          = time.Minute
)

var errAutoAnnounceNoChanges = errors.New("auto announce has no changes")

// birdProcessManager is the subset of bird.ProcessManager used by the daemon.
type birdProcessManager interface {
	Start(ctx context.Context, spec bird.BirdInstanceSpec) error
	Stop(ctx context.Context, spec bird.BirdInstanceSpec) error
	IsRunning(ctx context.Context) bool
	LastExit() *bird.ProcessExit
}

// vethManager is the subset of bird.VethManager used by the daemon.
type vethManager interface {
	EnsureVethPair(ctx context.Context, spec bird.VethSpec) error
	DeleteVethPair(ctx context.Context, spec bird.VethSpec) error
}

// birdClient is the subset of bird.Client used by the daemon.
type birdClient interface {
	Status(ctx context.Context) (*bird.BirdObservedState, error)
	Configure(ctx context.Context, path string) error
	ConfigureSoft(ctx context.Context, path string) error
	Raw(ctx context.Context, cmd string) (string, error)
}

func (d *DaemonService) reconcileRouting(ctx context.Context) error {
	if d == nil || d.Sync == nil || d.Sync.App == nil || d.Sync.App.Config == nil {
		return nil
	}
	snapshot, rev, _ := d.snapshotState()
	if snapshot == nil {
		return nil
	}
	workspace := cloneStateFile(snapshot)
	config := d.Sync.App.Config
	routingInstances := config.Routing.Instances
	if len(routingInstances) == 0 {
		return nil
	}
	if workspace.ManagedZone.IsRoot() || !workspace.ManagedZone.Valid() {
		return nil
	}

	now := d.Sync.now()
	if workspace.RoutingReconcile == nil {
		workspace.RoutingReconcile = &routingReconcileState{}
	}
	workspace.RoutingReconcile.LastRunUnix = now.Unix()

	ars, err := routing.BuildAuthorizedRouteSet(workspace.Network, now)
	if err != nil {
		workspace.RoutingReconcile.LastError = err.Error()
		_ = d.commitRoutingReconcileResult(rev, snapshot.BirdInstances, workspace)
		return fmt.Errorf("build authorized route set: %w", err)
	}

	dataDir := config.DataDir
	if dataDir == "" {
		dataDir = "."
	}
	if abs, err := filepath.Abs(dataDir); err == nil {
		dataDir = abs
	}

	var firstErr error
	if err := d.autoAnnounceAssignedIPs(ars); err != nil {
		firstErr = err
	}

	// If auto-announce is enabled, it may have committed new
	// route announcements. Rebuild the authorized route set so BIRD import/export
	// filters reflect the latest announcements.
	if config.IPAM.AutoAnnounceAssignedIPs {
		snapshot, rev, _ = d.snapshotState()
		if snapshot == nil {
			return firstErr
		}
		workspace = cloneStateFile(snapshot)
		if workspace.RoutingReconcile == nil {
			workspace.RoutingReconcile = &routingReconcileState{}
		}
		workspace.RoutingReconcile.LastRunUnix = now.Unix()
		ars, err = routing.BuildAuthorizedRouteSet(workspace.Network, now)
		if err != nil && firstErr == nil {
			firstErr = fmt.Errorf("rebuild authorized route set after auto-announce: %w", err)
		}
	}
	if workspace.BirdInstances == nil {
		workspace.BirdInstances = make(map[string]*BirdInstanceState)
	}

	// Build per-netns overlay groups for interface pattern merging.
	overlayByNetns := groupOverlaysByNetns(config.IPsec.LinkGroups, config.Overlay.DefaultNetNS)

	for _, inst := range routingInstances {
		if err := d.reconcileRoutingForInstance(ctx, workspace, inst, ars, dataDir, overlayByNetns, config, now); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	if firstErr != nil {
		workspace.RoutingReconcile.LastError = firstErr.Error()
	} else {
		workspace.RoutingReconcile.LastError = ""
	}

	if err := d.commitRoutingReconcileResult(rev, snapshot.BirdInstances, workspace); err != nil {
		return fmt.Errorf("save routing reconcile state: %w", err)
	}
	return firstErr
}

// netnsOverlayGroup holds the overlays sharing a single netns/BIRD instance.
type netnsOverlayGroup struct {
	NetNSName string
	Overlays  []string
	Spec      ipsec.NetNSSpec
}

func groupOverlaysByNetns(groups []ipsec.LinkGroupSpec, defaultNetNS ipsec.NetNSSpec) map[string]*netnsOverlayGroup {
	out := make(map[string]*netnsOverlayGroup)
	for _, group := range groups {
		netnsName := resolveOverlayNetNSName(group, defaultNetNS)
		ng, ok := out[netnsName]
		if !ok {
			ng = &netnsOverlayGroup{NetNSName: netnsName}
			netns := group.NetNS.Normalized()
			if netns.Kind == "" || (netns.Kind == ipsec.NetNSName && netns.Name == "") {
				netns = defaultNetNS.Normalized()
			}
			ng.Spec = netns
			out[netnsName] = ng
		}
		ng.Overlays = append(ng.Overlays, group.ID)
	}
	return out
}

func (d *DaemonService) commitRoutingReconcileResult(rev uint64, baseBird map[string]*BirdInstanceState, result *stateFile) error {
	if d == nil || d.StateStore == nil || result == nil {
		return nil
	}
	_, committed, err := d.StateStore.CommitIfRevision(rev, func(state *stateFile) error {
		state.BirdInstances = cloneBirdInstances(result.BirdInstances)
		state.RoutingReconcile = result.RoutingReconcile
		return nil
	})
	if err != nil {
		return err
	}
	if !committed {
		merged, err := d.commitRoutingBirdInstancesByNetNS(baseBird, result.BirdInstances, result.RoutingReconcile)
		if err != nil {
			return err
		}
		if merged {
			return nil
		}
		d.routingDirty = true
		d.publishStateStoreRuntimeFlags()
		return nil
	}
	return d.installAndSaveCommittedState()
}

func (d *DaemonService) commitRoutingBirdInstancesByNetNS(base, next map[string]*BirdInstanceState, reconcile *routingReconcileState) (bool, error) {
	if d == nil || d.StateStore == nil {
		return false, nil
	}
	changed := changedBirdInstanceNetNS(base, next)
	current, currentRev := d.StateStore.Snapshot()
	if current == nil {
		return false, nil
	}
	if len(changed) > 0 && !birdInstanceCommitTokensMatch(base, current.BirdInstances, changed) {
		return false, nil
	}
	_, committed, err := d.StateStore.CommitIfRevision(currentRev, func(state *stateFile) error {
		if state.BirdInstances == nil {
			state.BirdInstances = make(map[string]*BirdInstanceState)
		}
		for _, netns := range changed {
			inst, ok := next[netns]
			if !ok || inst == nil {
				delete(state.BirdInstances, netns)
				continue
			}
			copyInst := *inst
			if inst.Overlays != nil {
				copyInst.Overlays = append([]string(nil), inst.Overlays...)
			}
			state.BirdInstances[netns] = &copyInst
		}
		state.RoutingReconcile = reconcile
		return nil
	})
	if err != nil || !committed {
		return false, err
	}
	return true, d.installAndSaveCommittedState()
}

func changedBirdInstanceNetNS(base, next map[string]*BirdInstanceState) []string {
	seen := make(map[string]bool, len(base)+len(next))
	var out []string
	for netns, baseInst := range base {
		seen[netns] = true
		nextInst := next[netns]
		if !birdInstanceStatesEqual(baseInst, nextInst) {
			out = append(out, netns)
		}
	}
	for netns := range next {
		if !seen[netns] {
			out = append(out, netns)
		}
	}
	return out
}

func birdInstanceCommitTokensMatch(base, current map[string]*BirdInstanceState, netnsNames []string) bool {
	for _, netns := range netnsNames {
		baseInst := base[netns]
		currentInst := current[netns]
		if baseInst == nil {
			if currentInst != nil {
				return false
			}
			continue
		}
		if currentInst == nil {
			return false
		}
		if baseInst.Owner.Token == "" || currentInst.Owner.Token == "" {
			if !birdInstanceStatesEqual(baseInst, currentInst) {
				return false
			}
			continue
		}
		if baseInst.Owner.Token != currentInst.Owner.Token {
			return false
		}
	}
	return true
}

func birdInstanceStatesEqual(a, b *BirdInstanceState) bool {
	if a == nil || b == nil {
		return a == b
	}
	if len(a.Overlays) != len(b.Overlays) {
		return false
	}
	if a.NetNSName != b.NetNSName ||
		a.ConfigPath != b.ConfigPath ||
		a.ControlSocket != b.ControlSocket ||
		a.PIDFile != b.PIDFile ||
		a.RouterID != b.RouterID ||
		a.Owner != b.Owner ||
		a.LastConfigHash != b.LastConfigHash ||
		a.LastError != b.LastError ||
		a.LastExit != b.LastExit ||
		a.FailureCount != b.FailureCount ||
		a.BackoffUntilUnix != b.BackoffUntilUnix ||
		a.State != b.State {
		return false
	}
	for i := range a.Overlays {
		if a.Overlays[i] != b.Overlays[i] {
			return false
		}
	}
	return true
}

func (d *DaemonService) reconcileRoutingForInstance(ctx context.Context, state *stateFile, inst RoutingInstance, ars *routing.AuthorizedRouteSet, dataDir string, overlayByNetns map[string]*netnsOverlayGroup, config *appConfig, now time.Time) error {
	netnsName := inst.NetNS
	instState := state.BirdInstances[netnsName]
	if instState == nil {
		instState = &BirdInstanceState{NetNSName: netnsName}
		state.BirdInstances[netnsName] = instState
	}

	// Record which overlays share this instance.
	overlays := []string{}
	if ng, ok := overlayByNetns[netnsName]; ok {
		overlays = ng.Overlays
	}
	instState.Overlays = overlays

	routerIDLabel := netnsRouterIDLabel(netnsName, config.Netns, inst)
	routerID := bird.StableRouterID(state.ManagedZone, rootTrustHash(state.Network), routerIDLabel)
	instState.RouterID = routerID

	spec := buildBirdInstanceSpecForNetns(inst, routerID, dataDir, overlayByNetns[netnsName], config.Netns, ars, state.ManagedZone)
	instState.ConfigPath = spec.ConfigPath
	instState.ControlSocket = spec.ControlSocketPath
	instState.PIDFile = spec.PIDFilePath
	instState.Owner = birdOwnerForInstance(inst, netnsName)
	spec.Owner = instState.Owner

	// Ensure veth pair for upstream if configured and create_veth is true.
	if inst.Upstream != nil && inst.Upstream.Enabled && inst.Upstream.CreateVeth {
		vspec := bird.VethSpec{
			MeshInterface: inst.Upstream.Interface,
			PeerInterface: inst.Upstream.PeerInterface,
			MeshNetns:     netnsName,
			PeerNetns:     inst.Upstream.PeerNetns,
			MeshIPv4LL:    inst.Upstream.IPv4LL,
			MeshIPv6LL:    inst.Upstream.IPv6LL,
			PeerIPv4LL:    inst.Upstream.DownstreamIPv4LL,
			PeerIPv6LL:    inst.Upstream.DownstreamIPv6LL,
		}
		vm := d.vethManager
		if vm == nil {
			vm = bird.NewExecVethManager()
		}
		if err := vm.EnsureVethPair(ctx, vspec); err != nil {
			instState.State = birdInstanceStateError
			instState.LastError = fmt.Sprintf("ensure veth: %s", err)
			// Non-fatal in dry-run: continue with BIRD config generation.
		}
	}

	importSet := assignmentPrefixes(ars)
	// Phase 6.3.4: BIRD export set must use the same forwarding policy as the
	// firewall. A non-transit node only exports its own local assigned prefixes;
	// a transit node exports authorized prefixes filtered by the forwarding
	// policy allow/deny lists. Both BIRD and firewall consume the same policy
	// so they never disagree on which transit paths are allowed.
	exportSet := buildRoutingExportSet(ars, state.ManagedZone, config, netnsName)

	configBytes, err := bird.DefaultConfigGenerator{}.Generate(spec, importSet, exportSet)
	if err != nil {
		instState.State = birdInstanceStateError
		instState.LastError = err.Error()
		return fmt.Errorf("generate bird config for netns %q: %w", netnsName, err)
	}

	configHash := fmt.Sprintf("%x", sha256.Sum256(configBytes))
	configChanged := instState.LastConfigHash == "" || instState.LastConfigHash != configHash

	mode := bird.BirdMode(inst.Mode)
	if mode == "" {
		mode = bird.BirdModeManaged
	}
	if mode == bird.BirdModeDisabled {
		instState.State = birdInstanceStatePending
		instState.LastError = ""
		return nil
	}

	switch mode {
	case bird.BirdModeManaged:
		if configChanged {
			if err := os.MkdirAll(filepath.Dir(spec.ConfigPath), 0o700); err != nil {
				instState.State = birdInstanceStateError
				instState.LastError = err.Error()
				return fmt.Errorf("create bird config dir for netns %q: %w", netnsName, err)
			}
			if err := os.WriteFile(spec.ConfigPath, configBytes, 0o600); err != nil {
				instState.State = birdInstanceStateError
				instState.LastError = err.Error()
				return fmt.Errorf("write bird config for netns %q: %w", netnsName, err)
			}
		}

		pm := d.birdProcessManager
		if pm == nil {
			pm = d.routingProcessManagerForNetNS(netnsName)
		}
		running := pm.IsRunning(ctx)
		if exit := pm.LastExit(); exit != nil {
			instState.LastExit = formatBirdProcessExit(exit)
			instState.FailureCount++
			instState.BackoffUntilUnix = now.Add(routingCrashBackoff(instState.FailureCount)).Unix()
			instState.State = birdInstanceStateDegraded
			instState.LastError = fmt.Sprintf("bird process exited: %s", instState.LastExit)
			running = false
		}
		if !running && instState.BackoffUntilUnix > now.Unix() {
			instState.State = birdInstanceStateDegraded
			instState.LastError = fmt.Sprintf("bird restart backoff active until %s", time.Unix(instState.BackoffUntilUnix, 0).Format(time.RFC3339))
			return nil
		}
		if !running {
			if err := pm.Start(ctx, spec); err != nil {
				instState.State = birdInstanceStateError
				instState.LastError = err.Error()
				if !isDryRunMissingBirdError(err) {
					return fmt.Errorf("start bird for netns %q: %w", netnsName, err)
				}
			} else {
				instState.State = birdInstanceStateRunning
				instState.FailureCount = 0
				instState.BackoffUntilUnix = 0
				instState.LastExit = ""
			}
		} else if configChanged {
			client := d.newBirdClient(spec.ControlSocketPath)
			if err := client.ConfigureSoft(ctx, spec.ConfigPath); err != nil {
				instState.State = birdInstanceStateDegraded
				instState.LastError = err.Error()
				if !isDryRunConnectError(err) {
					return fmt.Errorf("configure bird for netns %q: %w", netnsName, err)
				}
			} else {
				instState.State = birdInstanceStateRunning
			}
		}
		d.observeBirdForHealth(ctx, state, netnsName, instState.Overlays, spec.ControlSocketPath)

	case bird.BirdModeExternal:
		client := d.newBirdClient(spec.ControlSocketPath)
		observed, err := client.Status(ctx)
		if err != nil {
			instState.State = birdInstanceStateError
			instState.LastError = err.Error()
			d.recordBirdHealthObservationUnavailableForState(state, netnsName, instState.Overlays)
			if !isDryRunConnectError(err) {
				return fmt.Errorf("bird status for netns %q: %w", netnsName, err)
			}
		} else {
			instState.State = birdInstanceStateRunning
			d.recordBirdHealthObservationForState(state, netnsName, instState.Overlays, observed)
		}
	}

	instState.LastConfigHash = configHash
	if instState.State == "" {
		instState.State = birdInstanceStatePending
	}
	if instState.State == birdInstanceStateRunning {
		instState.LastError = ""
	}
	return nil
}

func (d *DaemonService) observeBirdForHealth(ctx context.Context, state *stateFile, netnsName string, overlays []string, socketPath string) {
	if d == nil || d.health == nil || socketPath == "" {
		return
	}
	observeCtx, cancel := context.WithTimeout(ctx, birdHealthObservationTimeout)
	defer cancel()
	observed, err := d.newBirdClient(socketPath).Status(observeCtx)
	if err != nil {
		d.recordBirdHealthObservationUnavailableForState(state, netnsName, overlays)
		return
	}
	d.recordBirdHealthObservationForState(state, netnsName, overlays, observed)
}

func (d *DaemonService) recordBirdHealthObservationUnavailable(netnsName string, overlays []string) {
	if d == nil || d.Sync == nil {
		return
	}
	d.recordBirdHealthObservationUnavailableForState(d.Sync.State, netnsName, overlays)
}

func (d *DaemonService) recordBirdHealthObservationUnavailableForState(state *stateFile, netnsName string, overlays []string) {
	d.recordBirdHealthObservationForState(state, netnsName, overlays, &bird.BirdObservedState{})
}

func (d *DaemonService) recordBirdHealthObservation(netnsName string, overlays []string, observed *bird.BirdObservedState) {
	if d == nil || d.Sync == nil {
		return
	}
	d.recordBirdHealthObservationForState(d.Sync.State, netnsName, overlays, observed)
}

func (d *DaemonService) recordBirdHealthObservationForState(state *stateFile, netnsName string, overlays []string, observed *bird.BirdObservedState) {
	if d == nil || d.health == nil || state == nil || observed == nil {
		return
	}
	for _, inst := range state.LinkInstances {
		if inst.StagedInterfaceName == "" || !linkInstanceBelongsToBirdInstance(inst, netnsName, overlays) {
			continue
		}
		obs := birdObservationForInterface(inst.ID, healthProbeID(inst.ID, "staged"), inst.StagedInterfaceName, observed)
		d.health.SetBabelObservation(obs)
	}
}

func birdObservationForInterface(instanceID, probeID, iface string, observed *bird.BirdObservedState) health.BabelObservation {
	obs := health.BabelObservation{InstanceID: instanceID, ProbeID: probeID}
	if iface == "" || observed == nil {
		return obs
	}
	for _, n := range observed.Neighbors {
		if n.Interface != iface {
			continue
		}
		obs.Neighbor = true
		if n.Metric > 0 && (obs.Metric == 0 || int(n.Metric) < obs.Metric) {
			obs.Metric = int(n.Metric)
		}
	}
	for _, r := range observed.Routes {
		if r.Iface == iface && r.Selected && birdRouteIsBabel(r) {
			obs.Route = true
			if r.Metric > 0 && (obs.Metric == 0 || int(r.Metric) < obs.Metric) {
				obs.Metric = int(r.Metric)
			}
		}
	}
	return obs
}

func birdRouteIsBabel(route bird.BirdRoute) bool {
	return strings.Contains(strings.ToLower(route.Protocol), "babel") ||
		strings.Contains(strings.ToLower(route.Source), "babel")
}

func linkInstanceBelongsToBirdInstance(inst linkInstanceState, netnsName string, overlays []string) bool {
	for _, overlay := range overlays {
		if overlay == inst.GroupID {
			return true
		}
	}
	for _, addr := range []string{inst.StagedLocalTunnelAddr, inst.StagedPeerTunnelAddr, inst.LocalTunnelAddr, inst.PeerTunnelAddr} {
		if scopedNetNS(addr) == netnsName {
			return true
		}
	}
	return netnsName == "" || netnsName == "default"
}

func (d *DaemonService) routingProcessManagerForNetNS(netnsName string) birdProcessManager {
	if d.birdProcessManagers == nil {
		d.birdProcessManagers = make(map[string]birdProcessManager)
	}
	pm := d.birdProcessManagers[netnsName]
	if pm == nil {
		pm = bird.NewExecProcessManager("")
		d.birdProcessManagers[netnsName] = pm
	}
	return pm
}

func (d *DaemonService) stopManagedBirdInstances(ctx context.Context, force bool) error {
	if d == nil || d.Sync == nil || d.Sync.App == nil || d.Sync.App.Config == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}

	var firstErr error
	for _, inst := range d.Sync.App.Config.Routing.Instances {
		if !inst.Enabled || inst.Mode == ipsec.RoutingModeDisabled || inst.Mode == ipsec.RoutingModeExternal {
			continue
		}
		if !force && normalizedRoutingShutdownPolicy(inst.ShutdownPolicy) != routingShutdownPolicyStop {
			continue
		}
		pm := d.birdProcessManager
		if pm == nil {
			pm = d.birdProcessManagers[inst.NetNS]
		}
		if pm == nil {
			continue
		}
		mode := bird.BirdMode(inst.Mode)
		if mode == "" {
			mode = bird.BirdModeManaged
		}
		spec := bird.BirdInstanceSpec{
			NetNSName:         inst.NetNS,
			ControlSocketPath: inst.ControlSocket,
			PIDFilePath:       inst.PIDFile,
			ConfigPath:        inst.ConfigFile,
			Mode:              mode,
			Owner:             birdOwnerForInstance(inst, inst.NetNS),
		}
		if err := pm.Stop(ctx, spec); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("stop bird for netns %q: %w", inst.NetNS, err)
		}
	}
	return firstErr
}

func (d *DaemonService) newBirdClient(socketPath string) birdClient {
	if d.birdClientFactory != nil {
		return d.birdClientFactory(socketPath, 10*time.Second)
	}
	return bird.NewClient(socketPath, 10*time.Second)
}

func (d *DaemonService) birdDumpForControl(ctx context.Context, netnsName, command string) *birdDumpResponse {
	response := &birdDumpResponse{Instances: map[string]birdDumpInstance{}}
	if d == nil || d.Sync == nil || d.Sync.App == nil || d.Sync.App.Config == nil {
		return response
	}
	commands := defaultBirdDumpCommands()
	if trimmed := strings.TrimSpace(command); trimmed != "" {
		command = trimmed
		commands = []string{command}
	} else {
		command = ""
	}
	for _, inst := range d.Sync.App.Config.Routing.Instances {
		if !inst.Enabled || inst.Mode == ipsec.RoutingModeDisabled {
			continue
		}
		if netnsName != "" && inst.NetNS != netnsName && inst.ID != netnsName {
			continue
		}
		item := birdDumpInstance{
			NetNS:         inst.NetNS,
			InstanceID:    inst.ID,
			ControlSocket: inst.ControlSocket,
			Command:       command,
			Raw:           map[string]string{},
		}
		if inst.ControlSocket == "" {
			item.Error = "control socket is not configured"
			response.Instances[inst.NetNS] = item
			continue
		}
		client := d.newBirdClient(inst.ControlSocket)
		for _, cmd := range commands {
			out, err := client.Raw(ctx, cmd)
			if err != nil {
				if item.Error == "" {
					item.Error = err.Error()
				}
				item.Raw[cmd] = out
				continue
			}
			item.Raw[cmd] = out
		}
		response.Instances[inst.NetNS] = item
	}
	return response
}

func defaultBirdDumpCommands() []string {
	return []string{
		"show status",
		"show protocols all",
		"show route all",
		"show interfaces",
		"show babel neighbors",
	}
}

func buildBirdInstanceSpecForNetns(inst RoutingInstance, routerID uint32, _ string, ng *netnsOverlayGroup, netnsCfg netnsConfig, ars *routing.AuthorizedRouteSet, managedZone zone.ZonePath) bird.BirdInstanceSpec {
	netnsSpec := ipsec.NetNSSpec{}
	if s, ok := netnsCfg.Names[inst.NetNS]; ok {
		netnsSpec = s
	}
	if ng != nil {
		netnsSpec = ng.Spec
	}

	// Build interface patterns: merge the instance default + any overlay-specific patterns.
	// Currently all overlays use "hgs*" by default, so the instance pattern suffices.
	interfacePatterns := []string{}
	if inst.InterfacePat != "" {
		interfacePatterns = append(interfacePatterns, inst.InterfacePat)
	}

	overlays := []string{}
	if ng != nil {
		overlays = ng.Overlays
	}

	mode := bird.BirdMode(inst.Mode)
	if mode == "" {
		mode = bird.BirdModeManaged
	}

	spec := bird.BirdInstanceSpec{
		RouterID:          routerID,
		NetNSName:         inst.NetNS,
		Overlays:          overlays,
		NetNS:             bird.NetNSSpec{Kind: netnsSpec.Kind, Name: netnsSpec.Name, Path: netnsSpec.Path, Create: netnsSpec.Create},
		ControlSocketPath: inst.ControlSocket,
		PIDFilePath:       inst.PIDFile,
		ConfigPath:        inst.ConfigFile,
		TableID:           inst.TableID,
		MetricBase:        inst.MetricBase,
		MetricStaged:      inst.MetricStaged,
		MetricDraining:    inst.MetricDraining,
		InterfacePatterns: interfacePatterns,
		Mode:              mode,
		ECMP:              inst.ECMP,
		ECMPLimit:         inst.ECMPLimit,
	}

	// Wire upstream config into BIRD spec.
	if inst.Upstream != nil && inst.Upstream.Enabled {
		spec.Upstream = &bird.UpstreamSpec{
			Interface: inst.Upstream.Interface,
		}
	}

	// Build static routes for local assigned prefixes.
	if ars != nil && managedZone.Valid() {
		for prefix, entry := range ars.Assignments {
			if entry.AssignedTo != managedZone {
				continue
			}
			via := ""
			if inst.Upstream != nil && inst.Upstream.Enabled {
				via = inst.Upstream.Interface
			}
			spec.StaticRoutes = append(spec.StaticRoutes, bird.StaticRouteSpec{
				Prefix: prefix,
				Via:    via,
			})
		}
	}

	return spec
}

func routingInstancesEnabled(config *appConfig) []RoutingInstance {
	if config == nil {
		return nil
	}
	var out []RoutingInstance
	for _, inst := range config.Routing.Instances {
		if inst.Enabled && inst.Mode != ipsec.RoutingModeDisabled {
			out = append(out, inst)
		}
	}
	return out
}

// buildRoutingExportSet computes the BIRD export set using the forwarding policy
// shared with the firewall planner (Phase 6.3.4). When no firewall forwarding
// policy is configured for the given netns, it falls back to the legacy
// behavior of exporting all authorized prefixes from the managed zone. When a
// non-transit policy is present, only local assigned prefixes are exported;
// when transit=true, authorized prefixes are filtered by allow/deny lists.
func buildRoutingExportSet(ars *routing.AuthorizedRouteSet, managedZone zone.ZonePath, config *appConfig, netnsName string) []netip.Prefix {
	localExport := authorizedPrefixes(ars, []zone.ZonePath{managedZone})
	policy := netnsForwardingPolicy(config, netnsName)
	if policy == nil || !policy.Transit {
		// Non-transit or no policy: only export local assigned prefixes.
		return localExport
	}
	// Transit: export all authorized prefixes filtered by the policy.
	allAuthorized := authorizedPrefixes(ars, nil)
	if len(policy.AllowPrefixes) == 0 && len(policy.DenyPrefixes) == 0 {
		return allAuthorized
	}
	return filterAuthorizedByPolicy(allAuthorized, policy)
}

// netnsForwardingPolicy returns the forwarding policy from the firewall
// instance matching the given netns, or nil if none configured.
func netnsForwardingPolicy(config *appConfig, netnsName string) *firewall.ForwardingPolicy {
	if config == nil {
		return nil
	}
	for _, fi := range config.Firewall.Instances {
		if fi.NetNS == netnsName && !fi.IsHost {
			return &fi.Forwarding
		}
	}
	return nil
}

// filterAuthorizedByPolicy applies allow/deny prefix lists from a forwarding
// policy to a set of authorized prefixes.
func filterAuthorizedByPolicy(prefixes []netip.Prefix, policy *firewall.ForwardingPolicy) []netip.Prefix {
	if policy == nil {
		return prefixes
	}
	var out []netip.Prefix
	for _, p := range prefixes {
		if firewall.IsTransitPrefixAllowed(*policy, p) {
			out = append(out, p)
		}
	}
	return out
}

func authorizedPrefixes(ars *routing.AuthorizedRouteSet, zones []zone.ZonePath) []netip.Prefix {
	if ars == nil {
		return nil
	}
	var out []netip.Prefix
	for source, prefixes := range ars.Announced {
		if len(zones) > 0 {
			found := false
			for _, z := range zones {
				if source == z {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}
		for prefix := range prefixes {
			out = append(out, prefix)
		}
	}
	return out
}

// assignmentPrefixes returns all IPAM assignment prefixes from the authorized
// route set. These prefixes form the import whitelist: the local BIRD instance
// accepts any route advertised by overlay peers that falls within an assigned
// prefix (the BIRD prefix list uses "+" to include more specific prefixes).
func assignmentPrefixes(ars *routing.AuthorizedRouteSet) []netip.Prefix {
	if ars == nil {
		return nil
	}
	out := make([]netip.Prefix, 0, len(ars.Assignments))
	for prefix := range ars.Assignments {
		out = append(out, prefix)
	}
	return out
}

func birdOwnerForInstance(inst RoutingInstance, netnsName string) bird.BirdResourceOwner {
	owner := bird.BirdResourceOwner{
		Manager:    "higgs",
		InstanceID: inst.ID,
		NetNSName:  netnsName,
	}
	owner.Token = bird.OwnerToken(owner.InstanceID, owner.NetNSName)
	owner.ControlSocketToken = bird.ResourceToken(owner, "control_socket")
	owner.PIDFileToken = bird.ResourceToken(owner, "pid_file")
	owner.ConfigFileToken = bird.ResourceToken(owner, "config_file")
	owner.RouteTableToken = bird.ResourceToken(owner, "route_table")
	owner.RuleToken = bird.ResourceToken(owner, "rule")
	return owner
}

func routingCrashBackoff(failureCount int) time.Duration {
	if failureCount < 1 {
		failureCount = 1
	}
	backoff := time.Duration(1<<minInt(failureCount-1, 6)) * time.Second
	if backoff > maxRoutingCrashBackoff {
		return maxRoutingCrashBackoff
	}
	return backoff
}

func formatBirdProcessExit(exit *bird.ProcessExit) string {
	if exit == nil {
		return ""
	}
	if exit.PID > 0 && exit.Error != "" {
		return fmt.Sprintf("pid %d: %s", exit.PID, exit.Error)
	}
	if exit.PID > 0 {
		return fmt.Sprintf("pid %d", exit.PID)
	}
	return exit.Error
}

func rootTrustHash(ns *zone.NetworkState) []byte {
	if ns == nil {
		return nil
	}
	if len(ns.GlobalRoot) > 0 {
		return ns.GlobalRoot
	}
	root := ns.Zones[zone.RootZone]
	if root != nil && root.Authority != nil && len(root.Authority.Keys) > 0 {
		return root.Authority.Keys[0].Key
	}
	return nil
}

func isDryRunMissingBirdError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "bird binary not found") || strings.Contains(msg, "no such file") || strings.Contains(msg, "executable file not found")
}

func isDryRunConnectError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "dial") || strings.Contains(msg, "no such file") || strings.Contains(msg, "connection refused")
}

// autoAnnounceAssignedIPs publishes or withdraws routes/announcements/* records
// for every IPAM assignment whose assigned_to equals this node's managed zone.
// It commits network record changes through the daemon state store so routing
// reconcile can run BIRD work from a refreshed committed snapshot.
func (d *DaemonService) autoAnnounceAssignedIPs(ars *routing.AuthorizedRouteSet) error {
	if d == nil || d.Sync == nil || d.Sync.App == nil || d.StateStore == nil {
		return nil
	}
	if !d.Sync.App.Config.IPAM.AutoAnnounceAssignedIPs {
		return nil
	}
	_, err := d.StateStore.Update(func(state *stateFile) error {
		changed, err := d.autoAnnounceAssignedIPsForState(state, ars)
		if err != nil {
			return err
		}
		if !changed {
			return errAutoAnnounceNoChanges
		}
		return nil
	})
	if errors.Is(err, errAutoAnnounceNoChanges) {
		return nil
	}
	if err != nil {
		return err
	}
	return d.installAndSaveCommittedState()
}

func (d *DaemonService) autoAnnounceAssignedIPsForState(state *stateFile, ars *routing.AuthorizedRouteSet) (bool, error) {
	if d == nil || d.Sync == nil || d.Sync.App == nil || state == nil || state.Network == nil {
		return false, nil
	}
	if !d.Sync.App.Config.IPAM.AutoAnnounceAssignedIPs {
		return false, nil
	}
	managedZone := state.ManagedZone
	if managedZone.IsRoot() || !managedZone.Valid() {
		return false, nil
	}

	localAssigned := make(map[netip.Prefix]struct{})
	for prefix, entry := range ars.Assignments {
		if entry.AssignedTo == managedZone {
			localAssigned[prefix] = struct{}{}
		}
	}

	localAnnounced := make(map[netip.Prefix]bool)
	zs := state.Network.Zones[managedZone]
	if zs != nil {
		for key, rec := range zs.Records {
			if !strings.HasPrefix(key, routing.RecordKeyPrefixRoutes) {
				continue
			}
			ann, err := routing.ParseRouteAnnouncementRecord(rec)
			if err != nil {
				continue
			}
			p, err := netip.ParsePrefix(ann.Prefix)
			if err != nil {
				continue
			}
			localAnnounced[p] = ann.Active
		}
	}

	changed := false
	for prefix := range localAssigned {
		if active, ok := localAnnounced[prefix]; ok && active {
			continue
		}
		if err := d.putRouteAnnouncementForState(state, managedZone, prefix, true); err != nil {
			return changed, fmt.Errorf("auto-announce %s: %w", prefix, err)
		}
		changed = true
		d.logInfo("routing", "auto_announce_assigned_ip", map[string]any{
			"zone":   managedZone,
			"prefix": prefix.String(),
		})
	}

	for prefix, active := range localAnnounced {
		if !active {
			continue
		}
		if _, ok := localAssigned[prefix]; ok {
			continue
		}
		if err := d.putRouteAnnouncementForState(state, managedZone, prefix, false); err != nil {
			return changed, fmt.Errorf("auto-withdraw %s: %w", prefix, err)
		}
		changed = true
		d.logInfo("routing", "auto_withdraw_assigned_ip", map[string]any{
			"zone":   managedZone,
			"prefix": prefix.String(),
		})
	}

	return changed, nil
}

func (d *DaemonService) putRouteAnnouncementForState(state *stateFile, path zone.ZonePath, prefix netip.Prefix, active bool) error {
	canonical := prefix.Masked().String()
	key, err := routing.NormalizeRouteAnnouncementKey(canonical)
	if err != nil {
		return err
	}
	record := routing.RouteAnnouncementRecord{Version: 1, Prefix: canonical, Active: active}
	value, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("marshal route announcement: %w", err)
	}
	rec, err := buildSignedRecordAt(state, path, key, value, routing.RecordTypeRouteAnnouncement, d.Sync.now())
	if err != nil {
		return fmt.Errorf("build signed route record: %w", err)
	}
	if err := state.Network.Put(rec); err != nil {
		return fmt.Errorf("put route record: %w", err)
	}
	return nil
}

// publishRoutingNetnsRecord publishes a routing/netns record listing the netns
// names this node uses for routing. This allows other nodes to reverse-derive
// Router-ID → (zone, netns) for control-plane cross-audit.
func (d *DaemonService) publishRoutingNetnsRecord() error {
	if d == nil || d.Sync == nil || d.Sync.State == nil || d.Sync.State.Network == nil || d.Sync.App == nil || d.Sync.App.Config == nil {
		return nil
	}
	_, err := d.publishRoutingNetnsRecordInState(d.Sync.State)
	return err
}

func (d *DaemonService) publishRoutingNetnsRecordInState(state *stateFile) (bool, error) {
	if d == nil || d.Sync == nil || state == nil || state.Network == nil || d.Sync.App == nil || d.Sync.App.Config == nil {
		return false, nil
	}
	config := d.Sync.App.Config
	if state.ManagedZone == zone.RootZone || !state.ManagedZone.Valid() || len(state.ZonePrivateKey) == 0 {
		return false, nil
	}
	if len(config.Routing.Instances) == 0 {
		return false, nil
	}
	netnsNames := routingNetnsNames(config.Routing)
	if len(netnsNames) == 0 {
		return false, nil
	}
	record := routing.RoutingNetnsRecord{Version: 1, Netns: netnsNames}
	value, err := json.Marshal(record)
	if err != nil {
		return false, fmt.Errorf("marshal routing/netns record: %w", err)
	}
	updated, err := putSignedRoutingNetnsRecord(state, state.ManagedZone, value, d.Sync.now())
	if err != nil {
		return false, fmt.Errorf("put routing/netns record: %w", err)
	}
	if updated {
		d.logInfo("routing", "published_netns_record", map[string]any{
			"zone":  state.ManagedZone,
			"netns": netnsNames,
		})
	}
	return updated, nil
}

func putSignedRoutingNetnsRecord(state *stateFile, path zone.ZonePath, value []byte, now time.Time) (bool, error) {
	zs := state.Network.Zones[path]
	if zs != nil {
		if existing := zs.Records[routing.RecordKeyRoutingNetns]; existing != nil && bytesEqual(existing.Value, value) {
			return false, nil
		}
	}
	rec, err := buildSignedRecordAt(state, path, routing.RecordKeyRoutingNetns, value, routing.RecordTypeRoutingNetns, now)
	if err != nil {
		return false, err
	}
	if err := state.Network.Put(rec); err != nil {
		return false, err
	}
	return true, nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
