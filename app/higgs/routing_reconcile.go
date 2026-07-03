package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Catofes/higgs/pkg/core/zone"
	"github.com/Catofes/higgs/pkg/firewall"
	"github.com/Catofes/higgs/pkg/routing"
	"github.com/Catofes/higgs/pkg/routing/bird"
	"github.com/Catofes/higgs/pkg/transport/ipsec"
)

const (
	defaultRoutingReconcileInterval = 30 * time.Second
	birdInstanceStatePending        = "pending"
	birdInstanceStateRunning        = "running"
	birdInstanceStateDegraded       = "degraded"
	birdInstanceStateError          = "error"
)

// birdProcessManager is the subset of bird.ProcessManager used by the daemon.
type birdProcessManager interface {
	Start(ctx context.Context, spec bird.BirdInstanceSpec) error
	Stop(ctx context.Context, spec bird.BirdInstanceSpec) error
	IsRunning(ctx context.Context) bool
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
}

func (d *DaemonService) reconcileRouting(ctx context.Context) error {
	if d == nil || d.Sync == nil || d.Sync.App == nil || d.Sync.App.Config == nil || d.Sync.State == nil {
		return nil
	}
	config := d.Sync.App.Config
	routingInstances := config.Routing.Instances
	if len(routingInstances) == 0 {
		return nil
	}
	if d.Sync.State.ManagedZone.IsRoot() || !d.Sync.State.ManagedZone.Valid() {
		return nil
	}

	now := d.Sync.now()
	if d.Sync.State.RoutingReconcile == nil {
		d.Sync.State.RoutingReconcile = &routingReconcileState{}
	}
	d.Sync.State.RoutingReconcile.LastRunUnix = now.Unix()

	ars, err := routing.BuildAuthorizedRouteSet(d.Sync.State.Network, now)
	if err != nil {
		d.Sync.State.RoutingReconcile.LastError = err.Error()
		_ = d.Sync.saveState()
		return fmt.Errorf("build authorized route set: %w", err)
	}

	dataDir := config.DataDir
	if dataDir == "" {
		dataDir = "."
	}
	if abs, err := filepath.Abs(dataDir); err == nil {
		dataDir = abs
	}

	if d.Sync.State.BirdInstances == nil {
		d.Sync.State.BirdInstances = make(map[string]*BirdInstanceState)
	}

	var firstErr error
	if err := d.autoAnnounceAssignedIPs(ars); err != nil {
		firstErr = err
	}

	// If auto-announce is enabled, it may have mutated Sync.State with new
	// route announcements. Rebuild the authorized route set so BIRD import/export
	// filters reflect the latest announcements.
	if config.IPAM.AutoAnnounceAssignedIPs {
		ars, err = routing.BuildAuthorizedRouteSet(d.Sync.State.Network, now)
		if err != nil && firstErr == nil {
			firstErr = fmt.Errorf("rebuild authorized route set after auto-announce: %w", err)
		}
	}

	// Build per-netns overlay groups for interface pattern merging.
	overlayByNetns := groupOverlaysByNetns(config.IPsec.LinkGroups, config.Overlay.DefaultNetNS)

	for _, inst := range routingInstances {
		if err := d.reconcileRoutingForInstance(ctx, inst, ars, dataDir, overlayByNetns, config, now); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	if firstErr != nil {
		d.Sync.State.RoutingReconcile.LastError = firstErr.Error()
	} else {
		d.Sync.State.RoutingReconcile.LastError = ""
	}

	if err := d.Sync.saveState(); err != nil {
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

func (d *DaemonService) reconcileRoutingForInstance(ctx context.Context, inst RoutingInstance, ars *routing.AuthorizedRouteSet, dataDir string, overlayByNetns map[string]*netnsOverlayGroup, config *appConfig, _ time.Time) error {
	netnsName := inst.NetNS
	instState := d.Sync.State.BirdInstances[netnsName]
	if instState == nil {
		instState = &BirdInstanceState{NetNSName: netnsName}
		d.Sync.State.BirdInstances[netnsName] = instState
	}

	// Record which overlays share this instance.
	overlays := []string{}
	if ng, ok := overlayByNetns[netnsName]; ok {
		overlays = ng.Overlays
	}
	instState.Overlays = overlays

	routerIDLabel := netnsRouterIDLabel(netnsName, config.Netns, inst)
	routerID := bird.StableRouterID(d.Sync.State.ManagedZone, rootTrustHash(d.Sync.State.Network), routerIDLabel)
	instState.RouterID = routerID

	spec := buildBirdInstanceSpecForNetns(inst, routerID, dataDir, overlayByNetns[netnsName], config.Netns, ars, d.Sync.State.ManagedZone)
	instState.ConfigPath = spec.ConfigPath
	instState.ControlSocket = spec.ControlSocketPath
	instState.PIDFile = spec.PIDFilePath

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
	exportSet := buildRoutingExportSet(ars, d.Sync.State.ManagedZone, config, netnsName)

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
		if !pm.IsRunning(ctx) {
			if err := pm.Start(ctx, spec); err != nil {
				instState.State = birdInstanceStateError
				instState.LastError = err.Error()
				if !isDryRunMissingBirdError(err) {
					return fmt.Errorf("start bird for netns %q: %w", netnsName, err)
				}
			} else {
				instState.State = birdInstanceStateRunning
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

	case bird.BirdModeExternal:
		client := d.newBirdClient(spec.ControlSocketPath)
		if _, err := client.Status(ctx); err != nil {
			instState.State = birdInstanceStateError
			instState.LastError = err.Error()
			if !isDryRunConnectError(err) {
				return fmt.Errorf("bird status for netns %q: %w", netnsName, err)
			}
		} else {
			instState.State = birdInstanceStateRunning
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

func (d *DaemonService) newBirdClient(socketPath string) birdClient {
	if d.birdClientFactory != nil {
		return d.birdClientFactory(socketPath, 10*time.Second)
	}
	return bird.NewClient(socketPath, 10*time.Second)
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
// It runs inside the daemon's single-writer reconcile path and directly mutates
// d.Sync.State; callers must save the state afterwards.
func (d *DaemonService) autoAnnounceAssignedIPs(ars *routing.AuthorizedRouteSet) error {
	if d == nil || d.Sync == nil || d.Sync.App == nil || d.Sync.State == nil || d.Sync.State.Network == nil {
		return nil
	}
	if !d.Sync.App.Config.IPAM.AutoAnnounceAssignedIPs {
		return nil
	}
	managedZone := d.Sync.State.ManagedZone
	if managedZone.IsRoot() || !managedZone.Valid() {
		return nil
	}

	localAssigned := make(map[netip.Prefix]struct{})
	for prefix, entry := range ars.Assignments {
		if entry.AssignedTo == managedZone {
			localAssigned[prefix] = struct{}{}
		}
	}

	localAnnounced := make(map[netip.Prefix]bool)
	zs := d.Sync.State.Network.Zones[managedZone]
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

	for prefix := range localAssigned {
		if active, ok := localAnnounced[prefix]; ok && active {
			continue
		}
		if err := d.putRouteAnnouncement(managedZone, prefix, true); err != nil {
			return fmt.Errorf("auto-announce %s: %w", prefix, err)
		}
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
		if err := d.putRouteAnnouncement(managedZone, prefix, false); err != nil {
			return fmt.Errorf("auto-withdraw %s: %w", prefix, err)
		}
		d.logInfo("routing", "auto_withdraw_assigned_ip", map[string]any{
			"zone":   managedZone,
			"prefix": prefix.String(),
		})
	}

	return nil
}

// putRouteAnnouncement signs and writes a routes/announcements/* record into
// the current in-memory state. It must be called from the daemon's single-writer
// path where d.Sync.State is already locked/mutable.
func (d *DaemonService) putRouteAnnouncement(path zone.ZonePath, prefix netip.Prefix, active bool) error {
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
	rec, err := buildSignedRecordAt(d.Sync.State, path, key, value, routing.RecordTypeRouteAnnouncement, d.Sync.now())
	if err != nil {
		return fmt.Errorf("build signed route record: %w", err)
	}
	if err := d.Sync.State.Network.Put(rec); err != nil {
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
	config := d.Sync.App.Config
	if d.Sync.State.ManagedZone == zone.RootZone || !d.Sync.State.ManagedZone.Valid() || len(d.Sync.State.ZonePrivateKey) == 0 {
		return nil
	}
	if len(config.Routing.Instances) == 0 {
		return nil
	}
	netnsNames := routingNetnsNames(config.Routing)
	if len(netnsNames) == 0 {
		return nil
	}
	record := routing.RoutingNetnsRecord{Version: 1, Netns: netnsNames}
	value, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("marshal routing/netns record: %w", err)
	}
	updated, err := putSignedRoutingNetnsRecord(d.Sync.State, d.Sync.State.ManagedZone, value, d.Sync.now())
	if err != nil {
		return fmt.Errorf("put routing/netns record: %w", err)
	}
	if updated {
		d.logInfo("routing", "published_netns_record", map[string]any{
			"zone":  d.Sync.State.ManagedZone,
			"netns": netnsNames,
		})
	}
	return nil
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
