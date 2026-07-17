package main

import (
	"context"
	"fmt"
	"time"

	"github.com/Catofes/higgs/pkg/core/zone"
	"github.com/Catofes/higgs/pkg/firewall"
	"github.com/Catofes/higgs/pkg/routing"
	"github.com/Catofes/higgs/pkg/transport/ipsec"
)

const defaultFirewallReconcileInterval = 30 * time.Second

// firewallDriver is the subset of firewall.FirewallDriver used by the daemon.
type firewallDriver interface {
	Preflight(ctx context.Context, spec firewall.FirewallInstanceSpec) (firewall.FirewallPreflight, error)
	Plan(ctx context.Context, desired *firewall.FirewallDesiredState, observed firewall.FirewallObservedState) (firewall.FirewallPlan, error)
	Apply(ctx context.Context, plan firewall.FirewallPlan, desired *firewall.FirewallDesiredState) (firewall.FirewallApplyResult, error)
	ListOwned(ctx context.Context, owner firewall.Owner) (firewall.FirewallObservedState, error)
	DeleteStale(ctx context.Context, refs []firewall.FirewallObjectRef) error
}

// reconcileFirewall is the daemon single-writer firewall reconcile entry point.
// It computes the desired state from verified active state + local config,
// diffs against observed owned objects, and applies the plan via the driver.
// The default driver is DryRunDriver; real nft/iptables drivers are added later.
func (d *DaemonService) reconcileFirewall(ctx context.Context) error {
	if d == nil || d.Sync == nil || d.Sync.App == nil || d.Sync.App.Config == nil {
		return nil
	}
	snapshot, rev, _ := d.snapshotState()
	if snapshot == nil {
		return nil
	}
	config := d.Sync.App.Config
	instances := firewallInstancesEnabled(config)
	if len(instances) == 0 {
		return nil
	}
	if snapshot.ManagedZone.IsRoot() || !snapshot.ManagedZone.Valid() {
		return nil
	}

	now := d.Sync.now()
	summary := cloneFirewallReconcileState(snapshot.FirewallReconcile)
	if summary == nil {
		summary = &firewallReconcileState{}
	}
	summary.LastRunUnix = now.Unix()

	// Build authorized route set for prefix inputs.
	ars, err := routing.BuildAuthorizedRouteSet(snapshot.Network, now)
	if err != nil {
		summary.LastError = err.Error()
		_ = d.commitFirewallReconcileResult(rev, summary)
		return fmt.Errorf("firewall build authorized route set: %w", err)
	}

	preflight := firewall.PreflightProbe(ctx)
	summary.Backend = preflight.Backend

	if summary.Instances == nil {
		summary.Instances = make(map[string]*firewallInstanceReconcileStateEntry)
	}

	charonIKE, charonNATT := firewallCharonPorts(config, snapshot)

	if len(instances) > 0 && preflight.NFTNetlink != "ok" && preflight.Iptables != "available" {
		d.logWarn("firewall", "no_backend_available", map[string]any{
			"nft":       preflight.NFTNetlink,
			"iptables":  preflight.Iptables,
			"net_admin": preflight.CAPNetAdmin,
			"message":   "no nft or iptables command available; firewall rules will not be applied",
		})
	}

	var firstErr error
	for _, instCfg := range instances {
		listenAddrs := instCfg.ListenAddrs
		spec := firewallInstanceSpecFromConfig(instCfg, listenAddrs, charonIKE, charonNATT)
		if spec.IsHost {
			endpointServices, endpointErr := resolveEndpointServices(snapshot.EndpointACLs, ars)
			if endpointErr != nil {
				if firstErr == nil {
					firstErr = endpointErr
				}
				continue
			}
			spec.EndpointServices = endpointServices
		}
		input := buildFirewallPolicyInput(spec, ars, snapshot, config)
		desired, err := firewall.BuildDesiredState(spec, input)
		if err != nil {
			entry := getOrCreateFirewallEntry(summary, instCfg.ID)
			entry.LastRunUnix = now.Unix()
			entry.LastError = err.Error()
			if firstErr == nil {
				firstErr = fmt.Errorf("firewall instance %s: %w", instCfg.ID, err)
			}
			continue
		}

		driver, err := d.firewallDriverInstance(instCfg)
		if err != nil {
			entry := getOrCreateFirewallEntry(summary, instCfg.ID)
			entry.LastRunUnix = now.Unix()
			entry.LastError = err.Error()
			if firstErr == nil {
				firstErr = fmt.Errorf("firewall driver %s: %w", instCfg.ID, err)
			}
			continue
		}
		if driver == nil {
			driver = firewall.NewDryRunDriver()
		}

		owner := firewall.Owner{
			Manager:     "higgs",
			InstanceID:  firewallOwnerScope(spec),
			OwnerPrefix: instCfg.OwnerPrefix,
			Token:       firewall.OwnerToken(spec),
		}
		observed, _ := driver.ListOwned(ctx, owner)

		plan, err := driver.Plan(ctx, desired, observed)
		if err != nil {
			entry := getOrCreateFirewallEntry(summary, instCfg.ID)
			entry.LastRunUnix = now.Unix()
			entry.LastError = err.Error()
			if firstErr == nil {
				firstErr = fmt.Errorf("firewall plan %s: %w", instCfg.ID, err)
			}
			continue
		}

		result, err := driver.Apply(ctx, plan, desired)
		entry := getOrCreateFirewallEntry(summary, instCfg.ID)
		entry.LastRunUnix = now.Unix()
		entry.PolicyHash = firewall.DesiredStateHash(desired)
		entry.OwnedObjects = len(firewall.DesiredObjects(desired))
		if err != nil {
			entry.LastError = err.Error()
			if firstErr == nil {
				firstErr = fmt.Errorf("firewall apply %s: %w", instCfg.ID, err)
			}
			continue
		}
		entry.Generation = result.Generation
		entry.LastError = ""
	}

	if firstErr != nil {
		summary.LastError = firstErr.Error()
	} else {
		summary.LastError = ""
	}

	if err := d.commitFirewallReconcileResult(rev, summary); err != nil {
		return fmt.Errorf("save firewall reconcile state: %w", err)
	}
	return firstErr
}

func getOrCreateFirewallEntry(state *firewallReconcileState, id string) *firewallInstanceReconcileStateEntry {
	if state.Instances == nil {
		state.Instances = make(map[string]*firewallInstanceReconcileStateEntry)
	}
	entry := state.Instances[id]
	if entry == nil {
		entry = &firewallInstanceReconcileStateEntry{}
		state.Instances[id] = entry
	}
	return entry
}

func (d *DaemonService) commitFirewallReconcileResult(rev uint64, summary *firewallReconcileState) error {
	if d == nil || d.StateStore == nil || summary == nil {
		return nil
	}
	_, committed, err := d.StateStore.CommitIfRevision(rev, func(state *stateFile) error {
		state.FirewallReconcile = cloneFirewallReconcileState(summary)
		return nil
	})
	if err != nil {
		return err
	}
	if !committed {
		current := d.StateStore.Meta().Revision
		_, retryCommitted, retryErr := d.StateStore.CommitIfRevision(current, func(state *stateFile) error {
			state.FirewallReconcile = cloneFirewallReconcileState(summary)
			return nil
		})
		if retryErr != nil {
			return retryErr
		}
		if !retryCommitted {
			d.firewallDirty = true
			d.publishStateStoreRuntimeFlags()
			return nil
		}
		d.firewallDirty = true
		d.publishStateStoreRuntimeFlags()
		return d.installAndSaveCommittedState()
	}
	return d.installAndSaveCommittedState()
}

func firewallOwnerScope(spec firewall.FirewallInstanceSpec) string {
	if spec.IsHost {
		return "host"
	}
	return spec.NetNS
}

// firewallDriverInstance returns the configured firewall driver for one
// instance, or nil to fall back to dry-run.
func (d *DaemonService) firewallDriverInstance(inst FirewallInstanceConfig) (firewallDriver, error) {
	if d == nil || d.Sync == nil || d.Sync.App == nil || d.Sync.App.Config == nil {
		return nil, nil
	}
	if d.firewallDriver != nil {
		return d.firewallDriver, nil
	}
	pf := firewall.PreflightProbe(context.Background())
	if firewall.HasOverlayHooks(inst.Hooks) {
		switch inst.Backend {
		case firewall.BackendNFT:
			return nil, fmt.Errorf("firewall instance %s: nft backend does not support hooks; use backend iptables", inst.ID)
		case "", firewall.BackendAuto:
			if pf.Iptables == "available" {
				inst.Backend = firewall.BackendIptables
			} else {
				return nil, fmt.Errorf("firewall instance %s: hooks require iptables, but iptables is unavailable", inst.ID)
			}
		}
	}
	resolved := firewall.ResolveBackend(inst.Backend, pf)
	switch resolved {
	case firewall.BackendNFT:
		netns, err := firewallDriverNetNS(inst, d.Sync.App.Config)
		if err != nil {
			return nil, err
		}
		driver := firewall.NewNFTDriver()
		driver.NetNS = netns
		return driver, nil
	case firewall.BackendIptables:
		netns, err := firewallDriverNetNS(inst, d.Sync.App.Config)
		if err != nil {
			return nil, err
		}
		driver := firewall.NewIPTablesDriver()
		driver.NetNS = netns
		return driver, nil
	default:
		// dry-run / none
		return nil, nil
	}
}

func firewallDriverNetNS(inst FirewallInstanceConfig, config *appConfig) (string, error) {
	if inst.IsHost {
		return "", nil
	}
	if config == nil {
		return "", nil
	}
	spec, ok := config.Netns.Names[inst.NetNS]
	if !ok {
		return "", fmt.Errorf("netns %q not found", inst.NetNS)
	}
	spec = spec.Normalized()
	switch spec.Kind {
	case ipsec.NetNSHost:
		return "", nil
	case ipsec.NetNSName:
		return spec.Name, nil
	default:
		return "", fmt.Errorf("netns %q kind %q is not supported by firewall CLI drivers", inst.NetNS, spec.Kind)
	}
}

// buildFirewallPolicyInput assembles the verified derived state for the planner.
func buildFirewallPolicyInput(spec firewall.FirewallInstanceSpec, ars *routing.AuthorizedRouteSet, state *stateFile, config *appConfig) firewall.FirewallPolicyInput {
	input := firewall.FirewallPolicyInput{}
	if ars == nil || state == nil {
		return input
	}

	// Local assigned prefixes (AssignedTo == managed zone).
	managedZone := state.ManagedZone
	for prefix, entry := range ars.Assignments {
		if entry.AssignedTo == managedZone {
			input.LocalAssigned = append(input.LocalAssigned, prefix)
		}
	}

	// All authorized mesh prefixes.
	for _, prefixes := range ars.Announced {
		for prefix := range prefixes {
			input.MeshAuthorized = append(input.MeshAuthorized, prefix)
		}
	}

	// Assignment prefixes (import whitelist).
	input.AssignmentPrefixes = assignmentPrefixes(ars)

	// Provider-neutral live Babel-facing interfaces.
	for _, link := range linkOutputsFromState(state) {
		if link.InterfaceName != "" && link.Readiness.Interface == "ready" {
			input.LiveInterfaces = append(input.LiveInterfaces, link.InterfaceName)
		}
	}

	// Upstream interfaces from routing config.
	for _, inst := range config.Routing.Instances {
		if inst.Upstream != nil && inst.Upstream.Enabled && inst.Upstream.MeshInterface != "" {
			input.UpstreamInterfaces = append(input.UpstreamInterfaces, inst.Upstream.MeshInterface)
		}
	}

	// Forwarding policy is owned by the network namespace and shared with BIRD.
	if !spec.IsHost {
		input.Forwarding = netnsForwardingPolicy(config, spec.NetNS)
	}

	// Phase 6.3.7: derive revoked prefixes from the route authorization errors.
	// Any prefix in a revoked zone is excluded from allow sets (deny-first).
	revokedSet := make(map[string]bool)
	for _, e := range ars.Errors {
		if e.Code == "route_zone_revoked" {
			input.Revoked = append(input.Revoked, e.Prefix)
			revokedSet[e.Prefix.String()] = true
		}
	}

	// Advertised current/previous ports for host redirect. Current advertised
	// ports keep ipsec.port_mode=range usable while charon listens on stable
	// 500/4500; previous ports keep rotate grace alive during the configured
	// window.
	if spec.IsHost && state.Network != nil && state.ManagedZone.Valid() {
		now := time.Now()
		if d := nowFunc(); !d.IsZero() {
			now = d
		}
		input.AdvertisedCurrentIKEPorts, input.AdvertisedCurrentNATTPorts, input.AdvertisedPreviousIKEPorts, input.AdvertisedPreviousNATTPorts = extractIPsecRedirectPortsFromNetwork(state.Network, state.ManagedZone, now)
	}

	return input
}

// extractIPsecRedirectPortsFromNetwork reads the signed ipsec/ports record from
// the managed zone's active state and returns current advertised ports plus
// previous-generation ports still within the grace window. These ports are used
// by the host firewall planner to generate DNAT/redirect rules.
func extractIPsecRedirectPortsFromNetwork(network *zone.NetworkState, managedZone zone.ZonePath, now time.Time) (currentIKE []uint16, currentNATT []uint16, previousIKE []uint16, previousNATT []uint16) {
	if network == nil || !managedZone.Valid() {
		return nil, nil, nil, nil
	}
	zs, ok := network.Zones[managedZone]
	if !ok || zs == nil {
		return nil, nil, nil, nil
	}
	record := zs.Records[ipsec.RecordKeyPorts]
	if record == nil {
		return nil, nil, nil, nil
	}
	pr, err := ipsec.ParsePortRecord(record)
	if err != nil || pr == nil {
		return nil, nil, nil, nil
	}
	if pr.Current != nil {
		if pr.Current.IKE.Advertised > 0 {
			currentIKE = append(currentIKE, pr.Current.IKE.Advertised)
		}
		if pr.Current.NATT.Advertised > 0 {
			currentNATT = append(currentNATT, pr.Current.NATT.Advertised)
		}
	}
	for _, sel := range pr.Previous {
		// Check if still within grace window.
		if sel.ValidUntil > 0 && now.Unix() > sel.ValidUntil {
			continue
		}
		if sel.IKE.Advertised > 0 {
			previousIKE = append(previousIKE, sel.IKE.Advertised)
		}
		if sel.NATT.Advertised > 0 {
			previousNATT = append(previousNATT, sel.NATT.Advertised)
		}
	}
	return currentIKE, currentNATT, previousIKE, previousNATT
}

// nowFunc returns the current time. Overridable in tests.
var nowFunc = func() time.Time { return time.Time{} }

// firewallCharonPorts returns the current charon IKE/NAT-T listen ports.
// First version: defaults (500/4500). Future: derive from ipsec port record.
func firewallCharonPorts(_ *appConfig, _ *stateFile) (uint16, uint16) {
	return 500, 4500
}

// flushFirewallReconcile runs firewall reconcile if dirty.
func (d *DaemonService) flushFirewallReconcile(ctx context.Context) bool {
	flushed, err := d.flushFirewallReconcileResult(ctx)
	if err != nil {
		d.logWarn("firewall", "reconcile_failed", map[string]any{"error": err})
	}
	return flushed
}

// flushFirewallReconcileResult is used by security-sensitive control writes
// that must not report success before the new policy reaches the backend.
func (d *DaemonService) flushFirewallReconcileResult(ctx context.Context) (bool, error) {
	if d == nil || !d.firewallDirty {
		return false, nil
	}
	d.firewallDirty = false
	d.noteReconcileFlush("firewall")
	reconcileCtx, cancel := boundedReconcileContext(ctx)
	defer cancel()
	err := d.reconcileFirewall(reconcileCtx)
	d.publishCommittedStateSnapshot()
	return true, err
}

func (d *DaemonService) firewallReconcileInterval() time.Duration {
	if d == nil || d.Sync == nil || d.Sync.App == nil || d.Sync.App.Config == nil {
		return 0
	}
	instances := firewallInstancesEnabled(d.Sync.App.Config)
	if len(instances) == 0 {
		return 0
	}
	return defaultFirewallReconcileInterval
}

func nextFirewallReconcileTime(now time.Time, interval time.Duration) time.Time {
	if interval <= 0 {
		return time.Time{}
	}
	return now.Add(interval)
}

// recoverFirewallOnStart triggers an initial firewall reconcile at daemon start.
func (d *DaemonService) recoverFirewallOnStart(ctx context.Context) {
	if d == nil {
		return
	}
	d.firewallDirty = true
	d.flushFirewallReconcile(ctx)
}
