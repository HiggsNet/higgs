package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
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
	if d == nil || d.Sync == nil || d.Sync.App == nil || d.Sync.App.Config == nil || d.Sync.State == nil {
		return nil
	}
	config := d.Sync.App.Config
	instances := firewallInstancesEnabled(config)
	if len(instances) == 0 {
		return nil
	}
	if d.Sync.State.ManagedZone.IsRoot() || !d.Sync.State.ManagedZone.Valid() {
		return nil
	}

	now := d.Sync.now()
	if d.Sync.State.FirewallReconcile == nil {
		d.Sync.State.FirewallReconcile = &firewallReconcileState{}
	}
	d.Sync.State.FirewallReconcile.LastRunUnix = now.Unix()

	// Build authorized route set for prefix inputs.
	ars, err := routing.BuildAuthorizedRouteSet(d.Sync.State.Network, now)
	if err != nil {
		d.Sync.State.FirewallReconcile.LastError = err.Error()
		_ = d.Sync.saveState()
		return fmt.Errorf("firewall build authorized route set: %w", err)
	}

	driver := d.firewallDriverInstance()
	if driver == nil {
		driver = firewall.NewDryRunDriver()
	}

	preflight := firewall.PreflightProbe(ctx)
	d.Sync.State.FirewallReconcile.Backend = preflight.Backend

	if d.Sync.State.FirewallReconcile.Instances == nil {
		d.Sync.State.FirewallReconcile.Instances = make(map[string]*firewallInstanceReconcileStateEntry)
	}

	listenAddrs := firewallListenAddrs(config)
	charonIKE, charonNATT := firewallCharonPorts(config, d.Sync.State)

	var firstErr error
	for _, instCfg := range instances {
		spec := firewallInstanceSpecFromConfig(instCfg, listenAddrs, charonIKE, charonNATT)
		input := buildFirewallPolicyInput(spec, ars, d.Sync.State, config)
		desired, err := firewall.BuildDesiredState(spec, input)
		if err != nil {
			entry := d.getOrCreateFirewallEntry(instCfg.ID)
			entry.LastRunUnix = now.Unix()
			entry.LastError = err.Error()
			if firstErr == nil {
				firstErr = fmt.Errorf("firewall instance %s: %w", instCfg.ID, err)
			}
			continue
		}

		owner := firewall.Owner{
			Manager:     "higgs",
			InstanceID:  instCfg.ID,
			OwnerPrefix: instCfg.OwnerPrefix,
			Token:       firewall.OwnerToken(spec),
		}
		observed, _ := driver.ListOwned(ctx, owner)

		plan, err := driver.Plan(ctx, desired, observed)
		if err != nil {
			entry := d.getOrCreateFirewallEntry(instCfg.ID)
			entry.LastRunUnix = now.Unix()
			entry.LastError = err.Error()
			if firstErr == nil {
				firstErr = fmt.Errorf("firewall plan %s: %w", instCfg.ID, err)
			}
			continue
		}

		result, err := driver.Apply(ctx, plan, desired)
		entry := d.getOrCreateFirewallEntry(instCfg.ID)
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
		d.Sync.State.FirewallReconcile.LastError = firstErr.Error()
	} else {
		d.Sync.State.FirewallReconcile.LastError = ""
	}

	if err := d.Sync.saveState(); err != nil {
		return fmt.Errorf("save firewall reconcile state: %w", err)
	}
	return firstErr
}

func (d *DaemonService) getOrCreateFirewallEntry(id string) *firewallInstanceReconcileStateEntry {
	if d.Sync.State.FirewallReconcile.Instances == nil {
		d.Sync.State.FirewallReconcile.Instances = make(map[string]*firewallInstanceReconcileStateEntry)
	}
	entry := d.Sync.State.FirewallReconcile.Instances[id]
	if entry == nil {
		entry = &firewallInstanceReconcileStateEntry{}
		d.Sync.State.FirewallReconcile.Instances[id] = entry
	}
	return entry
}

// firewallDriverInstance returns the configured firewall driver, or nil to
// fall back to dry-run.
func (d *DaemonService) firewallDriverInstance() firewallDriver {
	if d == nil || d.Sync == nil || d.Sync.App == nil || d.Sync.App.Config == nil {
		return nil
	}
	if d.firewallDriver != nil {
		return d.firewallDriver
	}
	// Determine the effective backend from config + preflight.
	instances := firewallInstancesEnabled(d.Sync.App.Config)
	if len(instances) == 0 {
		return nil
	}
	// Use the first enabled instance's backend as the global selection.
	backend := instances[0].Backend
	pf := firewall.PreflightProbe(context.Background())
	resolved := firewall.ResolveBackend(backend, pf)
	switch resolved {
	case firewall.BackendNFT:
		return firewall.NewNFTDriver()
	case firewall.BackendIptables:
		return firewall.NewIPTablesDriver()
	default:
		// dry-run / none
		return nil
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

	// Live link interfaces from LinkInstances.
	for _, li := range state.LinkInstances {
		if li.InterfaceName != "" && li.ActualState != "" && li.ActualState != "removing" {
			input.LiveInterfaces = append(input.LiveInterfaces, li.InterfaceName)
		}
	}

	// Upstream interfaces from routing config.
	for _, inst := range config.Routing.Instances {
		if inst.Upstream != nil && inst.Upstream.Enabled && inst.Upstream.Interface != "" {
			input.UpstreamInterfaces = append(input.UpstreamInterfaces, inst.Upstream.Interface)
		}
	}

	// Forwarding policy from matching firewall instance config.
	for _, fi := range config.Firewall.Instances {
		if fi.ID == spec.ID {
			input.Forwarding = fi.Forwarding
			break
		}
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

	// Advertised previous ports (for host redirect grace).
	// Extract previous IKE/NAT-T ports from the active state's signed
	// ipsec/ports record so the host firewall can redirect old advertised
	// ports to the current charon listen port during the grace window
	// (Phase 6.3.5).
	if spec.IsHost && state.Network != nil && state.ManagedZone.Valid() {
		now := time.Now()
		if d := nowFunc(); !d.IsZero() {
			now = d
		}
		input.AdvertisedPreviousIKEPorts, input.AdvertisedPreviousNATTPorts = extractPreviousPortsFromNetwork(state.Network, state.ManagedZone, now)
	}

	return input
}

// extractPreviousPortsFromNetwork reads the signed ipsec/ports record from the
// managed zone's active state and returns the previous-generation IKE and NAT-T
// advertised ports that are still within the grace window. These ports are used
// by the host firewall planner to generate DNAT/redirect rules.
func extractPreviousPortsFromNetwork(network *zone.NetworkState, managedZone zone.ZonePath, now time.Time) ([]uint16, []uint16) {
	if network == nil || !managedZone.Valid() {
		return nil, nil
	}
	zs, ok := network.Zones[managedZone]
	if !ok || zs == nil {
		return nil, nil
	}
	record := zs.Records[ipsec.RecordKeyPorts]
	if record == nil {
		return nil, nil
	}
	pr, err := ipsec.ParsePortRecord(record)
	if err != nil || pr == nil {
		return nil, nil
	}
	var ikePorts, nattPorts []uint16
	for _, sel := range pr.Previous {
		// Check if still within grace window.
		if sel.ValidUntil > 0 && now.Unix() > sel.ValidUntil {
			continue
		}
		if sel.IKE.Advertised > 0 {
			ikePorts = append(ikePorts, sel.IKE.Advertised)
		}
		if sel.NATT.Advertised > 0 {
			nattPorts = append(nattPorts, sel.NATT.Advertised)
		}
	}
	return ikePorts, nattPorts
}

// nowFunc returns the current time. Overridable in tests.
var nowFunc = func() time.Time { return time.Time{} }

// firewallListenAddrs derives host listen addresses from config.
func firewallListenAddrs(config *appConfig) []netip.Addr {
	var out []netip.Addr
	for _, addr := range config.AdvertiseAddrs {
		if ip, err := netip.ParseAddr(addr); err == nil {
			out = append(out, ip)
			continue
		}
		// Try host:port split
		if host, _, err := net.SplitHostPort(addr); err == nil {
			if ip, err := netip.ParseAddr(host); err == nil {
				out = append(out, ip)
			}
		}
	}
	return out
}

// firewallCharonPorts returns the current charon IKE/NAT-T listen ports.
// First version: defaults (500/4500). Future: derive from ipsec port record.
func firewallCharonPorts(config *appConfig, state *stateFile) (uint16, uint16) {
	return 500, 4500
}

// flushFirewallReconcile runs firewall reconcile if dirty.
func (d *DaemonService) flushFirewallReconcile(ctx context.Context) bool {
	if d == nil || !d.firewallDirty {
		return false
	}
	d.firewallDirty = false
	d.noteReconcileFlush("firewall")
	if err := d.reconcileFirewall(ctx); err != nil {
		d.logWarn("firewall", "reconcile_failed", map[string]any{"error": err})
	}
	return true
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
