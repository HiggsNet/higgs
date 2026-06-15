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
	groups := routingEnabledGroups(d.Sync.App.Config.IPsec.LinkGroups)
	if len(groups) == 0 {
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

	dataDir := d.Sync.App.Config.DataDir
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
	if err := d.autoAnnounceAssignedIPs(ars); err != nil && firstErr == nil {
		firstErr = err
	}

	// If auto-announce is enabled, it may have mutated Sync.State with new
	// route announcements. Rebuild the authorized route set so BIRD import/export
	// filters reflect the latest announcements.
	if d.Sync.App.Config.IPAM.AutoAnnounceAssignedIPs {
		ars, err = routing.BuildAuthorizedRouteSet(d.Sync.State.Network, now)
		if err != nil && firstErr == nil {
			firstErr = fmt.Errorf("rebuild authorized route set after auto-announce: %w", err)
		}
	}

	for _, group := range groups {
		if err := d.reconcileRoutingForGroup(ctx, group, ars, dataDir, now); err != nil && firstErr == nil {
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

func (d *DaemonService) reconcileRoutingForGroup(ctx context.Context, group ipsec.LinkGroupSpec, ars *routing.AuthorizedRouteSet, dataDir string, now time.Time) error {
	overlayID := group.ID
	instState := d.Sync.State.BirdInstances[overlayID]
	if instState == nil {
		instState = &BirdInstanceState{OverlayID: overlayID}
		d.Sync.State.BirdInstances[overlayID] = instState
	}

	routerID := group.Routing.RouterID
	if routerID == 0 {
		if instState.RouterID != 0 {
			routerID = instState.RouterID
		} else {
			routerID = bird.StableRouterID(d.Sync.State.ManagedZone, rootTrustHash(d.Sync.State.Network), overlayID)
		}
	}
	instState.RouterID = routerID

	spec := buildBirdInstanceSpec(group, routerID, dataDir, overlayID)
	instState.ConfigPath = spec.ConfigPath
	instState.ControlSocket = spec.ControlSocketPath
	instState.PIDFile = spec.PIDFilePath

	importSet := assignmentPrefixes(ars)
	exportSet := authorizedPrefixes(ars, []zone.ZonePath{d.Sync.State.ManagedZone})

	configBytes, err := bird.DefaultConfigGenerator{}.Generate(spec, importSet, exportSet)
	if err != nil {
		instState.State = birdInstanceStateError
		instState.LastError = err.Error()
		return fmt.Errorf("generate bird config for overlay %q: %w", overlayID, err)
	}

	configHash := fmt.Sprintf("%x", sha256.Sum256(configBytes))
	configChanged := instState.LastConfigHash == "" || instState.LastConfigHash != configHash

	mode := bird.BirdMode(group.Routing.Mode)
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
				return fmt.Errorf("create bird config dir for overlay %q: %w", overlayID, err)
			}
			if err := os.WriteFile(spec.ConfigPath, configBytes, 0o600); err != nil {
				instState.State = birdInstanceStateError
				instState.LastError = err.Error()
				return fmt.Errorf("write bird config for overlay %q: %w", overlayID, err)
			}
		}

		pm := d.birdProcessManager
		if pm == nil {
			pm = bird.NewExecProcessManager("")
		}
		if !pm.IsRunning(ctx) {
			if err := pm.Start(ctx, spec); err != nil {
				instState.State = birdInstanceStateError
				instState.LastError = err.Error()
				// In dry-run / no bird binary scenarios, still generate config and update state but do not fail hard.
				if !isDryRunMissingBirdError(err) {
					return fmt.Errorf("start bird for overlay %q: %w", overlayID, err)
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
					return fmt.Errorf("configure bird for overlay %q: %w", overlayID, err)
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
				return fmt.Errorf("bird status for overlay %q: %w", overlayID, err)
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

func (d *DaemonService) newBirdClient(socketPath string) birdClient {
	if d.birdClientFactory != nil {
		return d.birdClientFactory(socketPath, 10*time.Second)
	}
	return bird.NewClient(socketPath, 10*time.Second)
}

func buildBirdInstanceSpec(group ipsec.LinkGroupSpec, routerID uint32, dataDir, overlayID string) bird.BirdInstanceSpec {
	routing := group.Routing
	netns := routing.NetNS
	if netns.Kind == "" && netns.Name == "" && netns.Path == "" {
		netns = group.NetNS.Normalized()
	}

	mode := bird.BirdMode(routing.Mode)
	if mode == "" {
		mode = bird.BirdModeManaged
	}

	configDir := filepath.Join(dataDir, "bird")
	return bird.BirdInstanceSpec{
		RouterID:          routerID,
		OverlayID:         overlayID,
		NetNS:             bird.NetNSSpec{Kind: netns.Kind, Name: netns.Name, Path: netns.Path, Create: netns.Create},
		ControlSocketPath: firstNonEmpty(routing.ControlSocket, filepath.Join(configDir, fmt.Sprintf("bird-%s.ctl", overlayID))),
		PIDFilePath:       firstNonEmpty(routing.PIDFile, filepath.Join(configDir, fmt.Sprintf("bird-%s.pid", overlayID))),
		ConfigPath:        firstNonEmpty(routing.ConfigFile, filepath.Join(configDir, fmt.Sprintf("bird-%s.conf", overlayID))),
		TableID:           routing.TableID,
		MetricBase:        routing.MetricBase,
		MetricStaged:      routing.MetricStaged,
		MetricDraining:    routing.MetricDraining,
		InterfacePattern:  routing.InterfacePattern,
		Mode:              mode,
		ECMP:              routing.ECMP,
		ECMPLimit:         routing.ECMPLimit,
	}
}

func routingEnabledGroups(groups []ipsec.LinkGroupSpec) []ipsec.LinkGroupSpec {
	var out []ipsec.LinkGroupSpec
	for _, group := range groups {
		if group.Routing.Enabled {
			out = append(out, group)
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
	// ExecProcessManager returns "bird binary not found on PATH" when bird is absent.
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
