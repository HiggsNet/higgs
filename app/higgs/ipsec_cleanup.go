package main

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/Catofes/higgs/pkg/transport/ipsec"
)

func recoveryCleanupIPsec(ctx context.Context) error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	if response, ok, err := cleanupIPsecViaControl(rt); err != nil {
		return err
	} else if ok {
		fmt.Printf("cleaned %d ipsec link(s) via daemon\n", response.CleanedLinks)
		return nil
	}
	cleaned, err := recoveryCleanupIPsecDirect(ctx, rt)
	if err != nil {
		return err
	}
	fmt.Printf("cleaned %d ipsec link(s) directly\n", cleaned)
	return nil
}

func cleanupIPsecViaControl(rt *Runtime) (*controlResponse, bool, error) {
	path := controlSocketPath(rt.Config)
	response, err := sendControlRequest(path, controlRequest{Method: "ipsec_cleanup"})
	if err != nil && isControlSocketUnavailable(err) {
		return nil, false, nil
	}
	return response, true, err
}

func recoveryCleanupIPsecDirect(ctx context.Context, rt *Runtime) (int, error) {
	if rt == nil {
		return 0, errors.New("runtime is nil")
	}
	state, err := rt.LoadState()
	if err != nil {
		return 0, err
	}
	state.Lock()
	defer state.Unlock()
	if len(state.LinkInstances) == 0 {
		markIPsecCleanupSnapshot(state, rt.Now())
		if err := rt.SaveState(state); err != nil {
			return 0, err
		}
		return 0, nil
	}
	drivers, err := newIPsecCleanupDrivers(rt.Config)
	if err != nil {
		return 0, err
	}
	if drivers.close != nil {
		defer func() { _ = drivers.close() }()
	}
	cleaned, err := cleanupIPsecLinkInstances(ctx, state, drivers.ipsecDriver, drivers.xfrmDriver, rt.Now())
	if err != nil {
		return cleaned, err
	}
	if err := rt.SaveState(state); err != nil {
		return cleaned, err
	}
	return cleaned, nil
}

func (d *DaemonService) handleIPsecCleanupEvent(ctx context.Context) (int, error) {
	if d == nil || d.Sync == nil || d.Sync.State == nil || d.Sync.App == nil {
		return 0, errors.New("daemon service is not initialized")
	}
	if len(d.Sync.State.LinkInstances) == 0 {
		markIPsecCleanupSnapshot(d.Sync.State, d.Sync.now())
		if err := d.Sync.saveState(); err != nil {
			return 0, err
		}
		return 0, nil
	}
	ipsecDriver := d.IPsecDriver
	xfrmDriver := d.XFRMDriver
	var closeFn func() error
	if ipsecDriver == nil || xfrmDriver == nil {
		drivers, err := newIPsecCleanupDrivers(d.Sync.App.Config)
		if err != nil {
			return 0, err
		}
		ipsecDriver = drivers.ipsecDriver
		xfrmDriver = drivers.xfrmDriver
		closeFn = drivers.close
	}
	if closeFn != nil {
		defer func() { _ = closeFn() }()
	}
	cleaned, err := cleanupIPsecLinkInstances(ctx, d.Sync.State, ipsecDriver, xfrmDriver, d.Sync.now())
	if err != nil {
		return cleaned, err
	}
	if err := d.Sync.saveState(); err != nil {
		return cleaned, err
	}
	return cleaned, nil
}

func newIPsecCleanupDrivers(config *appConfig) (configuredIPsecDrivers, error) {
	if config == nil {
		return configuredIPsecDrivers{}, errors.New("config is nil")
	}
	driver := config.IPsec.Driver
	if driver == "" {
		driver = ipsecDriverStrongSwan
	}
	switch driver {
	case ipsecDriverDryRun:
		dryRun := &ipsec.DryRunDriver{}
		return configuredIPsecDrivers{ipsecDriver: dryRun, xfrmDriver: dryRun}, nil
	case ipsecDriverStrongSwan:
		client, err := ipsec.NewGoviciClient(config.IPsec.VICISocket)
		if err != nil {
			return configuredIPsecDrivers{}, fmt.Errorf("initialize strongswan vici client: %w", err)
		}
		return configuredIPsecDrivers{
			ipsecDriver: &ipsec.StrongSwanDriver{VICI: client},
			xfrmDriver:  ipsec.NewSystemXFRMDriver(config.IPsec.DefaultNetNS),
			close:       client.Close,
		}, nil
	default:
		return configuredIPsecDrivers{}, fmt.Errorf("unsupported ipsec driver %q", driver)
	}
}

func cleanupIPsecLinkInstances(ctx context.Context, state *stateFile, ipsecDriver ipsec.IPsecDriver, xfrmDriver ipsec.XFRMDriver, now time.Time) (int, error) {
	if state == nil {
		return 0, errors.New("state is nil")
	}
	if ipsecDriver == nil {
		return 0, errors.New("ipsec driver is nil")
	}
	if xfrmDriver == nil {
		return 0, errors.New("xfrm driver is nil")
	}
	instances := linkInstancesToIPsec(state.LinkInstances)
	ids := make([]string, 0, len(instances))
	for id := range instances {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	cleaned := 0
	for _, id := range ids {
		inst := instances[id]
		if err := inst.Owner.Validate(inst); err != nil {
			return cleaned, fmt.Errorf("refuse cleanup of unmanaged ipsec link %s: %w", id, err)
		}
		action := ipsec.ReconcileAction{Action: ipsec.ReconcileActionTeardown, Instance: &inst}
		if _, err := ipsec.ApplyReconcileAction(ctx, ipsecDriver, xfrmDriver, action, ipsec.NetNSSpec{}); err != nil {
			return cleaned, fmt.Errorf("cleanup ipsec link %s: %w", id, err)
		}
		delete(instances, id)
		cleaned++
	}
	state.LinkInstances = linkInstancesFromIPsec(instances)
	markIPsecCleanupSnapshot(state, now)
	return cleaned, nil
}

func cleanupIPsecLinkInstancesByID(ctx context.Context, state *stateFile, ids []string, ipsecDriver ipsec.IPsecDriver, xfrmDriver ipsec.XFRMDriver, now time.Time) (int, error) {
	if state == nil {
		return 0, errors.New("state is nil")
	}
	if len(ids) == 0 {
		return 0, nil
	}
	if ipsecDriver == nil {
		return 0, errors.New("ipsec driver is nil")
	}
	if xfrmDriver == nil {
		return 0, errors.New("xfrm driver is nil")
	}
	instances := linkInstancesToIPsec(state.LinkInstances)
	sortedIDs := append([]string(nil), ids...)
	sort.Strings(sortedIDs)
	cleaned := 0
	for _, id := range sortedIDs {
		inst, ok := instances[id]
		if !ok {
			continue
		}
		if err := inst.Owner.Validate(inst); err != nil {
			return cleaned, fmt.Errorf("refuse cleanup of unmanaged ipsec link %s: %w", id, err)
		}
		action := ipsec.ReconcileAction{Action: ipsec.ReconcileActionTeardown, Instance: &inst}
		if _, err := ipsec.ApplyReconcileAction(ctx, ipsecDriver, xfrmDriver, action, ipsec.NetNSSpec{}); err != nil {
			return cleaned, fmt.Errorf("cleanup ipsec link %s: %w", id, err)
		}
		delete(instances, id)
		cleaned++
	}
	state.LinkInstances = linkInstancesFromIPsec(instances)
	if cleaned > 0 {
		markIPsecCleanupSnapshot(state, now)
	}
	return cleaned, nil
}

func markIPsecCleanupSnapshot(state *stateFile, now time.Time) {
	if state.IPsecReconcile == nil {
		state.IPsecReconcile = &ipsecReconcileState{}
	}
	state.IPsecReconcile.LastRunUnix = now.Unix()
	state.IPsecReconcile.DesiredLinks = 0
	state.IPsecReconcile.LastError = ""
	state.IPsecReconcile.Desired = nil
	state.IPsecReconcile.Actions = nil
	state.IPsecReconcile.ActualSAs = nil
	state.IPsecReconcile.Skipped = nil
}
