package main

import (
	"fmt"
	"sort"
)

// stateGCPlan lists local runtime state that no current configuration can
// reference. It intentionally does not manage external processes or kernel
// resources: those require their own explicit lifecycle operations.
type stateGCPlan struct {
	OrphanBirdInstances []string `json:"orphan_bird_instances,omitempty"`
}

func buildStateGCPlan(config *appConfig, state *stateFile) *stateGCPlan {
	plan := &stateGCPlan{}
	if state == nil || len(state.BirdInstances) == 0 {
		return plan
	}
	configured := make(map[string]struct{})
	if config != nil {
		for _, inst := range config.Routing.Instances {
			// Keep disabled entries too: they are still explicit configuration and
			// can be re-enabled without reconstructing their diagnostic state.
			configured[inst.NetNS] = struct{}{}
		}
	}
	for netns := range state.BirdInstances {
		if _, ok := configured[netns]; !ok {
			plan.OrphanBirdInstances = append(plan.OrphanBirdInstances, netns)
		}
	}
	sort.Strings(plan.OrphanBirdInstances)
	return plan
}

func applyStateGCPlan(state *stateFile, plan *stateGCPlan) bool {
	if state == nil || plan == nil || len(plan.OrphanBirdInstances) == 0 {
		return false
	}
	for _, netns := range plan.OrphanBirdInstances {
		delete(state.BirdInstances, netns)
	}
	return true
}

func (d *DaemonService) handleStateGCEvent(apply bool) (*stateGCPlan, error) {
	if d == nil || d.Sync == nil || d.Sync.App == nil || d.Sync.App.Config == nil {
		return nil, fmt.Errorf("daemon service is not initialized")
	}
	var plan *stateGCPlan
	if !apply {
		return d.StateStore.stateGCPlanProjection(d.Sync.App.Config), nil
	}
	state, revision := d.StateStore.Snapshot()
	plan = buildStateGCPlan(d.Sync.App.Config, state)
	_, _, err := d.StateStore.commitBirdGCIfRevision(revision, plan.OrphanBirdInstances)
	if err != nil {
		return nil, err
	}
	if plan == nil {
		plan = d.StateStore.stateGCPlanProjection(d.Sync.App.Config)
	}
	return plan, nil
}

func garbageCollectState(apply, direct bool) error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	rt.DisableControl = direct
	if response, ok, err := stateGCViaControl(rt, apply); err != nil {
		return err
	} else if ok {
		writeStateGCResult(response.StateGC, apply, "via daemon")
		return nil
	}
	state, err := rt.LoadState()
	if err != nil {
		return err
	}
	state.Lock()
	defer state.Unlock()
	plan := buildStateGCPlan(rt.Config, state)
	if apply && applyStateGCPlan(state, plan) {
		if err := rt.SaveState(state); err != nil {
			return err
		}
	}
	writeStateGCResult(plan, apply, "directly")
	return nil
}

func writeStateGCResult(plan *stateGCPlan, apply bool, source string) {
	if plan == nil || len(plan.OrphanBirdInstances) == 0 {
		fmt.Printf("no stale runtime state found %s\n", source)
		return
	}
	verb := "would remove"
	if apply {
		verb = "removed"
	}
	for _, netns := range plan.OrphanBirdInstances {
		fmt.Printf("%s stale BIRD state for netns %s %s\n", verb, netns, source)
	}
}
