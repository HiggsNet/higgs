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

func buildStateGCPlan(config *appConfig, instances map[string]*BirdInstanceState) *stateGCPlan {
	plan := &stateGCPlan{}
	if len(instances) == 0 {
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
	for netns := range instances {
		if _, ok := configured[netns]; !ok {
			plan.OrphanBirdInstances = append(plan.OrphanBirdInstances, netns)
		}
	}
	sort.Strings(plan.OrphanBirdInstances)
	return plan
}

func applyStateGCPlan(runtime *linuxRuntimeState, plan *stateGCPlan) bool {
	if runtime == nil || plan == nil || len(plan.OrphanBirdInstances) == 0 {
		return false
	}
	for _, netns := range plan.OrphanBirdInstances {
		delete(runtime.BirdInstances, netns)
	}
	return true
}

func (d *DaemonService) handleStateGCEvent(apply bool) (*stateGCPlan, error) {
	if d == nil || d.Sync == nil || d.Sync.App == nil || d.Sync.App.Config == nil {
		return nil, fmt.Errorf("daemon service is not initialized")
	}
	d.StateStore.mu.RLock()
	instances := cloneBirdInstances(d.StateStore.runtime.BirdInstances)
	revision := d.StateStore.revision
	d.StateStore.mu.RUnlock()
	plan := buildStateGCPlan(d.Sync.App.Config, instances)
	if !apply {
		return plan, nil
	}
	_, _, err := d.StateStore.commitBirdGCIfRevision(revision, plan.OrphanBirdInstances)
	if err != nil {
		return nil, err
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
	plan, err := garbageCollectStateDirect(rt, apply)
	if err != nil {
		return err
	}
	writeStateGCResult(plan, apply, "directly")
	return nil
}

func garbageCollectStateDirect(rt *Runtime, apply bool) (*stateGCPlan, error) {
	boltStore, startup, err := openLinuxDaemonState(rt)
	if err != nil {
		return nil, err
	}
	defer boltStore.Close()
	defer startup.Common.Close()
	runtimeCandidate := cloneLinuxRuntimeState(startup.Runtime)
	plan := buildStateGCPlan(rt.Config, runtimeCandidate.BirdInstances)
	if apply && applyStateGCPlan(runtimeCandidate, plan) {
		if err := commitLinuxRuntime(boltStore, startup.Common.VerifiedRevision(), runtimeCandidate); err != nil {
			return nil, err
		}
	}
	return plan, nil
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
