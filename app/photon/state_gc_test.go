package main

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/Catofes/photon/pkg/transport/ipsec"
)

func TestStateGCOnlyPlansUnconfiguredBirdInstances(t *testing.T) {
	config := defaultAppConfig()
	config.Routing = routingConfig{Instances: []RoutingInstance{
		{ID: "main", NetNS: "photon", Enabled: true, Mode: ipsec.RoutingModeManaged},
		// Disabled entries remain configured and must not be treated as orphans.
		{ID: "standby", NetNS: "edge", Enabled: false, Mode: ipsec.RoutingModeDisabled},
	}}
	state := &stateFile{BirdInstances: map[string]*BirdInstanceState{
		"default": {NetNSName: "default"},
		"edge":    {NetNSName: "edge"},
		"photon":  {NetNSName: "photon"},
	}}

	plan := buildStateGCPlan(config, state)
	if len(plan.OrphanBirdInstances) != 1 || plan.OrphanBirdInstances[0] != "default" {
		t.Fatalf("orphan BIRD instances = %#v, want [default]", plan.OrphanBirdInstances)
	}
	if !applyStateGCPlan(state, plan) {
		t.Fatal("applyStateGCPlan = false, want true")
	}
	if _, ok := state.BirdInstances["default"]; ok {
		t.Fatal("default BIRD state was not removed")
	}
	if len(state.BirdInstances) != 2 || state.BirdInstances["photon"] == nil || state.BirdInstances["edge"] == nil {
		t.Fatalf("remaining BIRD state = %#v", state.BirdInstances)
	}
}

func TestStateGCEmptyPlanDoesNotMutateState(t *testing.T) {
	config := defaultAppConfig()
	config.Routing = routingConfig{Instances: []RoutingInstance{{ID: "main", NetNS: "photon", Enabled: true}}}
	state := &stateFile{BirdInstances: map[string]*BirdInstanceState{"photon": {NetNSName: "photon"}}}

	plan := buildStateGCPlan(config, state)
	if len(plan.OrphanBirdInstances) != 0 {
		t.Fatalf("orphan BIRD instances = %#v, want none", plan.OrphanBirdInstances)
	}
	if applyStateGCPlan(state, plan) {
		t.Fatal("applyStateGCPlan = true for empty plan")
	}
}

func TestDaemonStateGCApplyPersistsPlan(t *testing.T) {
	state, syncConfig := buildTestNetworkState(t)
	state.BirdInstances = map[string]*BirdInstanceState{
		"default": {NetNSName: "default"},
		"photon":  {NetNSName: "photon"},
	}
	appConfig := defaultAppConfig()
	appConfig.Routing = routingConfig{Instances: []RoutingInstance{{ID: "main", NetNS: "photon", Enabled: true}}}
	rt := &Runtime{Config: appConfig, StatePath: filepath.Join(t.TempDir(), "photon.db")}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	service := newDaemonService(rt, state, syncConfig, time.Second)

	preview, err := service.handleStateGCEvent(false)
	if err != nil {
		t.Fatalf("state GC preview: %v", err)
	}
	if len(preview.OrphanBirdInstances) != 1 || preview.OrphanBirdInstances[0] != "default" {
		t.Fatalf("preview = %#v, want default orphan", preview)
	}
	if _, ok := state.BirdInstances["default"]; !ok {
		t.Fatal("preview mutated state")
	}

	applied, err := service.handleStateGCEvent(true)
	if err != nil {
		t.Fatalf("state GC apply: %v", err)
	}
	if len(applied.OrphanBirdInstances) != 1 || applied.OrphanBirdInstances[0] != "default" {
		t.Fatalf("applied plan = %#v, want default orphan", applied)
	}
	reloaded, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if _, ok := reloaded.BirdInstances["default"]; ok {
		t.Fatalf("stale default BIRD state remained: %#v", reloaded.BirdInstances)
	}
	if reloaded.BirdInstances["photon"] == nil {
		t.Fatalf("configured photon BIRD state was removed: %#v", reloaded.BirdInstances)
	}
}
