package firewall

import (
	"context"
	"fmt"
)

// DryRunDriver is a non-root, testable FirewallDriver that records apply
// decisions without touching the system. It is the default driver for dry-run
// mode, unit tests, and non-privileged environments.
type DryRunDriver struct {
	// Backend overrides the reported backend name; defaults to "dry-run".
	Backend string
	// Applied records the most recent apply plans for inspection in tests.
	Applied []FirewallPlan
	// OwnedObjects simulates system state for adopt/delete decisions.
	OwnedObjects []FirewallObjectRef
}

// NewDryRunDriver returns a DryRunDriver with the given simulated owned objects.
func NewDryRunDriver() *DryRunDriver {
	return &DryRunDriver{Backend: "dry-run"}
}

func (d *DryRunDriver) Preflight(ctx context.Context, spec FirewallInstanceSpec) (FirewallPreflight, error) {
	backend := d.Backend
	if backend == "" {
		backend = "dry-run"
	}
	return FirewallPreflight{
		Backend:     backend,
		NFTNetlink:  "dry-run",
		CAPNetAdmin: "dry-run",
		NetNSStatus: "dry-run",
	}, nil
}

func (d *DryRunDriver) Plan(ctx context.Context, desired *FirewallDesiredState, observed FirewallObservedState) (FirewallPlan, error) {
	if desired == nil {
		return FirewallPlan{}, fmt.Errorf("desired state is nil")
	}
	return PlanDiff(desired.Instance.ID, desired, observed), nil
}

func (d *DryRunDriver) Apply(ctx context.Context, plan FirewallPlan, desired *FirewallDesiredState) (FirewallApplyResult, error) {
	if desired != nil && (desired.Instance.Mode == ModeExternal || desired.Instance.Mode == ModeDisabled) {
		return FirewallApplyResult{}, nil
	}
	d.Applied = append(d.Applied, plan)
	result := FirewallApplyResult{
		Generation: 1,
	}
	for _, action := range plan.Actions {
		switch action.Action {
		case "create", "update":
			result.Applied++
		case "delete":
			result.Applied++
		case "adopt":
			// adopt is a noop for apply
		}
	}
	if desired != nil {
		hash := DesiredStateHash(desired)
		_ = hash
		result.Generation = 1
	}
	return result, nil
}

func (d *DryRunDriver) ListOwned(ctx context.Context, owner Owner) (FirewallObservedState, error) {
	return FirewallObservedState{Objects: d.OwnedObjects}, nil
}

func (d *DryRunDriver) DeleteStale(ctx context.Context, refs []FirewallObjectRef) error {
	return nil
}

// CompiledApplyRecords returns the recorded apply plans for test assertions.
func (d *DryRunDriver) RecordedPlans() []FirewallPlan {
	return d.Applied
}
