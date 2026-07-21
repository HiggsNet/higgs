package firewall

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// FirewallDriver is the backend abstraction for firewall apply/observe.
// nftables is the primary backend; iptables is a fallback; dry-run is for tests.
type FirewallDriver interface {
	// Preflight probes backend availability without modifying the system.
	Preflight(ctx context.Context, spec FirewallInstanceSpec) (FirewallPreflight, error)
	// Plan computes the create/update/delete/adopt/noop diff.
	Plan(ctx context.Context, desired *FirewallDesiredState, observed FirewallObservedState) (FirewallPlan, error)
	// Apply executes a plan against the system. Returns generation and errors.
	Apply(ctx context.Context, plan FirewallPlan, desired *FirewallDesiredState) (FirewallApplyResult, error)
	// ListOwned reads currently-owned objects from the system.
	ListOwned(ctx context.Context, owner Owner) (FirewallObservedState, error)
	// DeleteStale removes stale owned objects.
	DeleteStale(ctx context.Context, refs []FirewallObjectRef) error
}

// PlanDiff computes the diff between desired objects and observed owned objects.
// This is pure logic shared by all drivers.
func PlanDiff(instanceID string, desired *FirewallDesiredState, observed FirewallObservedState) FirewallPlan {
	desiredRefs := DesiredObjects(desired)
	desiredSet := make(map[string]bool, len(desiredRefs))
	for _, ref := range desiredRefs {
		desiredSet[objKey(ref)] = true
	}

	observedSet := make(map[string]bool, len(observed.Objects))
	for _, ref := range observed.Objects {
		observedSet[objKey(ref)] = true
	}

	var actions []FirewallPlanAction
	// Create: in desired but not observed.
	for _, ref := range desiredRefs {
		key := objKey(ref)
		if observedSet[key] {
			actions = append(actions, FirewallPlanAction{Action: "adopt", Object: ref, Reason: "already exists"})
		} else {
			actions = append(actions, FirewallPlanAction{Action: "create", Object: ref, Reason: "desired object missing"})
		}
	}
	// Delete: observed but not in desired (stale).
	deletedSet := make(map[string]bool, len(observed.Objects))
	for _, ref := range observed.Objects {
		key := objKey(ref)
		if !desiredSet[key] && !deletedSet[key] {
			actions = append(actions, FirewallPlanAction{Action: "delete", Object: ref, Reason: "stale owned object"})
			deletedSet[key] = true
		}
	}
	return FirewallPlan{InstanceID: instanceID, Actions: actions}
}

func objKey(ref FirewallObjectRef) string {
	return ref.Kind + ":" + ref.Family + ":" + ref.Name
}

// PreflightProbe performs backend auto-detection. It returns the selected
// backend and a preflight summary. It does not modify the system.
func PreflightProbe(ctx context.Context) FirewallPreflight {
	pf := FirewallPreflight{
		Backend:     BackendNFT,
		NFTNetlink:  "unavailable",
		CAPNetAdmin: "unknown",
	}

	// Check nft binary availability (proxy for nftables support).
	if path, err := exec.LookPath("nft"); err == nil {
		_ = path
		pf.NFTNetlink = "ok"
		pf.Backend = BackendNFT
	} else {
		pf.NFTNetlink = "unavailable"
	}

	// Check iptables fallback.
	if iptPath, err := exec.LookPath("iptables"); err == nil {
		_ = iptPath
		pf.Iptables = "available"
		if pf.Backend == BackendAuto || pf.NFTNetlink != "ok" {
			pf.Backend = BackendIptables
		}
		// Detect variant: iptables-nft vs iptables-legacy.
		pf.IptablesVariant = detectIptablesVariant()
	} else {
		pf.Iptables = "unavailable"
	}

	// If nothing available, fall back to none/dry-run.
	if pf.NFTNetlink != "ok" && pf.Iptables != "available" {
		pf.Backend = BackendNone
	}

	// CAP_NET_ADMIN check (best-effort, doesn't fail on non-Linux).
	pf.CAPNetAdmin = checkCAPNETAdmin()

	return pf
}

func detectIptablesVariant() string {
	// iptables -V typically prints "iptables vX.Y (nf_tables)" or "(legacy)".
	out, err := exec.Command("iptables", "-V").CombinedOutput()
	if err != nil {
		return "unknown"
	}
	s := string(out)
	if strings.Contains(s, "nf_tables") {
		return "nft"
	}
	if strings.Contains(s, "legacy") {
		return "legacy"
	}
	return "unknown"
}

func checkCAPNETAdmin() string {
	// Best-effort: try creating a dummy nft table in a throwaway namespace.
	// On non-root/non-Linux, return "missing".
	// We avoid actually requiring netlink; use `nft list tables` as a probe.
	if _, err := exec.LookPath("nft"); err != nil {
		return "missing"
	}
	cmd := exec.Command("nft", "list", "tables")
	if err := cmd.Run(); err != nil {
		return "missing"
	}
	return "ok"
}

// ResolveBackend maps a configured backend to a concrete one based on preflight.
func ResolveBackend(configured string, pf FirewallPreflight) string {
	switch configured {
	case BackendNFT:
		if pf.NFTNetlink == "ok" {
			return BackendNFT
		}
		return BackendNone
	case BackendIptables:
		if pf.Iptables == "available" {
			return BackendIptables
		}
		return BackendNone
	case BackendNone:
		return BackendNone
	case "", BackendAuto:
		return pf.Backend
	default:
		return BackendNone
	}
}

// ResolveBackendForInstance applies hook compatibility constraints before the
// ordinary availability-based backend selection. It never silently ignores a
// backend-native hook block.
func ResolveBackendForInstance(spec FirewallInstanceSpec, pf FirewallPreflight) (string, error) {
	configured := spec.Backend
	hasNFTInline := HasNFTInlineHooks(spec.NativeHooks)
	hasIPTablesInline := HasIPTablesInlineHooks(spec.NativeHooks)
	if HasOverlayHooks(spec.Hooks) {
		switch configured {
		case BackendNFT:
			return BackendNone, fmt.Errorf("firewall instance %s: nft backend does not support legacy chain hooks; use backend iptables", spec.ID)
		case "", BackendAuto:
			if pf.Iptables != "available" {
				return BackendNone, fmt.Errorf("firewall instance %s: legacy chain hooks require iptables, but iptables is unavailable", spec.ID)
			}
			configured = BackendIptables
		}
	}
	switch configured {
	case BackendNFT:
		if hasIPTablesInline && !hasNFTInline {
			return BackendNone, fmt.Errorf("firewall instance %s: backend nft has only iptables_hooks configured", spec.ID)
		}
	case BackendIptables:
		if hasNFTInline && !hasIPTablesInline {
			return BackendNone, fmt.Errorf("firewall instance %s: backend iptables has only nft_hooks configured", spec.ID)
		}
	case "", BackendAuto:
		switch {
		case hasNFTInline && !hasIPTablesInline:
			if pf.NFTNetlink != "ok" {
				return BackendNone, fmt.Errorf("firewall instance %s: nft_hooks require nft, but nft is unavailable", spec.ID)
			}
			configured = BackendNFT
		case hasIPTablesInline && !hasNFTInline:
			if pf.Iptables != "available" {
				return BackendNone, fmt.Errorf("firewall instance %s: iptables_hooks require iptables, but iptables is unavailable", spec.ID)
			}
			configured = BackendIptables
		}
	}
	return ResolveBackend(configured, pf), nil
}

// MergeConflicts scans observed state for potential non-Higgs conflicts.
// First version is conservative: returns empty (no conflict detection beyond
// owner matching, which is handled by ListOwned).
func MergeConflicts(observed FirewallObservedState) []string {
	_ = observed
	return nil
}

var _ = fmt.Sprintf
