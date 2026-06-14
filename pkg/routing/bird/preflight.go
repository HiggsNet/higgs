package bird

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"time"
)

// PreflightCheck is a single BIRD readiness check result.
type PreflightCheck struct {
	Name    string
	OK      bool
	Skipped bool
	Detail  string
}

// PreflightResult aggregates BIRD preflight checks.
type PreflightResult struct {
	Checks []PreflightCheck
}

// Ready reports whether all non-skipped checks passed.
func (r PreflightResult) Ready() bool {
	for _, check := range r.Checks {
		if !check.OK && !check.Skipped {
			return false
		}
	}
	return true
}

// Errors returns the details of failed checks.
func (r PreflightResult) Errors() []string {
	var errs []string
	for _, check := range r.Checks {
		if !check.OK && !check.Skipped {
			errs = append(errs, check.Name+": "+check.Detail)
		}
	}
	return errs
}

type preflightChecker struct {
	GOOS     string
	LookPath func(string) (string, error)
	Command  func(context.Context, string, ...string) ([]byte, error)
}

// BirdPreflight checks for BIRD binary and ip netns availability.
// This can be invoked from `higgs debug preflight` later; for now it is
// exposed as a standalone function.
func BirdPreflight(ctx context.Context) PreflightResult {
	return defaultPreflightChecker().Run(ctx)
}

func defaultPreflightChecker() preflightChecker {
	return preflightChecker{}
}

func (c preflightChecker) Run(ctx context.Context) PreflightResult {
	c = c.withDefaults()
	out := PreflightResult{}
	out.add("linux", c.GOOS == "linux", false, fmt.Sprintf("GOOS=%s", c.GOOS))

	birdPath, err := c.LookPath("bird")
	out.add("bird-binary", err == nil, false, detailForPath("bird", birdPath, err))

	birdcPath, err := c.LookPath("birdc")
	out.add("birdc-binary", err == nil, false, detailForPath("birdc", birdcPath, err))

	ipPath, err := c.LookPath("ip")
	out.add("iproute2-ip", err == nil, false, detailForPath("ip", ipPath, err))

	out.add("iproute2-netns", c.commandSucceeds(ctx, "ip", "netns", "list"), false, "requires ip netns support")

	return out
}

func (c preflightChecker) withDefaults() preflightChecker {
	if c.GOOS == "" {
		c.GOOS = runtime.GOOS
	}
	if c.LookPath == nil {
		c.LookPath = exec.LookPath
	}
	if c.Command == nil {
		c.Command = func(ctx context.Context, name string, args ...string) ([]byte, error) {
			cmdCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			defer cancel()
			return exec.CommandContext(cmdCtx, name, args...).CombinedOutput()
		}
	}
	return c
}

func (c preflightChecker) commandSucceeds(ctx context.Context, name string, args ...string) bool {
	_, err := c.Command(ctx, name, args...)
	return err == nil
}

func (r *PreflightResult) add(name string, ok bool, skipped bool, detail string) {
	r.Checks = append(r.Checks, PreflightCheck{Name: name, OK: ok, Skipped: skipped, Detail: detail})
}

func detailForPath(name, path string, err error) string {
	if err == nil {
		return fmt.Sprintf("%s found at %s", name, path)
	}
	return fmt.Sprintf("%s not found on PATH: %v", name, err)
}
