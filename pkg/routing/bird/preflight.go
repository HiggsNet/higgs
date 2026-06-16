package bird

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
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

	if versionDetail := c.checkBirdVersion(ctx, birdPath, err); versionDetail != "" {
		out.add("bird-version", true, false, versionDetail)
	}

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

// checkBirdVersion runs `bird --version` and asserts >= 2.0. Returns a detail
// string if the check was performed, or empty if bird is not found.
func (c preflightChecker) checkBirdVersion(ctx context.Context, birdPath string, lookErr error) string {
	if lookErr != nil || birdPath == "" {
		return ""
	}
	output, err := c.Command(ctx, "bird", "--version")
	if err != nil {
		return fmt.Sprintf("bird version check failed: %v", err)
	}
	version := parseBirdVersion(string(output))
	if version == "" {
		return fmt.Sprintf("bird version not parseable: %s", string(output))
	}
	major := parseBirdMajorVersion(version)
	if major < 2 {
		return fmt.Sprintf("bird version %s < 2.0 (Higgs requires BIRD 2.x)", version)
	}
	return fmt.Sprintf("bird version %s", version)
}

// parseBirdVersion extracts the version string from `bird --version` output.
func parseBirdVersion(output string) string {
	// Typical: "BIRD version 2.16" or "BIRD version 3.0.1"
	lines := strings.Split(strings.TrimSpace(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "BIRD version ") {
			return strings.TrimPrefix(line, "BIRD version ")
		}
	}
	return strings.TrimSpace(output)
}

// parseBirdMajorVersion returns the major version number (e.g. 2 for "2.16").
func parseBirdMajorVersion(version string) int {
	parts := strings.SplitN(version, ".", 2)
	if len(parts) == 0 {
		return 0
	}
	var major int
	_, _ = fmt.Sscanf(parts[0], "%d", &major)
	return major
}

func detailForPath(name, path string, err error) string {
	if err == nil {
		return fmt.Sprintf("%s found at %s", name, path)
	}
	return fmt.Sprintf("%s not found on PATH: %v", name, err)
}
