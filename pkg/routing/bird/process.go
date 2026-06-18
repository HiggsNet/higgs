package bird

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ProcessManager owns the BIRD child process in managed mode.
type ProcessManager interface {
	// Start ensures the target netns exists and starts BIRD inside it.
	// If a compatible BIRD process is already running (matching router id,
	// table, and control socket), Start adopts it instead of spawning a new one.
	Start(ctx context.Context, spec BirdInstanceSpec) error

	// Stop gracefully stops the BIRD process and removes Higgs-owned
	// pid/control-socket/config files when ownership checks pass.
	Stop(ctx context.Context, spec BirdInstanceSpec) error

	// IsRunning reports whether the currently managed BIRD process is alive.
	// The implementation is expected to hold the spec it was started with.
	IsRunning(ctx context.Context) bool
}

// ExecProcessManager implements ProcessManager by executing BIRD and ip
// binaries directly.
type ExecProcessManager struct {
	birdBinary string
	runner     func(ctx context.Context, cmd string, args ...string) *exec.Cmd

	mu   sync.Mutex
	pid  int
	spec BirdInstanceSpec

	// socketWaitTimeout is the maximum time to wait for the BIRD control
	// socket to appear after Start. Exported for tests.
	socketWaitTimeout time.Duration
}

// NewExecProcessManager returns an ExecProcessManager that uses birdBinary
// (or looks up "bird" on PATH if empty).
func NewExecProcessManager(birdBinary string) *ExecProcessManager {
	return &ExecProcessManager{
		birdBinary:        birdBinary,
		runner:            exec.CommandContext,
		socketWaitTimeout: 2 * time.Second,
	}
}

var _ ProcessManager = (*ExecProcessManager)(nil)

// Start ensures the target netns exists and starts BIRD inside it.
func (pm *ExecProcessManager) Start(ctx context.Context, spec BirdInstanceSpec) error {
	if spec.Mode != BirdModeManaged {
		return fmt.Errorf("bird process manager only supports mode %q, got %q", BirdModeManaged, spec.Mode)
	}

	if spec.NetNSName == "" {
		return errors.New("bird instance netns_name is required")
	}

	for _, p := range []string{spec.ConfigPath, spec.ControlSocketPath, spec.PIDFilePath} {
		if !filepath.IsAbs(p) {
			return fmt.Errorf("bird path must be absolute: %s", p)
		}
	}

	binary, err := pm.resolveBinary()
	if err != nil {
		return err
	}

	args := []string{
		"-c", spec.ConfigPath,
		"-s", spec.ControlSocketPath,
		"-P", spec.PIDFilePath,
	}

	var cmd *exec.Cmd
	switch spec.NetNS.Kind {
	case "host":
		cmd = pm.runner(ctx, binary, args...)
	case "name":
		if spec.NetNS.Name == "" {
			return errors.New("netns name is required for named netns")
		}
		if spec.NetNS.Create {
			if err := pm.ensureNamedNetNS(ctx, spec.NetNS.Name); err != nil {
				return fmt.Errorf("ensure netns %q: %w", spec.NetNS.Name, err)
			}
		}
		wrapped := append([]string{"netns", "exec", spec.NetNS.Name, binary}, args...)
		cmd = pm.runner(ctx, "ip", wrapped...)
	case "path":
		return errors.New("path netns is not yet supported")
	default:
		return fmt.Errorf("unsupported netns kind %q", spec.NetNS.Kind)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start bird: %w", err)
	}

	pm.mu.Lock()
	pm.pid = cmd.Process.Pid
	pm.spec = spec
	pm.mu.Unlock()

	go func() { _ = cmd.Wait() }()

	if err := pm.waitForSocket(ctx, spec.ControlSocketPath); err != nil {
		_ = cmd.Process.Kill()
		pm.resetState()
		return fmt.Errorf("waiting for control socket: %w", err)
	}

	// BIRD daemonizes and the original process (or the ip netns exec wrapper)
	// exits. Read the real daemon PID from BIRD's pidfile so IsRunning/Stop
	// target the correct process. The pidfile may be created empty before BIRD
	// writes the PID, so retry briefly.
	if daemonPID := pm.waitForPidFile(ctx, spec.PIDFilePath); daemonPID > 0 {
		pm.mu.Lock()
		pm.pid = daemonPID
		pm.mu.Unlock()
	}

	return nil
}

// Stop gracefully stops the BIRD process and removes Higgs-owned files.
func (pm *ExecProcessManager) Stop(ctx context.Context, spec BirdInstanceSpec) error {
	pm.mu.Lock()
	pid := pm.pid
	pm.mu.Unlock()

	const gracefulTimeout = 5 * time.Second

	// Graceful shutdown via birdc if the socket exists.
	if fileExists(spec.ControlSocketPath) {
		shutdownCtx, cancel := context.WithTimeout(ctx, gracefulTimeout)
		defer cancel()

		graceful := pm.runner(shutdownCtx, "birdc", "-s", spec.ControlSocketPath, "down")
		if err := graceful.Run(); err == nil {
			if waitForProcessExit(shutdownCtx, pid, gracefulTimeout) {
				pm.clearManagedState(spec)
				return nil
			}
		}
	}

	// Fallback to SIGTERM if the process is still running.
	if pid > 0 && processIsRunning(pid) {
		proc, err := os.FindProcess(pid)
		if err == nil {
			_ = proc.Signal(syscall.SIGTERM)
			_ = waitForProcessExit(ctx, pid, gracefulTimeout)
		}
	}

	stillRunning := pid > 0 && processIsRunning(pid)
	pm.clearManagedState(spec)
	if stillRunning {
		return fmt.Errorf("failed to stop bird process %d", pid)
	}
	return nil
}

// IsRunning reports whether the currently managed BIRD process is alive.
func (pm *ExecProcessManager) IsRunning(ctx context.Context) bool {
	pm.mu.Lock()
	pid := pm.pid
	pm.mu.Unlock()
	return pid > 0 && processIsRunning(pid)
}

func (pm *ExecProcessManager) resolveBinary() (string, error) {
	if pm.birdBinary != "" {
		if _, err := os.Stat(pm.birdBinary); err != nil {
			return "", fmt.Errorf("bird binary %q: %w", pm.birdBinary, err)
		}
		return pm.birdBinary, nil
	}
	return findBirdBinary()
}

func (pm *ExecProcessManager) resetState() {
	pm.mu.Lock()
	pm.pid = 0
	pm.spec = BirdInstanceSpec{}
	pm.mu.Unlock()
}

func (pm *ExecProcessManager) clearManagedState(spec BirdInstanceSpec) {
	pm.resetState()

	_ = os.Remove(spec.PIDFilePath)
	_ = os.Remove(spec.ControlSocketPath)
	_ = os.Remove(spec.ConfigPath)
}

func (pm *ExecProcessManager) ensureNamedNetNS(ctx context.Context, name string) error {
	return ensureNamedNetNSWithRunner(ctx, name, pm.runner)
}

func (pm *ExecProcessManager) waitForSocket(ctx context.Context, path string) error {
	deadline := time.Now().Add(pm.socketWaitTimeout)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	for {
		if fileExists(path) {
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("control socket %s did not appear within %s", path, pm.socketWaitTimeout)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func waitForProcessExit(ctx context.Context, pid int, timeout time.Duration) bool {
	if pid <= 0 {
		return true
	}
	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	for {
		if !processIsRunning(pid) {
			return true
		}
		if err := ctx.Err(); err != nil {
			return false
		}
		if time.Now().After(deadline) {
			return false
		}
		select {
		case <-ctx.Done():
			return false
		case <-ticker.C:
		}
	}
}

// findBirdBinary locates the BIRD binary on PATH.
func findBirdBinary() (string, error) {
	path, err := exec.LookPath("bird")
	if err != nil {
		return "", fmt.Errorf("bird binary not found on PATH: %w", err)
	}
	return path, nil
}

// ensureNamedNetNS ensures a named network namespace exists, treating
// "already exists" as success.
func ensureNamedNetNS(ctx context.Context, name string) error {
	return ensureNamedNetNSWithRunner(ctx, name, func(ctx context.Context, cmd string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, cmd, args...)
	})
}

func ensureNamedNetNSWithRunner(
	ctx context.Context,
	name string,
	runner func(context.Context, string, ...string) *exec.Cmd,
) error {
	if name == "" {
		return errors.New("netns name is empty")
	}
	cmd := runner(ctx, "ip", "netns", "add", name)
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			stderr := string(exitErr.Stderr)
			if strings.Contains(stderr, "File exists") || strings.Contains(stderr, "already exists") {
				return nil
			}
		}
		return err
	}
	return nil
}

func readPidFile(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, err
	}
	return pid, nil
}

func (pm *ExecProcessManager) waitForPidFile(ctx context.Context, path string) int {
	deadline := time.Now().Add(pm.socketWaitTimeout)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	for {
		if pid, err := readPidFile(path); err == nil && pid > 0 {
			return pid
		}
		if err := ctx.Err(); err != nil {
			return 0
		}
		if time.Now().After(deadline) {
			return 0
		}
		select {
		case <-ctx.Done():
			return 0
		case <-ticker.C:
		}
	}
}

func processIsRunning(pid int) bool {
	if pid <= 0 {
		return false
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	// Signal 0 performs error checking without sending a signal.
	return proc.Signal(syscall.Signal(0)) == nil
}
