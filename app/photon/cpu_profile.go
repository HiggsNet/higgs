package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/pprof"
	"sync"
	"time"
)

const (
	defaultCPUProfileDuration = 5 * time.Minute
	maxCPUProfileDuration     = 30 * time.Minute
)

type cpuProfileHooks struct {
	start func(io.Writer) error
	stop  func()
}

var runtimeCPUProfileHooks = cpuProfileHooks{
	start: pprof.StartCPUProfile,
	stop:  pprof.StopCPUProfile,
}

func daemonRunProfiled(ctx context.Context, interval time.Duration, path string, duration time.Duration) error {
	return runWithBoundedCPUProfile(ctx, path, duration, runtimeCPUProfileHooks, func() error {
		return daemonRun(ctx, interval)
	})
}

func runWithBoundedCPUProfile(ctx context.Context, path string, duration time.Duration, hooks cpuProfileHooks, run func() error) error {
	if path == "" {
		return run()
	}
	if !filepath.IsAbs(path) {
		return fmt.Errorf("cpu profile path must be absolute: %q", path)
	}
	if duration <= 0 || duration > maxCPUProfileDuration {
		return fmt.Errorf("cpu profile duration must be greater than zero and at most %s", maxCPUProfileDuration)
	}
	if hooks.start == nil || hooks.stop == nil {
		return errors.New("cpu profile hooks are incomplete")
	}

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create cpu profile %s: %w", path, err)
	}
	if err := hooks.start(file); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return fmt.Errorf("start cpu profile: %w", err)
	}
	fmt.Fprintf(os.Stderr, "photon: cpu profile started path=%s duration=%s\n", path, duration)

	var once sync.Once
	var closeErr error
	done := make(chan struct{})
	stopProfile := func() {
		once.Do(func() {
			hooks.stop()
			closeErr = file.Close()
			fmt.Fprintf(os.Stderr, "photon: cpu profile completed path=%s\n", path)
			close(done)
		})
		<-done
	}
	timer := time.AfterFunc(duration, stopProfile)
	runErr := run()
	timer.Stop()
	stopProfile()
	if closeErr != nil {
		closeErr = fmt.Errorf("close cpu profile %s: %w", path, closeErr)
	}
	return errors.Join(runErr, closeErr)
}
