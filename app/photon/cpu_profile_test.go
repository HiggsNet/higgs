package main

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestRunWithBoundedCPUProfileDisabled(t *testing.T) {
	runs := 0
	err := runWithBoundedCPUProfile(context.Background(), "", defaultCPUProfileDuration, cpuProfileHooks{}, func() error {
		runs++
		return nil
	})
	if err != nil || runs != 1 {
		t.Fatalf("disabled profile result = %v, runs = %d", err, runs)
	}
}

func TestRunWithBoundedCPUProfileStopsAtDeadline(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cpu.pprof")
	stopped := make(chan struct{})
	var starts atomic.Int32
	var stops atomic.Int32
	var output io.Writer
	hooks := cpuProfileHooks{
		start: func(w io.Writer) error {
			output = w
			starts.Add(1)
			return nil
		},
		stop: func() {
			stops.Add(1)
			_, _ = io.WriteString(output, "profile")
			close(stopped)
		},
	}
	err := runWithBoundedCPUProfile(context.Background(), path, 10*time.Millisecond, hooks, func() error {
		<-stopped
		return nil
	})
	if err != nil {
		t.Fatalf("runWithBoundedCPUProfile: %v", err)
	}
	if starts.Load() != 1 || stops.Load() != 1 {
		t.Fatalf("profile starts/stops = %d/%d", starts.Load(), stops.Load())
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 || info.Size() == 0 {
		t.Fatalf("profile mode/size = %o/%d", info.Mode().Perm(), info.Size())
	}
}

func TestRunWithBoundedCPUProfileStopsWhenDaemonReturns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cpu.pprof")
	var stops atomic.Int32
	wantErr := errors.New("daemon stopped")
	err := runWithBoundedCPUProfile(context.Background(), path, time.Minute, cpuProfileHooks{
		start: func(io.Writer) error { return nil },
		stop:  func() { stops.Add(1) },
	}, func() error { return wantErr })
	if !errors.Is(err, wantErr) || stops.Load() != 1 {
		t.Fatalf("early return result = %v, stops = %d", err, stops.Load())
	}
}

func TestRunWithBoundedCPUProfileRejectsUnsafeOptions(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		duration time.Duration
		want     string
	}{
		{name: "relative path", path: "cpu.pprof", duration: time.Minute, want: "must be absolute"},
		{name: "zero duration", path: filepath.Join(t.TempDir(), "zero.pprof"), duration: 0, want: "greater than zero"},
		{name: "excessive duration", path: filepath.Join(t.TempDir(), "long.pprof"), duration: maxCPUProfileDuration + time.Second, want: "at most"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := runWithBoundedCPUProfile(context.Background(), test.path, test.duration, runtimeCPUProfileHooks, func() error {
				t.Fatal("daemon unexpectedly ran")
				return nil
			})
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestRunWithBoundedCPUProfileDoesNotOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cpu.pprof")
	if err := os.WriteFile(path, []byte("keep"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	err := runWithBoundedCPUProfile(context.Background(), path, time.Minute, runtimeCPUProfileHooks, func() error {
		t.Fatal("daemon unexpectedly ran")
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "file exists") {
		t.Fatalf("error = %v, want file exists", err)
	}
	content, err := os.ReadFile(path)
	if err != nil || string(content) != "keep" {
		t.Fatalf("existing profile content = %q, err = %v", content, err)
	}
}
