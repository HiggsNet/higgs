package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestVersionCommandUsesPhotonWindowsName(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"version"}, &stdout, &stderr); code != 0 {
		t.Fatalf("run(version) code = %d, stderr = %q", code, stderr.String())
	}
	if !strings.HasPrefix(stdout.String(), "photon-windows ") {
		t.Fatalf("version output = %q", stdout.String())
	}
}

func TestUnknownCommandDoesNotAdvertiseRuntimeReady(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"run"}, &stdout, &stderr); code != 2 {
		t.Fatalf("run(run) code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "not advertised as ready") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}
