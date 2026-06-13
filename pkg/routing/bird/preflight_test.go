package bird

import (
	"context"
	"errors"
	"testing"
)

func TestBirdPreflightMissingBinaries(t *testing.T) {
	checker := preflightChecker{
		GOOS: "linux",
		LookPath: func(name string) (string, error) {
			return "", errors.New("not found")
		},
		Command: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			return nil, errors.New("not found")
		},
	}
	result := checker.Run(context.Background())
	if result.Ready() {
		t.Fatalf("expected not ready when binaries are missing")
	}
	errs := result.Errors()
	if len(errs) == 0 {
		t.Fatalf("expected error details")
	}
}

func TestBirdPreflightReady(t *testing.T) {
	checker := preflightChecker{
		GOOS: "linux",
		LookPath: func(name string) (string, error) {
			return "/usr/sbin/" + name, nil
		},
		Command: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			return []byte("ok"), nil
		},
	}
	result := checker.Run(context.Background())
	if !result.Ready() {
		t.Fatalf("expected ready, got errors: %v", result.Errors())
	}
}
