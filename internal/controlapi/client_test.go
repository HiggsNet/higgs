package controlapi

import (
	"net"
	"os"
	"syscall"
	"testing"
)

func TestIsUnavailable(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "missing", err: &net.OpError{Op: "dial", Net: "unix", Err: os.ErrNotExist}, want: true},
		{name: "refused", err: &net.OpError{Op: "dial", Net: "unix", Err: syscall.ECONNREFUSED}, want: true},
		{name: "permission", err: &net.OpError{Op: "dial", Net: "unix", Err: os.ErrPermission}, want: false},
		{name: "reset", err: &net.OpError{Op: "read", Net: "unix", Err: syscall.ECONNRESET}, want: false},
		{name: "deadline", err: &net.OpError{Op: "read", Net: "unix", Err: os.ErrDeadlineExceeded}, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsUnavailable(tt.err); got != tt.want {
				t.Fatalf("IsUnavailable(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}
