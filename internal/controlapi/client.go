// Package controlapi contains the transport-level client boundary for the
// local Photon daemon control API. Business DTOs and daemon dispatch remain in
// app/photon until their surface is stable.
package controlapi

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"syscall"
	"time"
)

const (
	DialTimeout = time.Second
	Deadline    = 10 * time.Second
)

// Send exchanges one JSON request/response pair over a Unix domain socket.
func Send(path string, request, response any) error {
	conn, err := net.DialTimeout("unix", path, DialTimeout)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(Deadline))
	if err := json.NewEncoder(conn).Encode(request); err != nil {
		return err
	}
	return json.NewDecoder(conn).Decode(response)
}

// IsUnavailable reports only errors that positively mean no daemon is
// listening. Callers must not enter direct/offline fallback for other errors:
// the daemon may still be alive but unhealthy or inaccessible.
func IsUnavailable(err error) bool {
	return errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ECONNREFUSED)
}
