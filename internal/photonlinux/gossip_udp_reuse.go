package photonlinux

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
)

func setGossipUDPReuseOptions(network, address string, conn syscall.RawConn) error {
	var sockErr error
	if err := conn.Control(func(fd uintptr) {
		if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
			sockErr = fmt.Errorf("set SO_REUSEADDR on %s %s: %w", network, address, err)
			return
		}
		if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
			sockErr = fmt.Errorf("set SO_REUSEPORT on %s %s: %w", network, address, err)
		}
	}); err != nil {
		return err
	}
	return sockErr
}
