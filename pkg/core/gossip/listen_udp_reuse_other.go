//go:build !linux

package gossip

import "syscall"

func setUDPReuseOptions(network, address string, conn syscall.RawConn) error {
	return nil
}
