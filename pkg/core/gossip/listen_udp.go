package gossip

import (
	"context"
	"fmt"
	"net"
)

func listenUDP(addr *net.UDPAddr) (*net.UDPConn, error) {
	listenConfig := net.ListenConfig{
		Control: setUDPReuseOptions,
	}
	packetConn, err := listenConfig.ListenPacket(context.Background(), "udp", addr.String())
	if err != nil {
		return nil, err
	}
	conn, ok := packetConn.(*net.UDPConn)
	if !ok {
		_ = packetConn.Close()
		return nil, fmt.Errorf("listen udp returned %T, want *net.UDPConn", packetConn)
	}
	return conn, nil
}
