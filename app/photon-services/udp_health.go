package main

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"time"
)

func checkSOCKS5UDPDNS(proxyAddress string, resolver resolverConfig, timeout time.Duration) error {
	target, err := udpDNSProbeTarget(resolver.Servers)
	if err != nil {
		return err
	}
	control, err := net.DialTimeout("tcp", proxyAddress, timeout)
	if err != nil {
		return err
	}
	defer control.Close()
	if err := control.SetDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	if _, err := control.Write([]byte{5, 1, 0}); err != nil {
		return err
	}
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(control, greeting); err != nil {
		return err
	}
	if greeting[0] != 5 || greeting[1] != 0 {
		return fmt.Errorf("SOCKS5 NO AUTH negotiation returned %x", greeting)
	}
	if _, err := control.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return err
	}
	relay, err := readSOCKS5Reply(control)
	if err != nil {
		return err
	}
	proxyHost, _, err := net.SplitHostPort(proxyAddress)
	if err != nil {
		return err
	}
	if relay.IP == nil || relay.IP.IsUnspecified() {
		relay.IP = net.ParseIP(strings.Trim(proxyHost, "[]"))
	}
	if relay.IP == nil || relay.Port == 0 {
		return fmt.Errorf("SOCKS5 UDP ASSOCIATE returned unusable relay %s", relay)
	}
	network := "udp6"
	if relay.IP.To4() != nil {
		network = "udp4"
	}
	udp, err := net.ListenUDP(network, nil)
	if err != nil {
		return err
	}
	defer udp.Close()
	if err := udp.SetDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	query, id, err := dnsHealthQuery()
	if err != nil {
		return err
	}
	packet := append(socks5UDPHeader(target), query...)
	if _, err := udp.WriteToUDP(packet, relay); err != nil {
		return err
	}
	response := make([]byte, 65535)
	n, source, err := udp.ReadFromUDP(response)
	if err != nil {
		return err
	}
	if !source.IP.Equal(relay.IP) || source.Port != relay.Port {
		return fmt.Errorf("UDP reply source %s does not match relay %s", source, relay)
	}
	_, dns, err := parseSOCKS5UDPDatagram(response[:n])
	if err != nil {
		return err
	}
	if len(dns) < 12 {
		return fmt.Errorf("short DNS response: %d bytes", len(dns))
	}
	if binary.BigEndian.Uint16(dns[:2]) != id {
		return fmt.Errorf("DNS response ID %04x does not match request %04x", binary.BigEndian.Uint16(dns[:2]), id)
	}
	if dns[2]&0x80 == 0 || dns[3]&0x0f != 0 {
		return fmt.Errorf("DNS response flags indicate failure: %02x%02x", dns[2], dns[3])
	}
	if answers := binary.BigEndian.Uint16(dns[6:8]); answers == 0 {
		return fmt.Errorf("DNS response contains no answers")
	}
	return nil
}

func udpDNSProbeTarget(servers []string) (*net.UDPAddr, error) {
	for _, server := range servers {
		candidate := strings.TrimSpace(server)
		if strings.Contains(candidate, "://") {
			parsed, err := url.Parse(candidate)
			if err != nil || (parsed.Scheme != "udp" && parsed.Scheme != "dns") {
				continue
			}
			candidate = parsed.Host
		}
		if candidate == "" {
			continue
		}
		if ip := net.ParseIP(strings.Trim(candidate, "[]")); ip != nil {
			return &net.UDPAddr{IP: ip, Port: 53}, nil
		}
		if _, _, err := net.SplitHostPort(candidate); err != nil {
			candidate = net.JoinHostPort(candidate, "53")
		}
		address, err := net.ResolveUDPAddr("udp", candidate)
		if err == nil {
			return address, nil
		}
	}
	return nil, fmt.Errorf("SOCKS5 UDP DNS health check requires a plain, udp://, or dns:// resolver")
}

func readSOCKS5Reply(reader io.Reader) (*net.UDPAddr, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, err
	}
	if header[0] != 5 || header[1] != 0 || header[2] != 0 {
		return nil, fmt.Errorf("SOCKS5 UDP ASSOCIATE returned %x", header)
	}
	return readSOCKS5Address(reader, header[3])
}

func readSOCKS5Address(reader io.Reader, atyp byte) (*net.UDPAddr, error) {
	var host string
	switch atyp {
	case 1:
		address := make([]byte, net.IPv4len)
		if _, err := io.ReadFull(reader, address); err != nil {
			return nil, err
		}
		host = net.IP(address).String()
	case 3:
		length := []byte{0}
		if _, err := io.ReadFull(reader, length); err != nil {
			return nil, err
		}
		address := make([]byte, int(length[0]))
		if _, err := io.ReadFull(reader, address); err != nil {
			return nil, err
		}
		host = string(address)
	case 4:
		address := make([]byte, net.IPv6len)
		if _, err := io.ReadFull(reader, address); err != nil {
			return nil, err
		}
		host = net.IP(address).String()
	default:
		return nil, fmt.Errorf("unsupported SOCKS5 address type %d", atyp)
	}
	port := make([]byte, 2)
	if _, err := io.ReadFull(reader, port); err != nil {
		return nil, err
	}
	return net.ResolveUDPAddr("udp", net.JoinHostPort(host, fmt.Sprint(binary.BigEndian.Uint16(port))))
}

func socks5UDPHeader(address *net.UDPAddr) []byte {
	header := []byte{0, 0, 0}
	if ip := address.IP.To4(); ip != nil {
		header = append(header, 1)
		header = append(header, ip...)
	} else {
		header = append(header, 4)
		header = append(header, address.IP.To16()...)
	}
	return binary.BigEndian.AppendUint16(header, uint16(address.Port))
}

func parseSOCKS5UDPDatagram(packet []byte) (*net.UDPAddr, []byte, error) {
	if len(packet) < 4 || packet[0] != 0 || packet[1] != 0 || packet[2] != 0 {
		return nil, nil, fmt.Errorf("invalid SOCKS5 UDP datagram header")
	}
	reader := strings.NewReader(string(packet[4:]))
	target, err := readSOCKS5Address(reader, packet[3])
	if err != nil {
		return nil, nil, err
	}
	headerLength := len(packet) - reader.Len()
	return target, packet[headerLength:], nil
}

func dnsHealthQuery() ([]byte, uint16, error) {
	rawID := make([]byte, 2)
	if _, err := rand.Read(rawID); err != nil {
		return nil, 0, err
	}
	id := binary.BigEndian.Uint16(rawID)
	query := []byte{rawID[0], rawID[1], 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	query = append(query, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1)
	return query, id, nil
}
