package ipsec

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultVICISocket = "/run/charon.vici"
)

type PreflightOptions struct {
	VICISocket string
	IKEPort    uint16
	NATTPort   uint16
	RequireUDP bool
}

type PreflightResult struct {
	Checks []PreflightCheck
}

type PreflightCheck struct {
	Name    string
	OK      bool
	Skipped bool
	Detail  string
}

type PreflightChecker struct {
	GOOS        string
	ReadFile    func(string) ([]byte, error)
	Stat        func(string) error
	Command     func(context.Context, string, ...string) ([]byte, error)
	ListenUDP   func(context.Context, uint16) error
	EUID        func() int
	CapNetAdmin func() (bool, error)
}

func RunPreflight(ctx context.Context, opts PreflightOptions) PreflightResult {
	return defaultPreflightChecker().Run(ctx, opts)
}

func defaultPreflightChecker() PreflightChecker {
	return PreflightChecker{}
}

func (c PreflightChecker) Run(ctx context.Context, opts PreflightOptions) PreflightResult {
	c = c.withDefaults()
	if opts.VICISocket == "" {
		opts.VICISocket = DefaultVICISocket
	}
	if opts.IKEPort == 0 {
		opts.IKEPort = 500
	}
	if opts.NATTPort == 0 {
		opts.NATTPort = 4500
	}
	out := PreflightResult{}
	out.add("linux", c.GOOS == "linux", false, fmt.Sprintf("GOOS=%s", c.GOOS))
	out.add("root-or-cap-net-admin", c.hasNetAdmin(), false, "needs root or CAP_NET_ADMIN for XFRM interface and address changes")
	out.add("vici-socket", c.Stat(opts.VICISocket) == nil, false, opts.VICISocket)
	out.addCommand(ctx, c, "iproute2-ip", "ip")
	out.addCommand(ctx, c, "swanctl", "swanctl")
	out.addCommand(ctx, c, "charon", "charon")
	out.add("kernel-xfrm", c.fileExists("/proc/net/xfrm_stat") || c.fileExists("/proc/net/xfrm_policy"), false, "requires Linux XFRM support")
	out.add("iproute2-xfrm-interface", c.xfrmInterfaceSupported(ctx), false, "requires kernel support for ip link type xfrm (check CONFIG_XFRM_INTERFACE)")
	out.add("host-born-xfrm-netns-move", c.hostBornXFRMMoveSupported(ctx), false, "requires host-created XFRM interface to move into a named netns")
	if opts.RequireUDP {
		err := c.ListenUDP(ctx, opts.IKEPort)
		out.add("udp-ike-port", err == nil, false, udpPortDetail(opts.IKEPort, err))
		err = c.ListenUDP(ctx, opts.NATTPort)
		out.add("udp-natt-port", err == nil, false, udpPortDetail(opts.NATTPort, err))
	} else {
		out.add("udp-ike-port", false, true, "not requested")
		out.add("udp-natt-port", false, true, "not requested")
	}
	return out
}

func (r PreflightResult) Ready() bool {
	for _, check := range r.Checks {
		if !check.OK && !check.Skipped {
			return false
		}
	}
	return true
}

func (r PreflightResult) Errors() []string {
	var errs []string
	for _, check := range r.Checks {
		if !check.OK && !check.Skipped {
			errs = append(errs, check.Name+": "+check.Detail)
		}
	}
	return errs
}

func (r *PreflightResult) add(name string, ok bool, skipped bool, detail string) {
	r.Checks = append(r.Checks, PreflightCheck{Name: name, OK: ok, Skipped: skipped, Detail: detail})
}

func (r *PreflightResult) addCommand(ctx context.Context, c PreflightChecker, name, command string) {
	if c.commandSucceeds(ctx, command, "--version") || c.commandSucceeds(ctx, command, "-v") || c.commandSucceeds(ctx, command) {
		r.add(name, true, false, command+" found")
		return
	}
	r.add(name, false, false, command+" not found or not executable")
}

func (c PreflightChecker) withDefaults() PreflightChecker {
	if c.GOOS == "" {
		c.GOOS = runtime.GOOS
	}
	if c.ReadFile == nil {
		c.ReadFile = os.ReadFile
	}
	if c.Stat == nil {
		c.Stat = func(path string) error {
			_, err := os.Stat(path)
			return err
		}
	}
	if c.Command == nil {
		c.Command = func(ctx context.Context, name string, args ...string) ([]byte, error) {
			cmdCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			defer cancel()
			return exec.CommandContext(cmdCtx, name, args...).CombinedOutput()
		}
	}
	if c.ListenUDP == nil {
		c.ListenUDP = bindUDPPort
	}
	if c.EUID == nil {
		c.EUID = os.Geteuid
	}
	if c.CapNetAdmin == nil {
		c.CapNetAdmin = c.readCapNetAdmin
	}
	return c
}

func (c PreflightChecker) hasNetAdmin() bool {
	if c.EUID != nil && c.EUID() == 0 {
		return true
	}
	ok, err := c.CapNetAdmin()
	return err == nil && ok
}

func (c PreflightChecker) fileExists(path string) bool {
	if c.ReadFile == nil {
		return false
	}
	_, err := c.ReadFile(path)
	return err == nil
}

func (c PreflightChecker) commandSucceeds(ctx context.Context, name string, args ...string) bool {
	if c.Command == nil {
		return false
	}
	_, err := c.Command(ctx, name, args...)
	return err == nil
}

func (c PreflightChecker) xfrmInterfaceSupported(ctx context.Context) bool {
	if c.Command == nil {
		return false
	}
	iface := fmt.Sprintf("hgsxfrmtest%d", time.Now().UnixNano()%1000000)
	if _, err := c.Command(ctx, "ip", "link", "add", iface, "type", "xfrm", "if_id", "1"); err != nil {
		return false
	}
	defer func() { _, _ = c.Command(ctx, "ip", "link", "delete", iface) }()
	return true
}

func (c PreflightChecker) hostBornXFRMMoveSupported(ctx context.Context) bool {
	if c.Command == nil {
		return false
	}
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	ns := "higgs-xfrm-preflight-" + suffix
	iface := "hgsxfrm" + suffix[len(suffix)-6:]
	if _, err := c.Command(ctx, "ip", "netns", "add", ns); err != nil {
		return false
	}
	defer func() { _, _ = c.Command(ctx, "ip", "netns", "delete", ns) }()
	if _, err := c.Command(ctx, "ip", "link", "add", iface, "type", "xfrm", "if_id", "2"); err != nil {
		return false
	}
	defer func() { _, _ = c.Command(ctx, "ip", "link", "delete", iface) }()
	if _, err := c.Command(ctx, "ip", "link", "set", iface, "netns", ns); err != nil {
		return false
	}
	_, err := c.Command(ctx, "ip", "netns", "exec", ns, "ip", "link", "show", "dev", iface)
	return err == nil
}

func (c PreflightChecker) readCapNetAdmin() (bool, error) {
	data, err := c.ReadFile("/proc/self/status")
	if err != nil {
		return false, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "CapEff:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return false, errors.New("CapEff is empty")
		}
		capEff, err := strconv.ParseUint(fields[1], 16, 64)
		if err != nil {
			return false, err
		}
		return capEff&(1<<12) != 0, nil
	}
	return false, errors.New("CapEff not found")
}

func bindUDPPort(ctx context.Context, port uint16) error {
	if port == 0 {
		return errors.New("port is required")
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	addr := net.UDPAddr{IP: net.IPv4(0, 0, 0, 0), Port: int(port)}
	conn, err := net.ListenUDP("udp", &addr)
	if err != nil {
		return err
	}
	return conn.Close()
}

func udpPortDetail(port uint16, err error) string {
	detail := fmt.Sprintf("udp/%d bindable", port)
	if err != nil {
		return detail + ": " + err.Error()
	}
	return detail
}
