package bird

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const sampleShowStatus = `1000-BIRD 2.15.1
1011-Router ID is 10.64.64.2
 Current server time is 2025-06-13 10:00:00.000
 Last reboot on 2025-06-13 09:00:00.000
 Last reconfiguration on 2025-06-13 09:30:00.000
0000 
`

const sampleShowProtocols = `2002-Name       Proto      Table      State  Since         Info
1002-direct1    Direct     ---        up     2025-06-13
 bfd1       BFD        ---        up     2025-06-13
 kernel1    Kernel     master4    up     2025-06-13
 device1    Device     ---        up     2025-06-13
 babel1     Babel      master4    up     2025-06-13    Established
0000 
`

const sampleShowRoutes = `Table master4:
10.0.0.0/8           unicast [babel1 2025-06-13] * (100)
	via 192.168.1.2 on eth0
192.168.0.0/16       unicast [kernel1 2025-06-13] (240)
	dev eth0
0000 
`

const sampleShowInterfaces = `1002-Interface  State  MTU  Link-local
eth0       up     1500 fe80::1
eth1       down   1500 -
0000 
`

const sampleShowBabelNeighbors = `1002-Interface  Neighbor           Metric
eth0       fe80::2             256
eth0       fe80::3             512
0000 
`

// fakeServer is a minimal birdc-style Unix socket server for tests.
type fakeServer struct {
	listener net.Listener
	socket   string
	handler  func(cmd string) string
}

func newFakeServer(t *testing.T, handler func(cmd string) string) *fakeServer {
	t.Helper()
	dir := t.TempDir()
	socket := filepath.Join(dir, "bird.ctl")
	l, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	s := &fakeServer{
		listener: l,
		socket:   socket,
		handler:  handler,
	}
	go s.serve(t)
	return s
}

func (s *fakeServer) serve(t *testing.T) {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		go s.handleConn(t, conn)
	}
}

func (s *fakeServer) handleConn(t *testing.T, conn net.Conn) {
	defer conn.Close()
	if _, err := fmt.Fprintf(conn, "0001 BIRD 2.15.1 ready.\n"); err != nil {
		t.Logf("greeting write: %v", err)
		return
	}
	reader := bufio.NewReader(conn)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.TrimSpace(line)
		response := s.handler(cmd)
		if _, err := fmt.Fprint(conn, response); err != nil {
			return
		}
	}
}

func (s *fakeServer) close() {
	_ = s.listener.Close()
}

func defaultHandler(cmd string) string {
	switch cmd {
	case "show status":
		return sampleShowStatus
	case "show protocols all":
		return sampleShowProtocols
	case "show route all":
		return sampleShowRoutes
	case "show interfaces":
		return sampleShowInterfaces
	case "show babel neighbors":
		return sampleShowBabelNeighbors
	case "configure /tmp/bird.conf":
		return "0002 Configuration OK\n0000 \n"
	case "configure soft /tmp/bird.conf":
		return "0002 Configuration OK\n0000 \n"
	case "reload in babel1":
		return "0002 Reload requested\n0000 \n"
	case "reload out babel1":
		return "0002 Reload requested\n0000 \n"
	case "down":
		return "0002 Shutdown requested\n0000 \n"
	default:
		return "8001 Unknown command\n0000 \n"
	}
}

func TestStatusParsing(t *testing.T) {
	server := newFakeServer(t, defaultHandler)
	defer server.close()

	client := NewClient(server.socket, 5*time.Second)
	state, err := client.Status(context.Background())
	if err != nil {
		t.Fatalf("Status failed: %v", err)
	}
	if state.Stale {
		t.Fatalf("unexpected stale state, warnings: %v", state.Warnings)
	}

	if state.Status.Version != "2.15.1" {
		t.Errorf("version = %q, want %q", state.Status.Version, "2.15.1")
	}
	if state.Status.RouterID != 0x0A404002 {
		t.Errorf("router id = 0x%x, want 0x%x", state.Status.RouterID, 0x0A404002)
	}
	if state.Status.LastReconfig.IsZero() {
		t.Error("expected LastReconfig to be parsed")
	}

	if len(state.Protocols) != 5 {
		t.Errorf("protocols = %d, want 5", len(state.Protocols))
	}
	foundBabel := false
	for _, p := range state.Protocols {
		if p.Name == "babel1" {
			foundBabel = true
			if p.State != "up" || p.Table != "master4" {
				t.Errorf("unexpected babel1 protocol: %+v", p)
			}
		}
	}
	if !foundBabel {
		t.Error("babel1 protocol not found")
	}

	if len(state.Routes) != 2 {
		t.Errorf("routes = %d, want 2", len(state.Routes))
	}
	var selected *BirdRoute
	for i := range state.Routes {
		if state.Routes[i].Selected {
			selected = &state.Routes[i]
		}
	}
	if selected == nil {
		t.Fatal("no selected route found")
	}
	if selected.Prefix.String() != "10.0.0.0/8" {
		t.Errorf("selected prefix = %q, want 10.0.0.0/8", selected.Prefix)
	}
	if selected.Via.String() != "192.168.1.2" {
		t.Errorf("selected via = %q, want 192.168.1.2", selected.Via)
	}

	if len(state.Interfaces) != 2 {
		t.Errorf("interfaces = %d, want 2", len(state.Interfaces))
	}

	if len(state.Neighbors) != 2 {
		t.Errorf("neighbors = %d, want 2", len(state.Neighbors))
	}
}

func TestConfigureSuccessAndError(t *testing.T) {
	server := newFakeServer(t, defaultHandler)
	defer server.close()

	client := NewClient(server.socket, 5*time.Second)

	if err := client.Configure(context.Background(), "/tmp/bird.conf"); err != nil {
		t.Errorf("Configure succeeded command returned error: %v", err)
	}

	if err := client.ConfigureSoft(context.Background(), "/tmp/bird.conf"); err != nil {
		t.Errorf("ConfigureSoft succeeded command returned error: %v", err)
	}

	err := client.Configure(context.Background(), "/tmp/missing.conf")
	if err == nil {
		t.Fatal("expected error for missing config command")
	}
	if !strings.Contains(err.Error(), "Unknown command") {
		t.Errorf("error message does not mention unknown command: %v", err)
	}
}

func TestShutdown(t *testing.T) {
	server := newFakeServer(t, defaultHandler)
	defer server.close()

	client := NewClient(server.socket, 5*time.Second)
	if err := client.Shutdown(context.Background()); err != nil {
		t.Errorf("Shutdown returned error: %v", err)
	}
}

func TestCommandTimeout(t *testing.T) {
	slowHandler := func(cmd string) string {
		time.Sleep(500 * time.Millisecond)
		return defaultHandler(cmd)
	}
	server := newFakeServer(t, slowHandler)
	defer server.close()

	client := NewClient(server.socket, 5*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	// Status accumulates per-command failures as stale warnings rather than
	// returning a hard error. Use a single checked command to observe the
	// timeout as an error.
	err := client.Configure(ctx, "/tmp/bird.conf")
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if !strings.Contains(err.Error(), "timeout") && !strings.Contains(err.Error(), "context") {
		t.Errorf("expected timeout-related error, got: %v", err)
	}
}

func TestParseStatusDirectly(t *testing.T) {
	status, err := parseStatus(sampleShowStatus)
	if err != nil {
		t.Fatalf("parseStatus: %v", err)
	}
	if status.Version != "2.15.1" {
		t.Errorf("version = %q, want %q", status.Version, "2.15.1")
	}
	if status.RouterID != 0x0A404002 {
		t.Errorf("router id = 0x%x", status.RouterID)
	}
}

func TestSocketNotFound(t *testing.T) {
	client := NewClient(filepath.Join(t.TempDir(), "missing.ctl"), 100*time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	state, err := client.Status(ctx)
	if err != nil {
		t.Fatalf("Status returned unexpected hard error: %v", err)
	}
	if !state.Stale {
		t.Fatal("expected stale state when socket is missing")
	}
	if len(state.Warnings) == 0 {
		t.Fatal("expected warnings when socket is missing")
	}
}

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
