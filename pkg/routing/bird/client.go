package bird

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Client talks to a running BIRD daemon through birdc over a Unix socket.
type Client interface {
	// Status returns a snapshot of BIRD status, protocols, routes,
	// interfaces and neighbors.
	Status(ctx context.Context) (*BirdObservedState, error)

	// Configure performs a full "birdc configure" using the file at path.
	Configure(ctx context.Context, path string) error

	// ConfigureSoft performs "birdc configure soft" using the file at path.
	ConfigureSoft(ctx context.Context, path string) error

	// ReloadIn triggers "birdc reload in <proto>".
	ReloadIn(ctx context.Context, proto string) error

	// ReloadOut triggers "birdc reload out <proto>".
	ReloadOut(ctx context.Context, proto string) error

	// Shutdown performs a graceful shutdown ("birdc down" or SIGTERM).
	Shutdown(ctx context.Context) error

	// Raw runs a single birdc command and returns the unparsed response body.
	Raw(ctx context.Context, cmd string) (string, error)
}

type birdcClient struct {
	socketPath string
	timeout    time.Duration
}

// NewClient creates a new birdc client connected to socketPath.
func NewClient(socketPath string, timeout time.Duration) Client {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &birdcClient{
		socketPath: socketPath,
		timeout:    timeout,
	}
}

// Status returns a snapshot of BIRD status, protocols, routes, interfaces and neighbors.
func (c *birdcClient) Status(ctx context.Context) (*BirdObservedState, error) {
	state := &BirdObservedState{
		FetchedAt: time.Now(),
	}

	commands := []struct {
		name  string
		cmd   string
		parse func(string, *BirdObservedState)
	}{
		{"status", "show status", func(out string, s *BirdObservedState) {
			status, err := parseStatus(out)
			if err != nil {
				s.Warnings = append(s.Warnings, fmt.Sprintf("parse status: %v", err))
				s.Stale = true
				return
			}
			s.Status = status
		}},
		{"protocols", "show protocols all", func(out string, s *BirdObservedState) {
			s.Protocols = parseProtocols(out)
		}},
		{"routes", "show route all", func(out string, s *BirdObservedState) {
			s.Routes = parseRoutes(out)
		}},
		{"interfaces", "show interfaces", func(out string, s *BirdObservedState) {
			s.Interfaces = parseInterfaces(out)
		}},
		{"neighbors", "show babel neighbors", func(out string, s *BirdObservedState) {
			s.Neighbors = parseBabelNeighbors(out)
		}},
	}

	for _, item := range commands {
		out, err := c.command(ctx, item.cmd)
		if err != nil {
			state.Warnings = append(state.Warnings, fmt.Sprintf("%s command failed: %v", item.name, err))
			state.Stale = true
			continue
		}
		item.parse(out, state)
	}

	return state, nil
}

// Configure performs a full "birdc configure" using the file at path.
func (c *birdcClient) Configure(ctx context.Context, path string) error {
	return c.commandCheck(ctx, fmt.Sprintf("configure %s", path))
}

// ConfigureSoft performs "birdc configure soft" using the file at path.
func (c *birdcClient) ConfigureSoft(ctx context.Context, path string) error {
	return c.commandCheck(ctx, fmt.Sprintf("configure soft %s", path))
}

// ReloadIn triggers "birdc reload in <proto>".
func (c *birdcClient) ReloadIn(ctx context.Context, proto string) error {
	return c.commandCheck(ctx, fmt.Sprintf("reload in %s", proto))
}

// ReloadOut triggers "birdc reload out <proto>".
func (c *birdcClient) ReloadOut(ctx context.Context, proto string) error {
	return c.commandCheck(ctx, fmt.Sprintf("reload out %s", proto))
}

// Shutdown performs a graceful shutdown ("birdc down" or SIGTERM).
func (c *birdcClient) Shutdown(ctx context.Context) error {
	return c.commandCheck(ctx, "down")
}

// Raw runs a single birdc command and returns the unparsed response body.
func (c *birdcClient) Raw(ctx context.Context, cmd string) (string, error) {
	return c.command(ctx, cmd)
}

// commandCheck runs a command and returns an error if BIRD reports a failure.
func (c *birdcClient) commandCheck(ctx context.Context, cmd string) error {
	out, err := c.command(ctx, cmd)
	if err != nil {
		return err
	}
	if isErrorResponse(out) {
		return fmt.Errorf("birdc error: %s", summarizeError(out))
	}
	return nil
}

// command sends a single birdc command and returns the cleaned response body.
func (c *birdcClient) command(ctx context.Context, cmd string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}

	dialer := net.Dialer{Timeout: c.timeout}
	conn, err := dialer.DialContext(ctx, "unix", c.socketPath)
	if err != nil {
		return "", fmt.Errorf("dial %s: %w", c.socketPath, err)
	}
	defer conn.Close()

	deadline := time.Now().Add(c.timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	_ = conn.SetDeadline(deadline)

	// Consume the greeting line (e.g. "0001 BIRD 2.15.1 ready.").
	reader := bufio.NewReader(conn)
	greeting, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("read greeting: %w", err)
	}
	_ = greeting

	if _, err := fmt.Fprintf(conn, "%s\n", cmd); err != nil {
		return "", fmt.Errorf("write command: %w", err)
	}

	var body strings.Builder
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return body.String(), fmt.Errorf("read response: %w", err)
		}

		// The birdc prompt marks the end of a response.
		if isPromptLine(line) {
			break
		}

		body.WriteString(line)
	}

	return body.String(), nil
}

func isPromptLine(line string) bool {
	line = strings.TrimRight(line, "\r\n")
	return line == "0000" || strings.HasPrefix(line, "0000 ")
}

// isErrorResponse reports whether a response body contains an error code line.
func isErrorResponse(output string) bool {
	return errorCodeRe.MatchString(output)
}

var errorCodeRe = regexp.MustCompile(`(?m)^[89]\d{3}[- ]`)

// summarizeError extracts the first error-looking line from a response.
func summarizeError(output string) string {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if len(line) >= 4 {
			code := line[:4]
			if n, _ := strconv.Atoi(code); n >= 8000 && n <= 9999 {
				return strings.TrimSpace(line[4:])
			}
		}
	}
	return output
}
