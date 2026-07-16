package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

const defaultManifestPath = "/etc/higgs/service.yaml"
const socks5ServiceName = "socks5"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: higgs-services <validate|render|publish|withdraw> [options]")
	}
	command := args[0]
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	configPath := flags.String("config", defaultManifestPath, "service manifest path")
	higgsBinary := flags.String("higgs", "higgs", "higgs CLI path")
	outputDir := flags.String("output", "", "override artifact output directory")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if command == "withdraw" {
		if flags.NArg() != 0 {
			return errors.New("usage: higgs-services withdraw [options]")
		}
		if err := runHiggs(*higgsBinary, "service", "withdraw"); err != nil {
			return err
		}
		return runHiggs(*higgsBinary, "firewall", "endpoint", "remove", socks5ServiceName)
	}
	manifest, err := loadManifest(*configPath)
	if err != nil {
		return err
	}
	if *outputDir != "" {
		manifest.OutputDir = *outputDir
	}
	assignments, err := queryAssignments(*higgsBinary)
	if err != nil {
		return err
	}
	resolved, err := resolveManifest(manifest, assignments)
	if err != nil {
		return err
	}
	switch command {
	case "validate":
		return writeJSON(os.Stdout, resolved)
	case "render":
		if err := renderArtifacts(resolved); err != nil {
			return err
		}
		fmt.Printf("rendered service artifacts under %s\n", resolved.OutputDir)
		return nil
	case "publish":
		if flags.NArg() != 0 {
			return errors.New("usage: higgs-services publish [options]")
		}
		return publishResolvedService(*higgsBinary, resolved)
	default:
		return fmt.Errorf("unknown command %q", command)
	}
}

func queryAssignments(higgsBinary string) ([]runtimeAssignment, error) {
	cmd := exec.Command(higgsBinary, "ipam", "mine")
	out, err := cmd.Output()
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return nil, fmt.Errorf("higgs ipam mine: %s", exit.Stderr)
		}
		return nil, fmt.Errorf("higgs ipam mine: %w", err)
	}
	var report struct {
		Assignments []runtimeAssignment `json:"assignments"`
	}
	if err := json.Unmarshal(out, &report); err != nil {
		return nil, fmt.Errorf("decode higgs ipam mine output: %w", err)
	}
	return report.Assignments, nil
}

func publishResolvedService(higgsBinary string, manifest resolvedManifest) error {
	service := manifest.SOCKS5
	lockPath := filepath.Join(manifest.OutputDir, "socks5", "resolved.json")
	data, err := os.ReadFile(lockPath)
	if err != nil {
		return fmt.Errorf("read rendered state %s: %w; run render first", lockPath, err)
	}
	var rendered resolvedSOCKS5
	if err := json.Unmarshal(data, &rendered); err != nil {
		return fmt.Errorf("decode rendered state: %w", err)
	}
	if rendered.ConfigHash != service.ConfigHash || rendered.Address != service.Address {
		return errors.New("socks5 runtime assignment or config changed; run render again")
	}
	connection, err := net.DialTimeout("tcp", net.JoinHostPort(service.Address, fmt.Sprint(service.Port)), 3*time.Second)
	if err != nil {
		return fmt.Errorf("socks5 TCP readiness check failed: %w", err)
	}
	connection.Close()
	if len(service.AllowZones) > 0 {
		args := []string{"firewall", "endpoint", "apply", socks5ServiceName, "--destination", service.Address, "--protocol", "tcp", "--port", fmt.Sprint(service.Port)}
		for _, selector := range service.AllowZones {
			args = append(args, "--allow-zone", selector)
		}
		if err := runHiggs(higgsBinary, args...); err != nil {
			return fmt.Errorf("apply endpoint ACL before publish: %w", err)
		}
	} else if err := runHiggs(higgsBinary, "firewall", "endpoint", "remove", socks5ServiceName); err != nil {
		return fmt.Errorf("remove stale endpoint ACL before unrestricted publish: %w", err)
	}
	return runHiggs(higgsBinary, "service", "publish", "--region", service.Region, "--address", service.Address, "--port", fmt.Sprint(service.Port))
}

func runHiggs(binary string, args ...string) error {
	cmd := exec.Command(binary, args...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("higgs %v: %w", args, err)
	}
	return nil
}

func writeJSON(file *os.File, value any) error {
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}
