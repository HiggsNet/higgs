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
	"reflect"
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
		manifest, err := loadManifest(*configPath)
		if err != nil {
			return err
		}
		if *outputDir != "" {
			manifest.OutputDir = *outputDir
		}
		lock, err := loadPublishedSOCKS5(manifest.OutputDir)
		if err != nil {
			return err
		}
		if err := runHiggs(*higgsBinary, "service", "withdraw"); err != nil {
			return err
		}
		for _, endpoint := range lock.Endpoints {
			if serviceControlsRoute(endpoint) {
				if err := runHiggs(*higgsBinary, "route", "withdraw", lock.ManagedZone, endpoint.Assignment); err != nil {
					return err
				}
			}
			if err := runHiggs(*higgsBinary, "firewall", "endpoint", "remove", endpointACLName(endpoint.Network)); err != nil {
				return err
			}
		}
		lock.Endpoints = nil
		return writeSOCKS5Lock(filepath.Join(manifest.OutputDir, "socks5", "published.json"), lock)
	}
	manifest, err := loadManifest(*configPath)
	if err != nil {
		return err
	}
	if *outputDir != "" {
		manifest.OutputDir = *outputDir
	}
	report, err := queryAssignments(*higgsBinary)
	if err != nil {
		return err
	}
	resolved, err := resolveManifest(manifest, report.Assignments)
	if err != nil {
		return err
	}
	resolved.ManagedZone = report.ManagedZone
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

func queryAssignments(higgsBinary string) (runtimeIPAMReport, error) {
	cmd := exec.Command(higgsBinary, "route", "ipam", "mine")
	out, err := cmd.Output()
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return runtimeIPAMReport{}, fmt.Errorf("higgs route ipam mine: %s", exit.Stderr)
		}
		return runtimeIPAMReport{}, fmt.Errorf("higgs route ipam mine: %w", err)
	}
	var report runtimeIPAMReport
	if err := json.Unmarshal(out, &report); err != nil {
		return runtimeIPAMReport{}, fmt.Errorf("decode higgs route ipam mine output: %w", err)
	}
	return report, nil
}

func publishResolvedService(higgsBinary string, manifest resolvedManifest) error {
	service := manifest.SOCKS5
	rendered, err := loadRenderedSOCKS5(manifest.OutputDir)
	if err != nil {
		return err
	}
	if rendered.ConfigHash != service.ConfigHash || rendered.ManagedZone != manifest.ManagedZone || !reflect.DeepEqual(rendered.Endpoints, service.Endpoints) {
		return errors.New("socks5 runtime assignment or config changed; run render again")
	}
	for _, endpoint := range service.Endpoints {
		connection, err := net.DialTimeout("tcp", net.JoinHostPort(endpoint.Address, fmt.Sprint(endpoint.Port)), 3*time.Second)
		if err != nil {
			return fmt.Errorf("socks5 endpoint %s TCP readiness check failed: %w", endpoint.Network, err)
		}
		connection.Close()
	}
	for _, endpoint := range service.Endpoints {
		aclName := endpointACLName(endpoint.Network)
		if len(service.AllowZones) > 0 {
			args := []string{"firewall", "endpoint", "apply", aclName, "--destination", endpoint.Address, "--protocol", "tcp", "--port", fmt.Sprint(endpoint.Port)}
			for _, selector := range service.AllowZones {
				args = append(args, "--allow-zone", selector)
			}
			if err := runHiggs(higgsBinary, args...); err != nil {
				return fmt.Errorf("apply endpoint ACL before publish: %w", err)
			}
		} else if err := runHiggs(higgsBinary, "firewall", "endpoint", "remove", aclName); err != nil {
			return fmt.Errorf("remove stale endpoint ACL before unrestricted publish: %w", err)
		}
		if serviceControlsRoute(endpoint) {
			if err := runHiggs(higgsBinary, "route", "announce", manifest.ManagedZone, endpoint.Assignment); err != nil {
				return fmt.Errorf("announce endpoint network %s: %w", endpoint.Network, err)
			}
		}
	}
	args := []string{"service", "publish"}
	for _, endpoint := range service.Endpoints {
		args = append(args, "--endpoint", fmt.Sprintf("%s,%s,%d", endpoint.Region, endpoint.Address, endpoint.Port))
	}
	if err := runHiggs(higgsBinary, args...); err != nil {
		return err
	}
	previous, _ := loadPublishedSOCKS5(manifest.OutputDir)
	current := renderedSOCKS5Lock{resolvedSOCKS5: service, ManagedZone: manifest.ManagedZone}
	for _, old := range previous.Endpoints {
		if endpointStillPublished(old, service.Endpoints) {
			continue
		}
		if serviceControlsRoute(old) {
			if err := runHiggs(higgsBinary, "route", "withdraw", previous.ManagedZone, old.Assignment); err != nil {
				return err
			}
		}
		if err := runHiggs(higgsBinary, "firewall", "endpoint", "remove", endpointACLName(old.Network)); err != nil {
			return err
		}
	}
	return writeSOCKS5Lock(filepath.Join(manifest.OutputDir, "socks5", "published.json"), current)
}

type renderedSOCKS5Lock struct {
	resolvedSOCKS5
	ManagedZone string `json:"managed_zone"`
}

func loadRenderedSOCKS5(outputDir string) (renderedSOCKS5Lock, error) {
	path := filepath.Join(outputDir, "socks5", "resolved.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return renderedSOCKS5Lock{}, fmt.Errorf("read rendered state %s: %w; run render first", path, err)
	}
	var lock renderedSOCKS5Lock
	if err := json.Unmarshal(data, &lock); err != nil {
		return renderedSOCKS5Lock{}, fmt.Errorf("decode rendered state: %w", err)
	}
	return lock, nil
}

func loadPublishedSOCKS5(outputDir string) (renderedSOCKS5Lock, error) {
	path := filepath.Join(outputDir, "socks5", "published.json")
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return loadRenderedSOCKS5(outputDir)
	}
	if err != nil {
		return renderedSOCKS5Lock{}, err
	}
	var lock renderedSOCKS5Lock
	if err := json.Unmarshal(data, &lock); err != nil {
		return renderedSOCKS5Lock{}, fmt.Errorf("decode published state: %w", err)
	}
	return lock, nil
}

func writeSOCKS5Lock(path string, lock renderedSOCKS5Lock) error {
	data, err := json.MarshalIndent(lock, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(path, append(data, '\n'), 0o644)
}

func endpointStillPublished(old resolvedEndpoint, current []resolvedEndpoint) bool {
	for _, endpoint := range current {
		if endpoint.Network == old.Network && endpoint.Assignment == old.Assignment && endpoint.Address == old.Address {
			return true
		}
	}
	return false
}

func serviceControlsRoute(endpoint resolvedEndpoint) bool { return endpoint.Shared }

func endpointACLName(network string) string { return socks5ServiceName + "-" + network }

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
