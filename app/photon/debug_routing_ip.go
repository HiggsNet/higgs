package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"

	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

type routingIPCommandRunner func(context.Context, string, ...string) ([]byte, error)

func debugRoutingIPRoute(ctx context.Context, netnsName, family string) error {
	rt, err := NewAppContext()
	if err != nil {
		return err
	}
	return debugRoutingIPRouteWithRuntime(ctx, rt, os.Stdout, netnsName, family, runRoutingIPCommand)
}

func runRoutingIPCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

func debugRoutingIPRouteWithRuntime(
	ctx context.Context,
	rt *AppContext,
	w io.Writer,
	netnsName string,
	family string,
	runner routingIPCommandRunner,
) error {
	if rt == nil || rt.Config == nil {
		return errors.New("routing configuration is unavailable")
	}
	families, err := routingIPFamilies(family)
	if err != nil {
		return err
	}
	if runner == nil {
		runner = runRoutingIPCommand
	}

	instances := make([]RoutingInstance, 0, len(rt.Config.Routing.Instances))
	for _, inst := range rt.Config.Routing.Instances {
		if !inst.Enabled || inst.Mode == ipsec.RoutingModeDisabled {
			continue
		}
		if netnsName != "" && inst.NetNS != netnsName && inst.ID != netnsName {
			continue
		}
		instances = append(instances, inst)
	}
	sort.Slice(instances, func(i, j int) bool {
		if instances[i].NetNS != instances[j].NetNS {
			return instances[i].NetNS < instances[j].NetNS
		}
		return instances[i].ID < instances[j].ID
	})
	if len(instances) == 0 {
		if netnsName != "" {
			return fmt.Errorf("routing netns or instance %q not found", netnsName)
		}
		fmt.Fprintln(w, "kernel_routes: no enabled routing instances")
		return nil
	}

	var runErrors []error
	for _, inst := range instances {
		spec, ok := routingIPNetNSSpec(rt.Config.Netns, inst.NetNS)
		if !ok {
			runErrors = append(runErrors, fmt.Errorf("netns %q: namespace configuration not found", inst.NetNS))
			continue
		}
		fmt.Fprintf(w, "netns %s\n", inst.NetNS)
		fmt.Fprintf(w, "  instance_id: %s\n", inst.ID)
		fmt.Fprintf(w, "  namespace: %s\n", routingIPNamespaceLabel(spec))
		for _, routeFamily := range families {
			fmt.Fprintf(w, "  %s:\n", routeFamily)
			name, args, err := routingIPRouteCommand(spec, routeFamily)
			if err != nil {
				fmt.Fprintf(w, "    error: %s\n", err)
				runErrors = append(runErrors, fmt.Errorf("netns %q %s: %w", inst.NetNS, routeFamily, err))
				continue
			}
			output, runErr := runner(ctx, name, args...)
			writeIndentedRoutingIPOutput(w, output)
			if runErr != nil {
				fmt.Fprintf(w, "    error: %s\n", runErr)
				runErrors = append(runErrors, fmt.Errorf("netns %q %s: %w", inst.NetNS, routeFamily, runErr))
			}
		}
	}
	return errors.Join(runErrors...)
}

func routingIPFamilies(family string) ([]string, error) {
	switch strings.ToLower(strings.TrimSpace(family)) {
	case "", "all":
		return []string{"ipv4", "ipv6"}, nil
	case "ipv4", "4":
		return []string{"ipv4"}, nil
	case "ipv6", "6":
		return []string{"ipv6"}, nil
	default:
		return nil, fmt.Errorf("unsupported address family %q; use ipv4, ipv6, or all", family)
	}
}

func routingIPNetNSSpec(config netnsConfig, netnsName string) (ipsec.NetNSSpec, bool) {
	if spec, ok := config.Names[netnsName]; ok {
		return spec.Normalized(), true
	}
	for _, spec := range config.Names {
		if routingNetNSTarget(spec) == netnsName {
			return spec.Normalized(), true
		}
	}
	return ipsec.NetNSSpec{}, false
}

func routingIPRouteCommand(spec ipsec.NetNSSpec, family string) (string, []string, error) {
	familyFlag := "-4"
	if family == "ipv6" {
		familyFlag = "-6"
	}
	spec = spec.Normalized()
	routeArgs := []string{familyFlag, "route", "show"}
	switch spec.Kind {
	case ipsec.NetNSHost:
		return "ip", routeArgs, nil
	case ipsec.NetNSName:
		args := []string{"netns", "exec", spec.Name, "ip"}
		return "ip", append(args, routeArgs...), nil
	case ipsec.NetNSPath:
		return "nsenter", append([]string{"--net=" + spec.Path, "ip"}, routeArgs...), nil
	default:
		return "", nil, fmt.Errorf("unsupported netns kind %q", spec.Kind)
	}
}

func routingIPNamespaceLabel(spec ipsec.NetNSSpec) string {
	spec = spec.Normalized()
	switch spec.Kind {
	case ipsec.NetNSHost:
		return "host"
	case ipsec.NetNSName:
		return "name:" + spec.Name
	case ipsec.NetNSPath:
		return "path:" + spec.Path
	default:
		return spec.Kind
	}
}

func writeIndentedRoutingIPOutput(w io.Writer, output []byte) {
	text := strings.TrimRight(string(output), "\n")
	if text == "" {
		fmt.Fprintln(w, "    -")
		return
	}
	for line := range strings.SplitSeq(text, "\n") {
		fmt.Fprintf(w, "    %s\n", line)
	}
}
