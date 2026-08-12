package main

import (
	"context"
	"fmt"
	"io"
	"maps"
	"net/netip"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
	inspecthttp "github.com/HiggsNet/photon/internal/inspect/http"
	inspecttext "github.com/HiggsNet/photon/internal/inspect/text"
	"github.com/HiggsNet/photon/pkg/routing"
	"github.com/HiggsNet/photon/pkg/routing/bird"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
	"github.com/urfave/cli/v3"
)

func debugBabel(_ context.Context, _ *cli.Command) error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	return debugBabelWithRuntime(rt, os.Stdout)
}

func debugRoutingReload(_ context.Context, _ *cli.Command) error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	return debugRoutingReloadWithRuntime(rt, os.Stdout)
}

func debugRoutingReloadWithRuntime(rt *Runtime, w io.Writer) error {
	response, ok, err := routingReloadViaControl(rt)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("daemon control socket unavailable; start the daemon to reload routing")
	}
	msg := "routing reloaded"
	if response.Message != "" {
		msg = response.Message
	}
	fmt.Fprintln(w, msg)
	return nil
}

type birdDebugView string

const (
	birdDebugStatus    birdDebugView = "status"
	birdDebugInterface birdDebugView = "interface"
	birdDebugFilter    birdDebugView = "filter"
	birdDebugRoute     birdDebugView = "route"
)

func debugBird(_ context.Context, netnsName string, view birdDebugView) error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	return debugBirdWithRuntime(rt, netnsName, view, os.Stdout)
}

func debugBirdWithRuntime(rt *Runtime, netnsName string, view birdDebugView, w io.Writer) error {
	response, ok, err := birdDumpViaControl(rt, netnsName, string(view))
	if err != nil {
		return err
	}
	if !ok {
		dump, err := birdDumpOffline(rt, netnsName, view)
		if err != nil {
			return err
		}
		return writeDebugBirdDump(w, dump)
	}
	return writeDebugBirdDump(w, response.BirdDump)
}

func birdDumpOffline(rt *Runtime, netnsName string, view birdDebugView) (*inspect.BirdDumpResponse, error) {
	if rt == nil || rt.Config == nil {
		return &inspect.BirdDumpResponse{Instances: map[string]inspect.BirdDumpInstance{}}, nil
	}
	state, err := rt.LoadState()
	if err != nil {
		return nil, err
	}
	commands, err := birdDebugCommands(view)
	if err != nil {
		return nil, err
	}
	response := &inspect.BirdDumpResponse{Instances: map[string]inspect.BirdDumpInstance{}}
	for _, inst := range rt.Config.Routing.Instances {
		if !inst.Enabled || inst.Mode == ipsec.RoutingModeDisabled {
			continue
		}
		if netnsName != "" && inst.NetNS != netnsName && inst.ID != netnsName {
			continue
		}
		controlSocket := inst.ControlSocket
		configPath := inst.ConfigFile
		if state != nil && state.BirdInstances != nil {
			if bi := state.BirdInstances[inst.NetNS]; bi != nil {
				if bi.ControlSocket != "" {
					controlSocket = bi.ControlSocket
				}
				if bi.ConfigPath != "" {
					configPath = bi.ConfigPath
				}
			}
		}
		item := inspect.BirdDumpInstance{
			NetNS:         inst.NetNS,
			InstanceID:    inst.ID,
			ControlSocket: controlSocket,
			Raw:           map[string]string{},
		}
		if view == birdDebugFilter {
			addBirdFilterDefinitions(&item, configPath)
		}
		if controlSocket == "" {
			item.Error = "control socket is not configured"
			response.Instances[inst.NetNS] = item
			continue
		}
		client := bird.NewClient(controlSocket, 10*time.Second)
		for _, cmd := range commands {
			out, err := client.Raw(context.Background(), cmd)
			if err != nil {
				if item.Error == "" {
					item.Error = err.Error()
				}
				item.Raw[cmd] = out
				continue
			}
			item.Raw[cmd] = out
		}
		enrichBirdDumpInstance(&item, state)
		response.Instances[inst.NetNS] = item
	}
	return response, nil
}

func birdDebugCommands(view birdDebugView) ([]string, error) {
	switch view {
	case birdDebugStatus:
		return []string{"show status", "show protocols all", "show babel neighbors", "show babel routes", "show babel entries"}, nil
	case birdDebugInterface:
		return []string{"show interfaces"}, nil
	case birdDebugFilter:
		return []string{"show symbols filter"}, nil
	case birdDebugRoute:
		return []string{"show route table all where source = RTS_BABEL all", "show babel routes"}, nil
	default:
		return nil, fmt.Errorf("unsupported bird debug view %q", view)
	}
}

func enrichBirdDumpInstance(item *inspect.BirdDumpInstance, state *stateFile) {
	if item == nil {
		return
	}
	contexts := birdInterfaceContexts(state, item.NetNS)
	item.Interfaces = make([]inspect.BirdInterfaceContext, 0, len(contexts))
	for _, context := range contexts {
		item.Interfaces = append(item.Interfaces, context)
	}
	sort.Slice(item.Interfaces, func(i, j int) bool { return item.Interfaces[i].Name < item.Interfaces[j].Name })

	if raw, ok := item.Raw["show babel neighbors"]; ok {
		item.Neighbors = parseBirdBabelNeighbors(raw, contexts)
	}
	if raw, ok := item.Raw["show babel routes"]; ok {
		item.BabelRoutes = parseBirdBabelRoutes(raw, contexts)
	}
	if raw, ok := item.Raw["show babel entries"]; ok {
		item.BabelEntries = parseBirdBabelEntries(raw, item.BabelRoutes, contexts)
	}
}

func birdInterfaceContexts(state *stateFile, netnsName string) map[string]inspect.BirdInterfaceContext {
	contexts := map[string]inspect.BirdInterfaceContext{}
	for _, output := range linkOutputsFromState(state) {
		if output.InterfaceName == "" || (output.NetNS != "" && netnsName != "" && output.NetNS != netnsName) {
			continue
		}
		contexts[output.InterfaceName] = inspect.BirdInterfaceContext{
			Name:        output.InterfaceName,
			Zone:        string(output.PeerZone),
			Family:      underlayFamilyFromPathKey(output.PathKey),
			LinkID:      output.ID,
			RuntimeRole: output.RuntimeRole,
		}
	}
	return contexts
}

func parseBirdBabelNeighbors(raw string, contexts map[string]inspect.BirdInterfaceContext) []inspect.BirdBabelNeighbor {
	var out []inspect.BirdBabelNeighbor
	protocol := ""
	inTable := false
	for line := range strings.SplitSeq(raw, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasSuffix(trimmed, ":") && len(strings.Fields(trimmed)) == 1 {
			protocol = strings.TrimSuffix(trimmed, ":")
			inTable = false
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) >= 3 && fields[0] == "IP" && fields[1] == "address" {
			inTable = true
			continue
		}
		if !inTable || len(fields) < 8 {
			continue
		}
		context := contexts[fields[1]]
		out = append(out, inspect.BirdBabelNeighbor{
			Protocol: protocol, Address: fields[0], Interface: fields[1], Zone: context.Zone, Family: context.Family,
			Metric: fields[2], Routes: fields[3], Hellos: fields[4], Expires: fields[5], Auth: fields[6], RTT: fields[7],
		})
		// Some BIRD versions render the RTT unit as a separate final token;
		// the value itself is always the penultimate or final numeric field.
		out[len(out)-1].RTT = fields[len(fields)-1]
	}
	return out
}

func parseBirdBabelRoutes(raw string, contexts map[string]inspect.BirdInterfaceContext) []inspect.BirdBabelRoute {
	var out []inspect.BirdBabelRoute
	protocol := ""
	inTable := false
	for line := range strings.SplitSeq(raw, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasSuffix(trimmed, ":") && len(strings.Fields(trimmed)) == 1 {
			protocol = strings.TrimSuffix(trimmed, ":")
			inTable = false
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) >= 2 && fields[0] == "Prefix" && fields[1] == "Nexthop" {
			inTable = true
			continue
		}
		if !inTable || len(fields) < 6 {
			continue
		}
		flag := ""
		seqIndex := 4
		if fields[4] == "*" || fields[4] == "+" {
			flag = fields[4]
			seqIndex = 5
		}
		if len(fields) <= seqIndex+1 {
			continue
		}
		context := contexts[fields[2]]
		out = append(out, inspect.BirdBabelRoute{
			Protocol: protocol, Prefix: fields[0], Nexthop: fields[1], Interface: fields[2], Zone: context.Zone,
			Family: context.Family, Metric: fields[3], Flag: flag, Seqno: fields[seqIndex], Expires: fields[seqIndex+1],
		})
	}
	return out
}

func parseBirdBabelEntries(raw string, routes []inspect.BirdBabelRoute, contexts map[string]inspect.BirdInterfaceContext) []inspect.BirdBabelEntry {
	selected := map[string]inspect.BirdBabelRoute{}
	for _, route := range routes {
		if route.Flag == "*" {
			selected[route.Protocol+"\x00"+route.Prefix] = route
		}
	}
	var out []inspect.BirdBabelEntry
	protocol := ""
	inTable := false
	for line := range strings.SplitSeq(raw, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasSuffix(trimmed, ":") && len(strings.Fields(trimmed)) == 1 {
			protocol = strings.TrimSuffix(trimmed, ":")
			inTable = false
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) >= 2 && fields[0] == "Prefix" && fields[1] == "Router" {
			inTable = true
			continue
		}
		if !inTable || len(fields) < 6 {
			continue
		}
		route := selected[protocol+"\x00"+fields[0]]
		context := contexts[route.Interface]
		out = append(out, inspect.BirdBabelEntry{
			Protocol: protocol, Prefix: fields[0], RouterID: fields[1], Metric: fields[2], Seqno: fields[3],
			Routes: fields[4], Sources: fields[5], Interface: route.Interface, Zone: context.Zone, Family: context.Family,
		})
	}
	return out
}

func addBirdFilterDefinitions(item *inspect.BirdDumpInstance, configPath string) {
	if item == nil {
		return
	}
	item.ConfigPath = configPath
	if configPath == "" {
		item.FilterError = "config file is not configured"
		return
	}
	config, err := os.ReadFile(configPath)
	if err != nil {
		item.FilterError = err.Error()
		return
	}
	item.FilterDefinitions = extractBirdFilterDefinitions(string(config))
}

func extractBirdFilterDefinitions(config string) string {
	var definitions strings.Builder
	inFilter := false
	depth := 0
	for line := range strings.SplitSeq(config, "\n") {
		trimmed := strings.TrimSpace(line)
		if !inFilter {
			if !strings.HasPrefix(trimmed, "filter ") || !strings.HasSuffix(trimmed, "{") {
				continue
			}
			inFilter = true
		}
		if definitions.Len() > 0 {
			definitions.WriteByte('\n')
		}
		definitions.WriteString(line)
		depth += strings.Count(line, "{") - strings.Count(line, "}")
		if inFilter && depth == 0 {
			inFilter = false
		}
	}
	return strings.TrimSpace(definitions.String())
}

func writeDebugBirdDump(w io.Writer, dump *inspect.BirdDumpResponse) error {
	return inspecttext.WriteBirdDump(w, dump)
}

func debugBabelWithRuntime(rt *Runtime, w io.Writer) error {
	response, ok, err := birdStatusViaControl(rt)
	if err != nil {
		return err
	}
	state, err := rt.LoadState()
	if err != nil {
		return err
	}
	if !ok {
		response = nil
	}
	return writeDebugBabel(w, rt, state, response)
}

func writeDebugBabel(w io.Writer, rt *Runtime, state *stateFile, response *controlResponse) error {
	return inspecttext.WriteBabelDebug(w, buildBabelDebugView(rt, state, response))
}

func buildBabelDebugView(rt *Runtime, state *stateFile, response *controlResponse) inspect.BabelDebugView {
	instances := map[string]*BirdInstanceState{}
	if response != nil && response.BirdInstances != nil {
		maps.Copy(instances, response.BirdInstances)
	}
	if len(instances) == 0 && state != nil && state.BirdInstances != nil {
		maps.Copy(instances, state.BirdInstances)
	}
	routingInstances := []RoutingInstance{}
	if rt != nil && rt.Config != nil {
		routingInstances = rt.Config.Routing.Instances
	}
	input := inspect.BabelDebugInput{}
	if len(routingInstances) == 0 {
		return inspect.BuildBabelDebug(input)
	}
	if response != nil && response.LastRoutingError != "" {
		input.LastReconcileError = response.LastRoutingError
	}
	input.RuntimeStates = instances
	for _, inst := range routingInstances {
		input.Instances = append(input.Instances, inspect.BabelInstanceInput{
			NetNS:          inst.NetNS,
			InstanceID:     inst.ID,
			Mode:           inst.Mode,
			ShutdownPolicy: inst.ShutdownPolicy,
			Enabled:        inst.Enabled,
		})
	}
	return inspect.BuildBabelDebug(input)
}

func debugRoutes(_ context.Context, _ *cli.Command) error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	return debugRoutesWithRuntime(rt, os.Stdout)
}

func debugRoutesWithRuntime(rt *Runtime, w io.Writer) error {
	response, ok, err := routesDumpViaControl(rt)
	if err != nil {
		return err
	}
	var dump *inspecthttp.RoutesResponse
	if ok && response.RoutesDump != nil {
		dump = response.RoutesDump
	} else {
		state, err := rt.LoadState()
		if err != nil {
			return err
		}
		configureValidation(state.Network)
		ars, err := routing.BuildAuthorizedRouteSet(state.Network, rt.Now())
		if err != nil {
			return err
		}
		dump = inspecthttp.RoutesFromAuthorizedSet(state.ManagedZone, ars)
	}
	return inspecttext.WriteRoutesDebug(w, dump)
}

func debugRoute(_ context.Context, cmd *cli.Command) error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	return debugRouteWithRuntime(rt, cmd.Args().First(), os.Stdout)
}

func debugRouteWithRuntime(rt *Runtime, prefixArg string, w io.Writer) error {
	canonical, err := routing.CanonicalizePrefix(prefixArg)
	if err != nil {
		return fmt.Errorf("invalid prefix %q: %w", prefixArg, err)
	}
	prefix, err := netip.ParsePrefix(canonical)
	if err != nil {
		return err
	}
	response, ok, err := routesDumpViaControl(rt)
	if err != nil {
		return err
	}
	var dump *inspecthttp.RoutesResponse
	if ok && response.RoutesDump != nil {
		dump = response.RoutesDump
	} else {
		state, err := rt.LoadState()
		if err != nil {
			return err
		}
		configureValidation(state.Network)
		ars, err := routing.BuildAuthorizedRouteSet(state.Network, rt.Now())
		if err != nil {
			return err
		}
		dump = inspecthttp.RoutesFromAuthorizedSet(state.ManagedZone, ars)
	}
	return inspecttext.WriteRouteDebug(w, prefix, dump)
}

// routingNetnsForOverlay returns the netns name for a given overlay group ID.
// Used by debug links routing state lookup.
func routingNetnsForOverlay(rt *Runtime, overlayID string) string {
	if rt == nil || rt.Config == nil {
		return ""
	}
	// Find the overlay group, resolve its netns name.
	for _, group := range rt.Config.IPsec.LinkGroups {
		if group.ID == overlayID {
			return resolveOverlayNetNSName(group, rt.Config.Overlay.DefaultNetNS)
		}
	}
	return ""
}

// routingNetnsNameForLinkInstance returns the netns name for a link instance.
// LinkInstance.GroupID = overlay ID; we map overlay → netns via config.
func routingNetnsNameForLinkInstance(rt *Runtime, groupID string) string {
	return routingNetnsForOverlay(rt, groupID)
}

// _ ensures import is used
var _ = ipsec.NetNSName
