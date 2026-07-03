package bird

import (
	"bytes"
	"fmt"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	defaultTableID        = "main"
	defaultMetricBase     = 100
	defaultMetricStaged   = 200
	defaultMetricDraining = 500
	defaultDeviceScanTime = 5 * time.Second
	defaultLogTarget      = "log syslog all"
)

// DefaultConfigGenerator generates BIRD configuration files from
// BirdInstanceSpec and authorized prefix sets.
type DefaultConfigGenerator struct{}

// Generate renders a complete bird.conf for the supplied spec.
func (DefaultConfigGenerator) Generate(spec BirdInstanceSpec, importSet, exportSet []netip.Prefix) ([]byte, error) {
	spec = applyDefaults(spec)
	if err := validateSpec(spec); err != nil {
		return nil, err
	}

	cfg := buildConfig(spec, importSet, exportSet)
	return renderConfig(cfg)
}

func applyDefaults(spec BirdInstanceSpec) BirdInstanceSpec {
	if spec.TableID == "" {
		spec.TableID = defaultTableID
	}
	if spec.MetricBase == 0 {
		spec.MetricBase = defaultMetricBase
	}
	if spec.MetricStaged == 0 {
		spec.MetricStaged = defaultMetricStaged
	}
	if spec.MetricDraining == 0 {
		spec.MetricDraining = defaultMetricDraining
	}
	if spec.DeviceScanTime == 0 {
		spec.DeviceScanTime = defaultDeviceScanTime
	}
	if spec.LogTarget == "" {
		spec.LogTarget = defaultLogTarget
	}
	if spec.InternalTableName == "" {
		spec.InternalTableName = defaultInternalTableName(spec.NetNSName)
	}
	// Merge legacy InterfacePattern into InterfacePatterns.
	if spec.InterfacePattern != "" {
		spec.InterfacePatterns = mergeInterfacePatterns(spec.InterfacePatterns, spec.InterfacePattern)
		spec.InterfacePattern = ""
	}
	if len(spec.InterfacePatterns) == 0 {
		spec.InterfacePatterns = []string{"hgs*"}
	}
	return spec
}

func mergeInterfacePatterns(patterns []string, extra string) []string {
	seen := make(map[string]bool, len(patterns)+1)
	var out []string
	for _, p := range patterns {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	if !seen[extra] {
		out = append(out, extra)
	}
	return out
}

func validateSpec(spec BirdInstanceSpec) error {
	if spec.RouterID == 0 {
		return fmt.Errorf("bird: router id is required")
	}
	if spec.NetNSName == "" {
		return fmt.Errorf("bird: netns name is required")
	}
	switch spec.Mode {
	case BirdModeManaged, BirdModeExternal:
		// ok
	case BirdModeDisabled:
		return fmt.Errorf("bird: cannot generate config for disabled mode")
	default:
		return fmt.Errorf("bird: invalid mode %q", spec.Mode)
	}
	if spec.TableID != defaultTableID {
		if _, err := strconv.ParseUint(spec.TableID, 10, 32); err != nil {
			return fmt.Errorf("bird: table id must be %q or a numeric kernel table id", defaultTableID)
		}
	}
	if !filepath.IsAbs(spec.ControlSocketPath) {
		return fmt.Errorf("bird: control socket path must be absolute")
	}
	if !filepath.IsAbs(spec.PIDFilePath) {
		return fmt.Errorf("bird: pid file path must be absolute")
	}
	if !filepath.IsAbs(spec.ConfigPath) {
		return fmt.Errorf("bird: config path must be absolute")
	}
	return nil
}

func buildConfig(spec BirdInstanceSpec, importSet, exportSet []netip.Prefix) BirdConfig {
	suffix := sanitizeNetNSName(spec.NetNSName)
	internalTable := spec.InternalTableName
	ipv4Table := internalTable + "4"
	ipv6Table := internalTable + "6"
	kernelName := "higgs_kern_" + suffix
	kernelName4 := kernelName + "4"
	kernelName6 := kernelName + "6"
	babelName := "higgs_babel_" + suffix
	importFilterName := "higgs_import_" + suffix
	exportFilterName := "higgs_export_" + suffix
	staticName := "higgs_static_" + suffix

	var kernelTableID uint32
	if spec.TableID != defaultTableID {
		if n, err := strconv.ParseUint(spec.TableID, 10, 32); err == nil {
			kernelTableID = uint32(n)
		}
	}

	importFilter := FilterBlock{
		Name: importFilterName,
		Body: RenderFilter(importFilterName, importSet, spec.BogonPrefixes),
	}
	exportFilter := FilterBlock{
		Name: exportFilterName,
		Body: RenderFilter(exportFilterName, exportSet, spec.BogonPrefixes),
	}

	interfacePatterns := spec.InterfacePatterns
	if len(interfacePatterns) == 0 {
		interfacePatterns = []string{"hgs*"}
	}

	// Determine if upstream is enabled and build upstream interface block.
	var upstreamBlock *BabelInterfaceBlock
	if spec.Upstream != nil {
		pat := spec.Upstream.InterfacePattern
		if pat == "" {
			pat = "hgs-2host*"
		}
		upstreamBlock = &BabelInterfaceBlock{
			InterfacePattern: pat,
			TypeTunnel:       false, // veth does NOT use type tunnel
			MetricBase:       spec.MetricBase,
		}
	}

	// Build static route block if any static routes are specified.
	var staticBlocks []StaticRouteBlock
	if len(spec.StaticRoutes) > 0 {
		block := StaticRouteBlock{Name: staticName}
		for _, sr := range spec.StaticRoutes {
			route := StaticRoute(sr)
			if sr.Prefix.Addr().Is4() {
				block.IPv4Routes = append(block.IPv4Routes, route)
			} else {
				block.IPv6Routes = append(block.IPv6Routes, route)
			}
		}
		staticBlocks = append(staticBlocks, block)
	}

	return BirdConfig{
		RouterID:       spec.RouterID,
		LogTarget:      spec.LogTarget,
		ListenSocket:   spec.ControlSocketPath,
		DeviceScanTime: spec.DeviceScanTime,
		IPv4Table:      ipv4Table,
		IPv6Table:      ipv6Table,
		KernelTableID:  kernelTableID,
		Kernel: []KernelProtocolBlock{
			{
				Name:          kernelName4,
				IPv4Table:     ipv4Table,
				KernelTableID: kernelTableID,
				Learn:         false,
				Persist:       false,
			},
			{
				Name:          kernelName6,
				IPv6Table:     ipv6Table,
				KernelTableID: kernelTableID,
				Learn:         false,
				Persist:       false,
			},
		},
		Babel: BabelProtocolBlock{
			Name:             babelName,
			IPv4Table:        ipv4Table,
			IPv6Table:        ipv6Table,
			InterfacePattern: renderInterfacePatterns(interfacePatterns),
			TypeTunnel:       true,
			MetricBase:       spec.MetricBase,
			MetricStaged:     spec.MetricStaged,
			MetricDraining:   spec.MetricDraining,
			ECMP:             spec.ECMP,
			ECMPLimit:        spec.ECMPLimit,
			Auth:             spec.BabelAuth,
			UpstreamBlock:    upstreamBlock,
		},
		ImportFilters: []FilterBlock{importFilter},
		ExportFilters: []FilterBlock{exportFilter},
		StaticRoutes:  staticBlocks,
	}
}

// renderInterfacePatterns renders multiple BIRD interface patterns as a
// space-separated list of quoted strings, e.g. "hgs*" "wg*".
func renderInterfacePatterns(patterns []string) string {
	quoted := make([]string, len(patterns))
	for i, p := range patterns {
		quoted[i] = fmt.Sprintf("%q", p)
	}
	return strings.Join(quoted, " ")
}

func renderConfig(cfg BirdConfig) ([]byte, error) {
	var b bytes.Buffer

	fmt.Fprintln(&b, "# Higgs-generated BIRD config")
	fmt.Fprintln(&b, "# Do not edit manually.")
	fmt.Fprintln(&b)
	fmt.Fprintf(&b, "%s;\n", cfg.LogTarget)
	fmt.Fprintf(&b, "router id %s;\n", formatRouterID(cfg.RouterID))
	fmt.Fprintln(&b, "# Control socket path is set on the bird command line with -s.")
	fmt.Fprintln(&b)
	fmt.Fprintf(&b, "protocol device {\n    scan time %d;\n}\n\n", int(cfg.DeviceScanTime.Seconds()))

	if cfg.IPv4Table != "" {
		fmt.Fprintf(&b, "ipv4 table %s;\n", cfg.IPv4Table)
	}
	if cfg.IPv6Table != "" {
		fmt.Fprintf(&b, "ipv6 table %s;\n", cfg.IPv6Table)
	}
	if cfg.IPv4Table != "" || cfg.IPv6Table != "" {
		fmt.Fprintln(&b)
	}

	for _, kp := range cfg.Kernel {
		fmt.Fprintf(&b, "protocol kernel %s {\n", kp.Name)
		if kp.IPv4Table != "" {
			fmt.Fprintf(&b, "    ipv4 { table %s; export all; };\n", kp.IPv4Table)
		}
		if kp.IPv6Table != "" {
			fmt.Fprintf(&b, "    ipv6 { table %s; export all; };\n", kp.IPv6Table)
		}
		if kp.KernelTableID != 0 {
			fmt.Fprintf(&b, "    kernel table %d;\n", kp.KernelTableID)
		}
		fmt.Fprintln(&b, "}")
		fmt.Fprintln(&b)
	}

	for _, f := range cfg.ImportFilters {
		fmt.Fprintln(&b, f.Body)
		fmt.Fprintln(&b)
	}
	for _, f := range cfg.ExportFilters {
		fmt.Fprintln(&b, f.Body)
		fmt.Fprintln(&b)
	}

	fmt.Fprintf(&b, "protocol babel %s {\n", cfg.Babel.Name)
	if cfg.Babel.IPv4Table != "" {
		fmt.Fprintln(&b, "    ipv4 {")
		fmt.Fprintf(&b, "        table %s;\n", cfg.Babel.IPv4Table)
		if len(cfg.ImportFilters) > 0 {
			fmt.Fprintf(&b, "        import filter %s;\n", cfg.ImportFilters[0].Name)
		}
		if len(cfg.ExportFilters) > 0 {
			fmt.Fprintf(&b, "        export filter %s;\n", cfg.ExportFilters[0].Name)
		}
		fmt.Fprintln(&b, "    };")
	}
	if cfg.Babel.IPv6Table != "" {
		fmt.Fprintln(&b, "    ipv6 {")
		fmt.Fprintf(&b, "        table %s;\n", cfg.Babel.IPv6Table)
		if len(cfg.ImportFilters) > 0 {
			fmt.Fprintf(&b, "        import filter %s;\n", cfg.ImportFilters[0].Name)
		}
		if len(cfg.ExportFilters) > 0 {
			fmt.Fprintf(&b, "        export filter %s;\n", cfg.ExportFilters[0].Name)
		}
		fmt.Fprintln(&b, "    };")
	}
	// Note: BIRD 2.19.x does not accept an "ecmp" directive inside the
	// Babel protocol block, so ECMP/Limit fields from the spec are currently
	// ignored during rendering. The struct fields are retained for future
	// BIRD versions or alternative backends.
	if cfg.Babel.InterfacePattern != "" {
		fmt.Fprintf(&b, "    interface %s {\n", cfg.Babel.InterfacePattern)
		if cfg.Babel.TypeTunnel {
			fmt.Fprintln(&b, "        type tunnel;")
		}
		fmt.Fprintf(&b, "        rxcost %d;\n", cfg.Babel.MetricBase)
		fmt.Fprintln(&b, "        hello interval 4 s;")
		fmt.Fprintln(&b, "        update interval 4 s;")
		if cfg.Babel.Auth != nil && cfg.Babel.Auth.Enabled {
			fmt.Fprintf(&b, "        auth %q key id %d password %q;\n", cfg.Babel.Auth.Algorithm, cfg.Babel.Auth.KeyID, cfg.Babel.Auth.Password)
		}
		fmt.Fprintln(&b, "    };")
	}
	// Upstream veth interface block (no type tunnel).
	if cfg.Babel.UpstreamBlock != nil {
		ub := cfg.Babel.UpstreamBlock
		fmt.Fprintf(&b, "    interface %q {\n", ub.InterfacePattern)
		// Do NOT emit "type tunnel" for veth — it uses default multicast/unicast.
		fmt.Fprintf(&b, "        rxcost %d;\n", ub.MetricBase)
		fmt.Fprintln(&b, "        hello interval 4 s;")
		fmt.Fprintln(&b, "        update interval 4 s;")
		fmt.Fprintln(&b, "    };")
	}
	fmt.Fprintln(&b, "}")

	// Static route blocks.
	for _, sr := range cfg.StaticRoutes {
		renderStaticRouteBlock(&b, sr, cfg.IPv4Table, cfg.IPv6Table)
	}

	return b.Bytes(), nil
}

// renderStaticRouteBlock renders one "protocol static { ... }" block.
func renderStaticRouteBlock(b *bytes.Buffer, sr StaticRouteBlock, ipv4Table, ipv6Table string) {
	fmt.Fprintf(b, "\nprotocol static %s {\n", sr.Name)
	if ipv4Table != "" && len(sr.IPv4Routes) > 0 {
		fmt.Fprintf(b, "    ipv4 { table %s; };\n", ipv4Table)
		for _, r := range sr.IPv4Routes {
			renderStaticRouteLine(b, r)
		}
	}
	if ipv6Table != "" && len(sr.IPv6Routes) > 0 {
		fmt.Fprintf(b, "    ipv6 { table %s; };\n", ipv6Table)
		for _, r := range sr.IPv6Routes {
			renderStaticRouteLine(b, r)
		}
	}
	fmt.Fprintln(b, "}")
}

func renderStaticRouteLine(b *bytes.Buffer, r StaticRoute) {
	if r.Blackhole {
		fmt.Fprintf(b, "    route %s blackhole;\n", r.Prefix.String())
		return
	}
	if r.Via != "" {
		fmt.Fprintf(b, "    route %s via \"%s\";\n", r.Prefix.String(), r.Via)
		return
	}
	// No via and no blackhole: default to blackhole for safety.
	fmt.Fprintf(b, "    route %s blackhole;\n", r.Prefix.String())
}

func formatRouterID(id uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		(id>>24)&0xff,
		(id>>16)&0xff,
		(id>>8)&0xff,
		id&0xff,
	)
}

// sanitizeNetNSName replaces non-alphanumeric characters in a netns name with
// underscores for use in BIRD identifiers (table/protocol/filter names).
func sanitizeNetNSName(name string) string {
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	s := b.String()
	if s == "" {
		s = "netns"
	}
	return s
}

func defaultInternalTableName(netnsName string) string {
	return "higgs_" + sanitizeNetNSName(netnsName)
}
