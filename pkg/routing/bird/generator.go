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
		spec.InternalTableName = defaultInternalTableName(spec.OverlayID)
	}
	return spec
}

func validateSpec(spec BirdInstanceSpec) error {
	if spec.RouterID == 0 {
		return fmt.Errorf("bird: router id is required")
	}
	if spec.OverlayID == "" {
		return fmt.Errorf("bird: overlay id is required")
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
	suffix := sanitizeOverlayID(spec.OverlayID)
	internalTable := spec.InternalTableName
	kernelName := "higgs_kern_" + suffix
	babelName := "higgs_babel_" + suffix
	importFilterName := "higgs_import_" + suffix
	exportFilterName := "higgs_export_" + suffix

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

	return BirdConfig{
		RouterID:       spec.RouterID,
		LogTarget:      spec.LogTarget,
		ListenSocket:   spec.ControlSocketPath,
		DeviceScanTime: spec.DeviceScanTime,
		IPv4Table:      internalTable,
		IPv6Table:      internalTable,
		KernelTableID:  kernelTableID,
		Kernel: KernelProtocolBlock{
			Name:          kernelName,
			IPv4Table:     internalTable,
			IPv6Table:     internalTable,
			KernelTableID: kernelTableID,
			Learn:         false,
			Persist:       false,
		},
		Babel: BabelProtocolBlock{
			Name:             babelName,
			IPv4Table:        internalTable,
			IPv6Table:        internalTable,
			InterfacePattern: spec.InterfacePattern,
			TypeTunnel:       true,
			MetricBase:       spec.MetricBase,
			MetricStaged:     spec.MetricStaged,
			MetricDraining:   spec.MetricDraining,
			ECMP:             spec.ECMP,
			ECMPLimit:        spec.ECMPLimit,
			Auth:             spec.BabelAuth,
		},
		ImportFilters: []FilterBlock{importFilter},
		ExportFilters: []FilterBlock{exportFilter},
	}
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

	fmt.Fprintf(&b, "protocol kernel %s {\n", cfg.Kernel.Name)
	if cfg.Kernel.IPv4Table != "" {
		fmt.Fprintf(&b, "    ipv4 { table %s; export all; };\n", cfg.Kernel.IPv4Table)
	}
	if cfg.Kernel.IPv6Table != "" {
		fmt.Fprintf(&b, "    ipv6 { table %s; export all; };\n", cfg.Kernel.IPv6Table)
	}
	if cfg.Kernel.KernelTableID != 0 {
		fmt.Fprintf(&b, "    kernel table %d;\n", cfg.Kernel.KernelTableID)
	}
	fmt.Fprintln(&b, "}")
	fmt.Fprintln(&b)

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
	if cfg.Babel.ECMP {
		if cfg.Babel.ECMPLimit > 0 {
			fmt.Fprintf(&b, "    ecmp on limit %d;\n", cfg.Babel.ECMPLimit)
		} else {
			fmt.Fprintln(&b, "    ecmp on;")
		}
	}
	if cfg.Babel.InterfacePattern != "" {
		fmt.Fprintf(&b, "    interface %q {\n", cfg.Babel.InterfacePattern)
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
	fmt.Fprintln(&b, "}")

	return b.Bytes(), nil
}

func formatRouterID(id uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		(id>>24)&0xff,
		(id>>16)&0xff,
		(id>>8)&0xff,
		id&0xff,
	)
}

func sanitizeOverlayID(id string) string {
	var b strings.Builder
	for _, r := range id {
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
		s = "overlay"
	}
	return s
}

func defaultInternalTableName(overlayID string) string {
	return "higgs_" + sanitizeOverlayID(overlayID)
}
