package bird

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/HiggsNet/photon/pkg/core/zone"
)

func testBirdInstanceSpec() BirdInstanceSpec {
	return BirdInstanceSpec{
		RouterID:          0x01020304,
		NetNSName:         "ipsec-main",
		ControlSocketPath: "/run/photon/bird-ipsec-main.ctl",
		PIDFilePath:       "/run/photon/bird-ipsec-main.pid",
		ConfigPath:        "/etc/photon/bird-ipsec-main.conf",
		Mode:              BirdModeManaged,
		InterfacePattern:  "phx*",
	}
}

func TestGenerateManagedConfig(t *testing.T) {
	spec := testBirdInstanceSpec()
	importSet := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("2001:db8::/32"),
	}
	exportSet := []netip.Prefix{
		netip.MustParsePrefix("192.168.0.0/16"),
	}

	gen := DefaultConfigGenerator{}
	cfg, err := gen.Generate(spec, importSet, exportSet)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	s := string(cfg)

	if !strings.Contains(s, "Photon-generated BIRD config") {
		t.Error("missing Photon-generated header comment")
	}
	if !strings.Contains(s, "Do not edit manually") {
		t.Error("missing manual-edit warning")
	}
	if !strings.Contains(s, "router id 1.2.3.4;") {
		t.Error("missing router id directive")
	}
	if !strings.Contains(s, "log syslog all;") {
		t.Error("missing default log directive")
	}
	if !strings.Contains(s, "protocol device") {
		t.Error("missing protocol device block")
	}
	if !strings.Contains(s, "scan time 5;") {
		t.Error("missing default device scan time")
	}
	if !strings.Contains(s, "ipv4 table photon_ipsec_main4;") {
		t.Error("missing ipv4 table declaration")
	}
	if !strings.Contains(s, "ipv6 table photon_ipsec_main6;") {
		t.Error("missing ipv6 table declaration")
	}
	if !strings.Contains(s, "protocol kernel photon_kern_ipsec_main") {
		t.Error("missing kernel protocol block")
	}
	if !strings.Contains(s, "protocol babel photon_babel_ipsec_main") {
		t.Error("missing babel protocol block")
	}
	if !strings.Contains(s, "interface \"phx*\"") {
		t.Error("missing interface pattern")
	}
	if !strings.Contains(s, "type tunnel;") {
		t.Error("missing type tunnel directive")
	}
	if !strings.Contains(s, "rxcost 100;") {
		t.Error("missing default rxcost")
	}
	if !strings.Contains(s, "filter photon_import_ipsec_main") {
		t.Error("missing import filter")
	}
	if !strings.Contains(s, "filter photon_export_ipsec_main") {
		t.Error("missing export filter")
	}
}

func TestGenerateKernelMultipath(t *testing.T) {
	gen := DefaultConfigGenerator{}
	for _, tc := range []struct {
		name  string
		limit uint
		want  string
	}{
		{name: "without limit", want: "merge paths on;"},
		{name: "with limit", limit: 16, want: "merge paths on limit 16;"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec := testBirdInstanceSpec()
			spec.ECMP = true
			spec.ECMPLimit = tc.limit
			cfg, err := gen.Generate(spec, nil, nil)
			if err != nil {
				t.Fatalf("Generate failed: %v", err)
			}
			if !strings.Contains(string(cfg), tc.want) {
				t.Fatalf("generated config missing %q:\n%s", tc.want, cfg)
			}
		})
	}
}

func TestRenderFilter(t *testing.T) {
	prefixes := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("2001:db8::/32"),
	}
	bogons := []netip.Prefix{
		netip.MustParsePrefix("192.168.0.0/16"),
	}

	filter := RenderFilter("test_filter", prefixes, bogons)

	if !strings.Contains(filter, "filter test_filter {") {
		t.Error("missing filter declaration")
	}
	if !strings.Contains(filter, "if net ~ [ 0.0.0.0/0 ] then reject;") {
		t.Error("missing IPv4 default route rejection")
	}
	if !strings.Contains(filter, "if net ~ [ ::/0 ] then reject;") {
		t.Error("missing IPv6 default route rejection")
	}
	if !strings.Contains(filter, "192.168.0.0/16+") {
		t.Error("missing bogon rejection with more-specific")
	}
	if !strings.Contains(filter, "10.0.0.0/8{18,28}") {
		t.Error("missing bounded authorized IPv4 prefix acceptance")
	}
	if !strings.Contains(filter, "2001:db8::/32{48,96}") {
		t.Error("missing bounded authorized IPv6 prefix acceptance")
	}
	if !strings.HasSuffix(filter, "    reject;\n}") {
		t.Error("missing final reject")
	}
}

func TestAcceptedPrefixPatternBoundsIPv6Specifics(t *testing.T) {
	tests := []struct {
		raw  string
		want string
	}{
		{raw: "2001:db8::/32", want: "2001:db8::/32{48,96}"},
		{raw: "2001:db8:1:2::/64", want: "2001:db8:1:2::/64{64,96}"},
		{raw: "2001:db8:1:2:3::/80", want: "2001:db8:1:2:3::/80{80,96}"},
		{raw: "2001:db8:1:2:3:4::/112", want: "2001:db8:1:2:3:4::/112"},
	}
	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			if got := acceptedPrefixPattern(netip.MustParsePrefix(tt.raw)); got != tt.want {
				t.Fatalf("acceptedPrefixPattern(%s) = %s, want %s", tt.raw, got, tt.want)
			}
		})
	}
}

func TestAcceptedPrefixPatternBoundsIPv4Specifics(t *testing.T) {
	tests := []struct {
		raw  string
		want string
	}{
		{raw: "10.0.0.0/8", want: "10.0.0.0/8{18,28}"},
		{raw: "10.0.0.0/24", want: "10.0.0.0/24{24,28}"},
		{raw: "10.0.0.0/28", want: "10.0.0.0/28{28,28}"},
		{raw: "10.0.0.1/32", want: "10.0.0.1/32"},
	}
	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			if got := acceptedPrefixPattern(netip.MustParsePrefix(tt.raw)); got != tt.want {
				t.Fatalf("acceptedPrefixPattern(%s) = %s, want %s", tt.raw, got, tt.want)
			}
		})
	}
}

func TestStableRouterIDDeterministic(t *testing.T) {
	z := zone.ZonePath("test.example.")
	root := []byte("root-trust")
	overlay := "overlay-1"

	id1 := StableRouterID(z, root, overlay)
	id2 := StableRouterID(z, root, overlay)

	if id1 == 0 {
		t.Error("router id is zero")
	}
	if id1 != id2 {
		t.Errorf("router id not deterministic: %d vs %d", id1, id2)
	}
}

func TestDefaultsApplied(t *testing.T) {
	spec := BirdInstanceSpec{
		RouterID:          0x01020304,
		NetNSName:         "ipsec-main",
		ControlSocketPath: "/run/photon/bird-ipsec-main.ctl",
		PIDFilePath:       "/run/photon/bird-ipsec-main.pid",
		ConfigPath:        "/etc/photon/bird-ipsec-main.conf",
		Mode:              BirdModeManaged,
		InterfacePattern:  "phx*",
	}

	gen := DefaultConfigGenerator{}
	cfg, err := gen.Generate(spec, nil, nil)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	s := string(cfg)

	if !strings.Contains(s, "rxcost 100;") {
		t.Error("default metric base not applied")
	}
	if !strings.Contains(s, "scan time 5;") {
		t.Error("default device scan time not applied")
	}
	if !strings.Contains(s, "log syslog all;") {
		t.Error("default log target not applied")
	}
}

func TestRenderMultipleInterfacePatterns(t *testing.T) {
	spec := testBirdInstanceSpec()
	spec.InterfacePattern = ""
	spec.InterfacePatterns = []string{"phx-live0", "phx-live1"}

	gen := DefaultConfigGenerator{}
	cfg, err := gen.Generate(spec, nil, nil)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	s := string(cfg)
	if !strings.Contains(s, `interface "phx-live0", "phx-live1" {`) {
		t.Fatalf("interface pattern list not comma-separated:\n%s", s)
	}
}

func TestIPv4AndIPv6Prefixes(t *testing.T) {
	spec := testBirdInstanceSpec()
	importSet := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("2001:db8::/32"),
	}

	gen := DefaultConfigGenerator{}
	cfg, err := gen.Generate(spec, importSet, nil)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	s := string(cfg)

	if !strings.Contains(s, "10.0.0.0/8") {
		t.Error("missing IPv4 authorized prefix")
	}
	if !strings.Contains(s, "2001:db8::/32") {
		t.Error("missing IPv6 authorized prefix")
	}
}

func TestBabelAuthRendered(t *testing.T) {
	spec := testBirdInstanceSpec()
	spec.BabelAuth = &BabelAuthSpec{
		Enabled:   true,
		Algorithm: "hmac sha256",
		KeyID:     7,
		Password:  "secret-key",
	}

	gen := DefaultConfigGenerator{}
	cfg, err := gen.Generate(spec, nil, nil)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	s := string(cfg)

	want := "auth \"hmac sha256\" key id 7 password \"secret-key\";"
	if !strings.Contains(s, want) {
		t.Errorf("auth block not rendered correctly, want substring %q in:\n%s", want, s)
	}
}

func TestDisabledModeReturnsError(t *testing.T) {
	spec := testBirdInstanceSpec()
	spec.Mode = BirdModeDisabled

	gen := DefaultConfigGenerator{}
	_, err := gen.Generate(spec, nil, nil)
	if err == nil {
		t.Error("expected error for disabled mode")
	}
}
