package bird

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/Catofes/higgs/pkg/core/zone"
)

func testBirdInstanceSpec() BirdInstanceSpec {
	return BirdInstanceSpec{
		RouterID:          0x01020304,
		NetNSName:         "ipsec-main",
		ControlSocketPath: "/run/higgs/bird-ipsec-main.ctl",
		PIDFilePath:       "/run/higgs/bird-ipsec-main.pid",
		ConfigPath:        "/etc/higgs/bird-ipsec-main.conf",
		Mode:              BirdModeManaged,
		InterfacePattern:  "hgs*",
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

	if !strings.Contains(s, "Higgs-generated BIRD config") {
		t.Error("missing Higgs-generated header comment")
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
	if !strings.Contains(s, "ipv4 table higgs_ipsec_main4;") {
		t.Error("missing ipv4 table declaration")
	}
	if !strings.Contains(s, "ipv6 table higgs_ipsec_main6;") {
		t.Error("missing ipv6 table declaration")
	}
	if !strings.Contains(s, "protocol kernel higgs_kern_ipsec_main") {
		t.Error("missing kernel protocol block")
	}
	if !strings.Contains(s, "protocol babel higgs_babel_ipsec_main") {
		t.Error("missing babel protocol block")
	}
	if !strings.Contains(s, "interface \"hgs*\"") {
		t.Error("missing interface pattern")
	}
	if !strings.Contains(s, "type tunnel;") {
		t.Error("missing type tunnel directive")
	}
	if !strings.Contains(s, "rxcost 100;") {
		t.Error("missing default rxcost")
	}
	if !strings.Contains(s, "filter higgs_import_ipsec_main") {
		t.Error("missing import filter")
	}
	if !strings.Contains(s, "filter higgs_export_ipsec_main") {
		t.Error("missing export filter")
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
	if !strings.Contains(filter, "10.0.0.0/8+") {
		t.Error("missing authorized IPv4 prefix acceptance")
	}
	if !strings.Contains(filter, "2001:db8::/32+") {
		t.Error("missing authorized IPv6 prefix acceptance")
	}
	if !strings.HasSuffix(filter, "    reject;\n}") {
		t.Error("missing final reject")
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
		ControlSocketPath: "/run/higgs/bird-ipsec-main.ctl",
		PIDFilePath:       "/run/higgs/bird-ipsec-main.pid",
		ConfigPath:        "/etc/higgs/bird-ipsec-main.conf",
		Mode:              BirdModeManaged,
		InterfacePattern:  "hgs*",
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
	spec.InterfacePatterns = []string{"hgs-live0", "hgs-live1"}

	gen := DefaultConfigGenerator{}
	cfg, err := gen.Generate(spec, nil, nil)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	s := string(cfg)
	if !strings.Contains(s, `interface "hgs-live0", "hgs-live1" {`) {
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

	if !strings.Contains(s, "10.0.0.0/8+") {
		t.Error("missing IPv4 authorized prefix")
	}
	if !strings.Contains(s, "2001:db8::/32+") {
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
