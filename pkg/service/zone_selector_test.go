package service

import (
	"testing"

	"github.com/Catofes/higgs/pkg/core/zone"
)

func TestZoneSelectorMatches(t *testing.T) {
	tests := []struct {
		rule     string
		kind     ZoneSelectorKind
		matches  []zone.ZonePath
		nonmatch []zone.ZonePath
	}{
		{
			rule: "node-a.catofes.", kind: ZoneSelectorExact,
			matches:  []zone.ZonePath{"node-a.catofes."},
			nonmatch: []zone.ZonePath{"catofes.", "child.node-a.catofes.", "node-b.catofes."},
		},
		{
			rule: "*.catofes.", kind: ZoneSelectorSubtree,
			matches:  []zone.ZonePath{"catofes.", "node-a.catofes.", "child.node-a.catofes."},
			nonmatch: []zone.ZonePath{zone.RootZone, "example."},
		},
		{
			rule: "*.", kind: ZoneSelectorAll,
			matches:  []zone.ZonePath{"catofes.", "node-a.catofes.", "example."},
			nonmatch: []zone.ZonePath{zone.RootZone, "invalid"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.rule, func(t *testing.T) {
			selector, err := ParseZoneSelector(tc.rule)
			if err != nil {
				t.Fatalf("ParseZoneSelector: %v", err)
			}
			if selector.Kind() != tc.kind || selector.String() != tc.rule {
				t.Fatalf("selector = kind %q string %q", selector.Kind(), selector.String())
			}
			for _, candidate := range tc.matches {
				if !selector.Matches(candidate) {
					t.Errorf("%q should match %q", tc.rule, candidate)
				}
			}
			for _, candidate := range tc.nonmatch {
				if selector.Matches(candidate) {
					t.Errorf("%q should not match %q", tc.rule, candidate)
				}
			}
		})
	}
}

func TestParseZoneSelectorRejectsAmbiguousWildcards(t *testing.T) {
	for _, value := range []string{"", "catofes", "node-*.catofes.", "*catofes.", "*..", "**.catofes."} {
		t.Run(value, func(t *testing.T) {
			if selector, err := ParseZoneSelector(value); err == nil {
				t.Fatalf("ParseZoneSelector(%q) = %#v, want error", value, selector)
			}
		})
	}
}
