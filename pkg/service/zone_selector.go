package service

import (
	"fmt"
	"strings"

	"github.com/Catofes/photon/pkg/core/zone"
)

type ZoneSelectorKind string

const (
	ZoneSelectorExact   ZoneSelectorKind = "exact"
	ZoneSelectorSubtree ZoneSelectorKind = "subtree"
	ZoneSelectorAll     ZoneSelectorKind = "all"
)

// ZoneSelector is one local allow_zones rule. Wildcards are deliberately
// limited to a complete left-most "*." label so authorization stays easy to
// audit and does not become a general glob language.
type ZoneSelector struct {
	kind ZoneSelectorKind
	base zone.ZonePath
}

func ParseZoneSelector(raw string) (ZoneSelector, error) {
	value := strings.TrimSpace(raw)
	if value == "*." {
		return ZoneSelector{kind: ZoneSelectorAll, base: zone.RootZone}, nil
	}
	if after, ok := strings.CutPrefix(value, "*."); ok {
		base := zone.ZonePath(after)
		if base == zone.RootZone || !base.Valid() {
			return ZoneSelector{}, fmt.Errorf("invalid subtree zone selector %q", raw)
		}
		return ZoneSelector{kind: ZoneSelectorSubtree, base: base}, nil
	}
	if strings.Contains(value, "*") {
		return ZoneSelector{}, fmt.Errorf("invalid zone selector %q: wildcard is only allowed as a complete left-most '*.' label", raw)
	}
	base := zone.ZonePath(value)
	if !base.Valid() {
		return ZoneSelector{}, fmt.Errorf("invalid exact zone selector %q", raw)
	}
	return ZoneSelector{kind: ZoneSelectorExact, base: base}, nil
}

func (s ZoneSelector) String() string {
	switch s.kind {
	case ZoneSelectorAll:
		return "*."
	case ZoneSelectorSubtree:
		return "*." + s.base.String()
	case ZoneSelectorExact:
		return s.base.String()
	default:
		return ""
	}
}

// Matches reports whether candidate is selected. The global "*." rule
// intentionally excludes the root authority Zone: it means every node Zone,
// not the trust root itself.
func (s ZoneSelector) Matches(candidate zone.ZonePath) bool {
	if !candidate.Valid() {
		return false
	}
	switch s.kind {
	case ZoneSelectorAll:
		return !candidate.IsRoot()
	case ZoneSelectorExact:
		return candidate == s.base
	case ZoneSelectorSubtree:
		for current := candidate; ; current = current.Parent() {
			if current == s.base {
				return true
			}
			if current.IsRoot() {
				return false
			}
		}
	default:
		return false
	}
}
