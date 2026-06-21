package ipsec

import (
	"fmt"
	"net/url"
	"path"
	"strconv"
	"strings"

	"github.com/Catofes/higgs/pkg/core/zone"
)

const (
	RuleFamilyDual = "dual"
)

type MeshPolicyRule struct {
	Raw         string
	Provider    string
	ZonePattern string
	Role        string
	Tag         string
	Accept      string
	Family      string
	Sources     []string
	PathMode    string
	Direction   string
	MaxPeers    int
}

func ParseMeshPolicyRule(raw string) (MeshPolicyRule, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return MeshPolicyRule{}, fmt.Errorf("mesh policy rule is empty")
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return MeshPolicyRule{}, fmt.Errorf("parse mesh policy rule %q: %w", raw, err)
	}
	rule := MeshPolicyRule{
		Raw:      raw,
		Provider: parsed.Scheme,
		MaxPeers: -1,
	}
	if rule.Provider == "" {
		return MeshPolicyRule{}, fmt.Errorf("mesh policy rule %q missing provider scheme", raw)
	}
	if rule.Provider != ProviderStrongSwan {
		return MeshPolicyRule{}, fmt.Errorf("unsupported mesh policy provider %q", rule.Provider)
	}
	target := parsed.Host
	if target == "" && strings.Trim(parsed.Path, "/") != "" {
		target = strings.Trim(parsed.Path, "/")
	}
	if target == "" {
		return MeshPolicyRule{}, fmt.Errorf("mesh policy rule %q missing target", raw)
	}
	if key, value, ok := strings.Cut(target, "="); ok {
		switch key {
		case "role":
			rule.Role = value
		case "tag":
			rule.Tag = value
		default:
			return MeshPolicyRule{}, fmt.Errorf("unsupported mesh policy target %q", target)
		}
		if value == "" {
			return MeshPolicyRule{}, fmt.Errorf("mesh policy target %q has empty value", key)
		}
	} else {
		rule.ZonePattern = target
		if err := validateZonePattern(rule.ZonePattern); err != nil {
			return MeshPolicyRule{}, err
		}
	}
	query := parsed.Query()
	rule.Accept = firstQuery(query, "accept")
	rule.Family = firstQuery(query, "family")
	rule.PathMode = firstQuery(query, "mode")
	rule.Direction = NormalizeDirection(firstQuery(query, "direction"))
	if rawSources := firstQuery(query, "source"); rawSources != "" {
		for _, source := range strings.Split(rawSources, ",") {
			source = strings.TrimSpace(source)
			if source == "" {
				continue
			}
			rule.Sources = append(rule.Sources, source)
		}
	}
	if rawMaxPeers := firstQuery(query, "max_peers"); rawMaxPeers != "" {
		value, err := strconv.Atoi(rawMaxPeers)
		if err != nil || value < 0 {
			return MeshPolicyRule{}, fmt.Errorf("invalid max_peers %q", rawMaxPeers)
		}
		rule.MaxPeers = value
	}
	if err := rule.Validate(); err != nil {
		return MeshPolicyRule{}, err
	}
	return rule, nil
}

func ParseMeshPolicyRules(raw []string) ([]MeshPolicyRule, error) {
	rules := make([]MeshPolicyRule, 0, len(raw))
	for i, item := range raw {
		rule, err := ParseMeshPolicyRule(item)
		if err != nil {
			return nil, fmt.Errorf("rule[%d]: %w", i, err)
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

func (r MeshPolicyRule) Validate() error {
	if r.Provider != ProviderStrongSwan {
		return fmt.Errorf("unsupported mesh policy provider %q", r.Provider)
	}
	if r.ZonePattern == "" && r.Role == "" && r.Tag == "" {
		return fmt.Errorf("mesh policy rule must target zone, role, or tag")
	}
	if r.Accept != "" && !oneOf(r.Accept, AcceptNone, AcceptInbound, AcceptBidirectional) {
		return fmt.Errorf("unsupported mesh policy accept %q", r.Accept)
	}
	if r.Family != "" && !oneOf(r.Family, RuleFamilyDual, FamilyIPv4, FamilyIPv6) {
		return fmt.Errorf("unsupported mesh policy family %q", r.Family)
	}
	if r.PathMode != "" && !oneOf(r.PathMode, PathModeFamilyRedundant, PathModeExhaustive) {
		return fmt.Errorf("unsupported mesh policy mode %q", r.PathMode)
	}
	if r.Direction != "" && !oneOf(r.Direction, DirectionInbound, DirectionOutbound, DirectionBidirectional) {
		return fmt.Errorf("unsupported mesh policy direction %q", r.Direction)
	}
	for _, source := range r.Sources {
		if !oneOf(source, SourceManualAddress, SourceManualDNS, SourceDiscovery, SourceReflector, SourceLocal) {
			return fmt.Errorf("unsupported mesh policy source %q", source)
		}
	}
	if r.MaxPeers < -1 {
		return fmt.Errorf("max peers must be non-negative")
	}
	return nil
}

func (r MeshPolicyRule) MatchesZone(peer zone.ZonePath) bool {
	if r.ZonePattern == "" {
		return false
	}
	if r.ZonePattern == string(peer) {
		return true
	}
	ok, err := path.Match(r.ZonePattern, string(peer))
	return err == nil && ok
}

func validateZonePattern(pattern string) error {
	if pattern == "" {
		return fmt.Errorf("zone pattern is required")
	}
	if strings.Contains(pattern, "://") {
		return fmt.Errorf("invalid zone pattern %q", pattern)
	}
	if _, err := path.Match(pattern, "node.example."); err != nil {
		return fmt.Errorf("invalid zone glob %q: %w", pattern, err)
	}
	return nil
}

func firstQuery(values url.Values, key string) string {
	if got := values.Get(key); got != "" {
		return strings.TrimSpace(got)
	}
	return ""
}
