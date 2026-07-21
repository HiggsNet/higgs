package firewall

import (
	"fmt"
	"strings"
	"unicode"
)

const (
	maxInlineRulesPerPoint = 256
	maxInlineRuleLength    = 4096
)

var allHookPoints = []HookPoint{
	HookPreInput,
	HookPostInput,
	HookPreForward,
	HookPostForward,
	HookPreOutput,
	HookPostOutput,
	HookHostPrePrerouting,
	HookHostPostPrerouting,
	HookHostPreInput,
	HookHostPostInput,
}

var overlayHookPoints = []HookPoint{
	HookPreInput,
	HookPostInput,
	HookPreForward,
	HookPostForward,
	HookPreOutput,
	HookPostOutput,
}

var hostHookPoints = []HookPoint{
	HookHostPrePrerouting,
	HookHostPostPrerouting,
	HookHostPreInput,
	HookHostPostInput,
}

// Rules returns the ordered expressions configured at point.
func (h InlineHookRules) Rules(point HookPoint) []string {
	switch point {
	case HookPreInput:
		return h.PreInput
	case HookPostInput:
		return h.PostInput
	case HookPreForward:
		return h.PreForward
	case HookPostForward:
		return h.PostForward
	case HookPreOutput:
		return h.PreOutput
	case HookPostOutput:
		return h.PostOutput
	case HookHostPrePrerouting:
		return h.HostPrePrerouting
	case HookHostPostPrerouting:
		return h.HostPostPrerouting
	case HookHostPreInput:
		return h.HostPreInput
	case HookHostPostInput:
		return h.HostPostInput
	default:
		return nil
	}
}

// HasNFTInlineHooks reports whether any nft-native rule is configured.
func HasNFTInlineHooks(h NativeHooks) bool {
	return hasInlineRules(h.NFT, allHookPoints)
}

// HasIPTablesInlineHooks reports whether any iptables/ip6tables-native rule is
// configured.
func HasIPTablesInlineHooks(h NativeHooks) bool {
	return hasInlineRules(h.IPTables.IPv4, allHookPoints) || hasInlineRules(h.IPTables.IPv6, allHookPoints)
}

func hasInlineRules(h InlineHookRules, points []HookPoint) bool {
	for _, point := range points {
		if len(h.Rules(point)) > 0 {
			return true
		}
	}
	return false
}

func hasNativeHookAt(h NativeHooks, point HookPoint) bool {
	return len(h.NFT.Rules(point)) > 0 ||
		len(h.IPTables.IPv4.Rules(point)) > 0 ||
		len(h.IPTables.IPv6.Rules(point)) > 0
}

// ValidateNativeHooks validates rule-body syntax boundaries without invoking
// nft, iptables, a shell, or any other external process.
func ValidateNativeHooks(h NativeHooks) error {
	if err := validateInlineRuleSet("nft", "", h.NFT, validateNFTInlineRule); err != nil {
		return err
	}
	if err := validateInlineRuleSet("iptables", "ipv4", h.IPTables.IPv4, validateIPTablesInlineRule); err != nil {
		return err
	}
	return validateInlineRuleSet("iptables", "ipv6", h.IPTables.IPv6, validateIPTablesInlineRule)
}

func validateInlineRuleSet(backend, family string, hooks InlineHookRules, validate func(string) error) error {
	for _, point := range allHookPoints {
		rules := hooks.Rules(point)
		if len(rules) > maxInlineRulesPerPoint {
			return fmt.Errorf("%s%s hook %s: %d rules exceeds limit %d", backend, familyLabel(family), point, len(rules), maxInlineRulesPerPoint)
		}
		for i, rule := range rules {
			if len(rule) > maxInlineRuleLength {
				return fmt.Errorf("%s%s hook %s rule %d: length %d exceeds limit %d", backend, familyLabel(family), point, i, len(rule), maxInlineRuleLength)
			}
			if err := validate(rule); err != nil {
				return fmt.Errorf("%s%s hook %s rule %d: %w", backend, familyLabel(family), point, i, err)
			}
		}
	}
	return nil
}

func familyLabel(family string) string {
	if family == "" {
		return ""
	}
	return "/" + family
}

func validateNFTInlineRule(rule string) error {
	trimmed := strings.TrimSpace(rule)
	if trimmed == "" {
		return fmt.Errorf("rule is empty")
	}
	if strings.ContainsAny(rule, "\r\n\x00;") {
		return fmt.Errorf("rule contains a forbidden statement separator or control character")
	}
	fields := strings.Fields(trimmed)
	if len(fields) == 0 {
		return fmt.Errorf("rule is empty")
	}
	switch strings.ToLower(fields[0]) {
	case "add", "delete", "replace", "insert", "flush", "include", "table", "chain", "ruleset":
		return fmt.Errorf("rule must be an expression body, not an nft object command")
	}
	return nil
}

func validateIPTablesInlineRule(rule string) error {
	if strings.TrimSpace(rule) == "" {
		return fmt.Errorf("rule is empty")
	}
	if strings.ContainsAny(rule, "\r\n\x00;|&<>`$()") {
		return fmt.Errorf("rule contains a forbidden shell metacharacter or control character")
	}
	args, err := splitIPTablesRule(rule)
	if err != nil {
		return err
	}
	if len(args) == 0 {
		return fmt.Errorf("rule is empty")
	}
	for _, arg := range args {
		if isForbiddenIPTablesArg(arg) {
			return fmt.Errorf("argument %q may manage rules, chains, or tables", arg)
		}
	}
	return nil
}

func isForbiddenIPTablesArg(arg string) bool {
	forbidden := map[string]bool{
		"-A": true, "--append": true,
		"-C": true, "--check": true,
		"-D": true, "--delete": true,
		"-I": true, "--insert": true,
		"-R": true, "--replace": true,
		"-L": true, "--list": true,
		"-S": true, "--list-rules": true,
		"-F": true, "--flush": true,
		"-Z": true, "--zero": true,
		"-N": true, "--new-chain": true,
		"-X": true, "--delete-chain": true,
		"-P": true, "--policy": true,
		"-E": true, "--rename-chain": true,
		"-t": true, "--table": true,
	}
	if forbidden[arg] {
		return true
	}
	for _, prefix := range []string{
		"--append=", "--check=", "--delete=", "--insert=", "--replace=",
		"--list=", "--list-rules=", "--flush=", "--zero=", "--new-chain=",
		"--delete-chain=", "--policy=", "--rename-chain=", "--table=",
	} {
		if strings.HasPrefix(arg, prefix) {
			return true
		}
	}
	if len(arg) > 2 && arg[0] == '-' && strings.ContainsRune("ACDIRLSFZXNPEt", rune(arg[1])) {
		// Reject compact management forms such as -Afoo and -tfilter. The
		// long-option forms are covered by the exact checks above.
		return true
	}
	return false
}

// splitIPTablesRule performs shellwords-like tokenization but deliberately
// does not implement variable, command, glob, or tilde expansion.
func splitIPTablesRule(rule string) ([]string, error) {
	var args []string
	var current strings.Builder
	var quote rune
	escaped := false
	tokenStarted := false
	flush := func() {
		if tokenStarted {
			args = append(args, current.String())
			current.Reset()
			tokenStarted = false
		}
	}

	for _, r := range rule {
		if escaped {
			current.WriteRune(r)
			tokenStarted = true
			escaped = false
			continue
		}
		if quote != 0 {
			if r == quote {
				quote = 0
				tokenStarted = true
				continue
			}
			if r == '\\' && quote == '"' {
				escaped = true
				continue
			}
			current.WriteRune(r)
			tokenStarted = true
			continue
		}
		switch {
		case r == '\\':
			escaped = true
			tokenStarted = true
		case r == '\'' || r == '"':
			quote = r
			tokenStarted = true
		case unicode.IsSpace(r):
			flush()
		default:
			current.WriteRune(r)
			tokenStarted = true
		}
	}
	if escaped {
		return nil, fmt.Errorf("rule ends with an incomplete escape")
	}
	if quote != 0 {
		return nil, fmt.Errorf("rule contains an unterminated quote")
	}
	flush()
	return args, nil
}
