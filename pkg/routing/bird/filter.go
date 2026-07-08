package bird

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// RenderFilter returns a complete BIRD filter function named name.
// Authorized prefixes are accepted; bogon prefixes are rejected first.
// If prefixes is empty the filter rejects everything.
func RenderFilter(name string, prefixes []netip.Prefix, bogons []netip.Prefix) string {
	v4Bogons, v6Bogons := splitByFamily(bogons)
	v4Prefixes, v6Prefixes := splitByFamily(prefixes)

	var b strings.Builder
	fmt.Fprintf(&b, "filter %s {\n", name)
	b.WriteString("    if net ~ [ 0.0.0.0/0 ] then reject;\n")
	b.WriteString("    if net ~ [ ::/0 ] then reject;\n")
	writeRejectList(&b, v4Bogons)
	writeRejectList(&b, v6Bogons)
	writeAcceptList(&b, v4Prefixes)
	writeAcceptList(&b, v6Prefixes)
	b.WriteString("    reject;\n")
	b.WriteString("}")
	return b.String()
}

func splitByFamily(p []netip.Prefix) (v4, v6 []netip.Prefix) {
	for _, prefix := range p {
		if prefix.Addr().Is4() {
			v4 = append(v4, prefix)
		} else {
			v6 = append(v6, prefix)
		}
	}
	return
}

func sortPrefixes(p []netip.Prefix) []netip.Prefix {
	sort.Slice(p, func(i, j int) bool {
		return p[i].String() < p[j].String()
	})
	return p
}

func prefixListString(p []netip.Prefix, moreSpecific bool) string {
	p = sortPrefixes(p)
	parts := make([]string, len(p))
	for i, prefix := range p {
		s := prefix.String()
		if moreSpecific {
			s += "+"
		}
		parts[i] = s
	}
	return strings.Join(parts, ", ")
}

func acceptedPrefixListString(p []netip.Prefix) string {
	p = sortPrefixes(p)
	parts := make([]string, len(p))
	for i, prefix := range p {
		parts[i] = acceptedPrefixPattern(prefix)
	}
	return strings.Join(parts, ", ")
}

func acceptedPrefixPattern(prefix netip.Prefix) string {
	bits := prefix.Bits()
	if prefix.Addr().Is6() {
		const (
			minIPv6AnnounceBits = 48
			maxIPv6AnnounceBits = 96
		)
		if bits > maxIPv6AnnounceBits {
			return prefix.String()
		}
		minBits := max(bits, minIPv6AnnounceBits)
		return fmt.Sprintf("%s{%d,%d}", prefix.String(), minBits, maxIPv6AnnounceBits)
	}
	const (
		minIPv4AnnounceBits = 18
		maxIPv4AnnounceBits = 28
	)
	if bits > maxIPv4AnnounceBits {
		return prefix.String()
	}
	minBits := max(bits, minIPv4AnnounceBits)
	return fmt.Sprintf("%s{%d,%d}", prefix.String(), minBits, maxIPv4AnnounceBits)
}

func writeRejectList(b *strings.Builder, p []netip.Prefix) {
	if len(p) == 0 {
		return
	}
	fmt.Fprintf(b, "    if net ~ [ %s ] then reject;\n", prefixListString(p, true))
}

func writeAcceptList(b *strings.Builder, p []netip.Prefix) {
	if len(p) == 0 {
		return
	}
	fmt.Fprintf(b, "    if net ~ [ %s ] then accept;\n", acceptedPrefixListString(p))
}
