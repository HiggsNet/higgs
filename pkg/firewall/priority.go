package firewall

import (
	"fmt"
	"strconv"
	"strings"
)

const maxPriorityOffset = 10000

// ChainPriority is a constrained nftables priority expression. Base is one of
// the hook-specific symbolic priorities; Offset is rendered as "base +/- N".
// Keeping it typed prevents configuration text from escaping into nft syntax.
type ChainPriority struct {
	Base   string
	Offset int
}

// ChainPriorities configures nft base-chain priority at the three supported
// hook classes. iptables has no equivalent base-chain priority setting.
type ChainPriorities struct {
	Filter      ChainPriority
	Prerouting  ChainPriority
	Postrouting ChainPriority
}

func DefaultChainPriorities() ChainPriorities {
	return ChainPriorities{
		Filter:      ChainPriority{Base: "filter"},
		Prerouting:  ChainPriority{Base: "dstnat"},
		Postrouting: ChainPriority{Base: "srcnat"},
	}
}

func (p ChainPriorities) Normalized() ChainPriorities {
	defaults := DefaultChainPriorities()
	if p.Filter.Base == "" {
		p.Filter = defaults.Filter
	}
	if p.Prerouting.Base == "" {
		p.Prerouting = defaults.Prerouting
	}
	if p.Postrouting.Base == "" {
		p.Postrouting = defaults.Postrouting
	}
	return p
}

func (p ChainPriority) String() string {
	if p.Offset == 0 {
		return p.Base
	}
	if p.Offset > 0 {
		return fmt.Sprintf("%s + %d", p.Base, p.Offset)
	}
	return fmt.Sprintf("%s - %d", p.Base, -p.Offset)
}

// ParseChainPriority accepts either the hook's default symbolic priority or
// that priority followed by a spaced signed integer offset, such as
// "dstnat - 1". expectedBase binds every configuration field to its safe hook
// class rather than allowing arbitrary nft priority expressions.
func ParseChainPriority(raw, expectedBase string) (ChainPriority, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return ChainPriority{Base: expectedBase}, nil
	}
	fields := strings.Fields(value)
	if fields[0] != expectedBase {
		return ChainPriority{}, fmt.Errorf("must use %q as its priority base", expectedBase)
	}
	if len(fields) == 1 {
		return ChainPriority{Base: expectedBase}, nil
	}
	if len(fields) != 3 || (fields[1] != "+" && fields[1] != "-") {
		return ChainPriority{}, fmt.Errorf("must be %q or %q followed by + or - and an integer offset", expectedBase, expectedBase)
	}
	offset, err := strconv.Atoi(fields[2])
	if err != nil || offset < 0 || offset > maxPriorityOffset {
		return ChainPriority{}, fmt.Errorf("offset must be an integer between 0 and %d", maxPriorityOffset)
	}
	if fields[1] == "-" {
		offset = -offset
	}
	return ChainPriority{Base: expectedBase, Offset: offset}, nil
}

func ValidateChainPriorities(priorities ChainPriorities) error {
	priorities = priorities.Normalized()
	for _, item := range []struct {
		name string
		want string
		got  ChainPriority
	}{
		{name: "filter", want: "filter", got: priorities.Filter},
		{name: "prerouting", want: "dstnat", got: priorities.Prerouting},
		{name: "postrouting", want: "srcnat", got: priorities.Postrouting},
	} {
		if item.got.Base != item.want {
			return fmt.Errorf("priority.%s must use %q as its priority base", item.name, item.want)
		}
		if item.got.Offset < -maxPriorityOffset || item.got.Offset > maxPriorityOffset {
			return fmt.Errorf("priority.%s offset must be between -%d and %d", item.name, maxPriorityOffset, maxPriorityOffset)
		}
	}
	return nil
}
