package ipsec

import (
	"fmt"
	"time"
)

const (
	DefaultIKEPort  = 500
	DefaultNATTPort = 4500
)

type PortPlanOptions struct {
	Mode          string
	Range         *PortRange
	FixedIKE      uint16
	FixedNATT     uint16
	ObservedIKE   uint16
	ObservedNATT  uint16
	Generation    uint64
	Previous      *PortRecord
	PreviousGrace time.Duration
	PreviousLimit int
	Now           time.Time
}

func PlanPortRecord(opts PortPlanOptions) (*PortRecord, error) {
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	mode := opts.Mode
	if mode == "" {
		mode = PortModeFixed
	}
	selection, err := plannedCurrentPortSelection(opts)
	if err != nil {
		return nil, err
	}
	record := &PortRecord{
		Version:   1,
		Mode:      mode,
		Current:   &selection,
		UpdatedAt: now.Unix(),
	}
	if mode == PortModeRange {
		r := *opts.Range
		record.Range = &r
	}
	record.Previous = plannedPreviousPortSelections(opts, selection, now)
	if err := record.Validate(); err != nil {
		return nil, err
	}
	return record, nil
}

func plannedCurrentPortSelection(opts PortPlanOptions) (PortSelection, error) {
	switch opts.Mode {
	case "", PortModeFixed:
		ike := opts.FixedIKE
		if ike == 0 {
			ike = DefaultIKEPort
		}
		natt := opts.FixedNATT
		if natt == 0 {
			natt = DefaultNATTPort
		}
		return newPlannedPortSelection(opts.Generation, ike, natt, opts.ObservedIKE, opts.ObservedNATT), nil
	case PortModeRange:
		if opts.Range == nil {
			return PortSelection{}, fmt.Errorf("range mode requires range")
		}
		ike, natt, err := selectPortsFromRange(*opts.Range, opts.Generation)
		if err != nil {
			return PortSelection{}, err
		}
		return newPlannedPortSelection(opts.Generation, ike, natt, opts.ObservedIKE, opts.ObservedNATT), nil
	default:
		return PortSelection{}, fmt.Errorf("unsupported port mode %q", opts.Mode)
	}
}

func newPlannedPortSelection(generation uint64, ike, natt, observedIKE, observedNATT uint16) PortSelection {
	return PortSelection{
		Generation: generation,
		IKE: PortBinding{
			Local:      ike,
			Advertised: ike,
			Observed:   observedIKE,
		},
		NATT: PortBinding{
			Local:      natt,
			Advertised: natt,
			Observed:   observedNATT,
		},
	}
}

func selectPortsFromRange(r PortRange, generation uint64) (uint16, uint16, error) {
	if r.From == 0 || r.To == 0 || r.From > r.To {
		return 0, 0, fmt.Errorf("invalid port range %d-%d", r.From, r.To)
	}
	width := uint32(r.To) - uint32(r.From) + 1
	if width < 2 {
		return 0, 0, fmt.Errorf("port range %d-%d must contain at least two ports", r.From, r.To)
	}
	offset := uint32(generation % uint64(width))
	ike := uint16(uint32(r.From) + offset)
	natt := uint16(uint32(r.From) + ((offset + 1) % width))
	return ike, natt, nil
}

func plannedPreviousPortSelections(opts PortPlanOptions, current PortSelection, now time.Time) []PortSelection {
	if opts.Previous == nil || opts.PreviousGrace <= 0 {
		return nil
	}
	limit := opts.PreviousLimit
	if limit <= 0 {
		limit = 1
	}
	expires := now.Add(opts.PreviousGrace).Unix()
	var out []PortSelection
	if opts.Previous.Current != nil && opts.Previous.Current.Generation != current.Generation {
		previous := *opts.Previous.Current
		previous.ValidUntil = expires
		out = append(out, previous)
	}
	for _, previous := range opts.Previous.Previous {
		if len(out) >= limit {
			break
		}
		if previous.Generation == current.Generation || portSelectionExpired(previous, now) {
			continue
		}
		out = append(out, previous)
	}
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}
