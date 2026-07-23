//go:build !linux

package health

// NewRawICMProber falls back to the portable implementation on platforms that
// do not expose Linux network namespaces and raw ICMP socket primitives.
func NewRawICMProber(fallback Prober) Prober { return fallback }
