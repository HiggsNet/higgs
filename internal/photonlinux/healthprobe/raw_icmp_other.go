//go:build !linux

package healthprobe

// NewRawICMProber falls back to the portable implementation on platforms that
// do not expose Linux network namespaces and raw ICMP socket primitives.
func NewRawICMProber(fallback Prober, _ ...RawICMPFallbackReporter) Prober { return fallback }

// RawICMPFallbackReporter is unused on platforms without the Linux raw-ICMP
// implementation.
type RawICMPFallbackReporter func(ProbeTarget, error)
