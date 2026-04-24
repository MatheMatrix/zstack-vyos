package plugin

import "errors"

// ErrEbpfArchUnsupported is returned by initEbpfVipCounter on architectures
// where eBPF support is intentionally excluded at compile time (e.g. loong64).
// Callers can distinguish this from unexpected runtime failures:
//
//	if errors.Is(err, ErrEbpfArchUnsupported) → expected, log Info
//	otherwise                                  → unexpected, log Warn
var ErrEbpfArchUnsupported = errors.New("eBPF not supported on this architecture")
