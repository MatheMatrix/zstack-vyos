//go:build linux && loong64

package plugin

import (
	"fmt"
	"net"
)

// LoongArch does not support the eBPF VIP counter path.
// All functions are no-ops so the platform uses conntrack mode.
// initEbpfVipCounter returns a non-nil error so vip.go logs an Info
// message and stays in conntrack mode — no Warn-level noise.
type vipEbpfObjects struct{}

var ebpfObjs *vipEbpfObjects

func initEbpfVipCounter() error {
	return fmt.Errorf("linux/loong64: %w", ErrEbpfArchUnsupported)
}

func ensureEbpfOnInterface(_ string) {}

func HasClsact(_ string) bool { return false }

func ResetEbpfAttachment(_ string) {}

func ebpfAddVip(_ net.IP) {}

func ebpfDelVip(_ net.IP) {}

func updateCountersByEbpf(_ map[string]*VipCounter) {}

func closeEbpfVipCounter() {}
