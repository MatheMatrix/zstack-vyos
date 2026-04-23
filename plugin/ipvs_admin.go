package plugin

import (
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"
)

// IpvsAdmin is the single point of convergence for `ipvsadm` shell-out
// (D-016).  All write operations against the kernel IPVS table flow through
// this interface; production wiring uses realIpvsAdmin and tests use
// fakeIpvsAdmin.  The name follows NA-3: "Admin" is the Linux ipvsadm tool
// suffix, not a "human administrator" abstraction.
type IpvsAdmin interface {
	AddService(f IpvsFrontendService) error
	DelService(f IpvsFrontendService) error
	AddBackend(f IpvsFrontendService, b IpvsBackendServer) error
	DelBackend(f IpvsFrontendService, b IpvsBackendServer) error
	EditService(f IpvsFrontendService) error
	EditBackend(f IpvsFrontendService, b IpvsBackendServer) error
	Save() ([]IpvsFrontendService, error)
}

// realIpvsAdmin invokes ipvsadm via exec.Command with argv slices —
// never `bash -c` — so user-controlled VIP/RS strings cannot be
// shell-interpolated.  All mutating operations are idempotent at the
// wrapper level: re-add of an existing service is treated as success
// (kernel returns EEXIST=17), as is delete of a non-existent service
// (kernel returns ENOENT=2 / EINVAL=22).
type realIpvsAdmin struct {
	mu sync.Mutex
}

// NewRealIpvsAdmin returns the production IpvsAdmin implementation.
func NewRealIpvsAdmin() IpvsAdmin {
	return &realIpvsAdmin{}
}

func (a *realIpvsAdmin) run(args ...string) (stdout, stderr string, exit int, err error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	full := append([]string{"ipvsadm"}, args...)
	cmd := exec.Command("sudo", full...)
	var so, se strings.Builder
	cmd.Stdout = &so
	cmd.Stderr = &se
	err = cmd.Run()
	stdout = so.String()
	stderr = se.String()
	if cmd.ProcessState != nil {
		exit = cmd.ProcessState.ExitCode()
	}
	return
}

func bracketIPv6(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed != nil && parsed.To4() == nil {
		return fmt.Sprintf("[%s]", ip)
	}
	return ip
}

func protoFlag(p string) string {
	return IpvsadmProtoFlag(p)
}

func vipPort(f IpvsFrontendService) string {
	return bracketIPv6(f.FrontIp) + ":" + f.FrontPort
}

func rsPort(b IpvsBackendServer) string {
	return bracketIPv6(b.BackendIp) + ":" + b.BackendPort
}

// idempotentExitCode reports whether the given (exit, stderr) pair indicates
// "the requested state already holds" rather than a real error.
func idempotentExitCode(op string, exit int, stderr string) bool {
	low := strings.ToLower(stderr)
	switch op {
	case "add":
		// EEXIST: "Service already exists" / "Destination already exists"
		return exit == 17 || strings.Contains(low, "already exists")
	case "del":
		// ENOENT/EINVAL: "No such service" / "No such destination"
		return exit == 2 || exit == 22 ||
			strings.Contains(low, "no such service") ||
			strings.Contains(low, "no such destination") ||
			strings.Contains(low, "memory allocation problem")
	}
	return false
}

func (a *realIpvsAdmin) wrapErr(op, cmdline string, exit int, stderr string, err error) error {
	if err == nil && exit == 0 {
		return nil
	}
	if idempotentExitCode(op, exit, stderr) {
		log.Debugf("[ipvsadm] %s idempotent ok exit=%d stderr=%q cmd=%s", op, exit, strings.TrimSpace(stderr), cmdline)
		return nil
	}
	return fmt.Errorf("ipvsadm %s failed exit=%d err=%v stderr=%s cmd=%s",
		op, exit, err, strings.TrimSpace(stderr), cmdline)
}

func (a *realIpvsAdmin) AddService(f IpvsFrontendService) error {
	args := []string{"-A", protoFlag(f.ProtocolType), vipPort(f)}
	if f.Scheduler != "" {
		args = append(args, "-s", f.Scheduler)
	}
	_, se, ec, err := a.run(args...)
	return a.wrapErr("add", "ipvsadm "+strings.Join(args, " "), ec, se, err)
}

func (a *realIpvsAdmin) DelService(f IpvsFrontendService) error {
	args := []string{"-D", protoFlag(f.ProtocolType), vipPort(f)}
	_, se, ec, err := a.run(args...)
	return a.wrapErr("del", "ipvsadm "+strings.Join(args, " "), ec, se, err)
}

func (a *realIpvsAdmin) EditService(f IpvsFrontendService) error {
	args := []string{"-E", protoFlag(f.ProtocolType), vipPort(f)}
	if f.Scheduler != "" {
		args = append(args, "-s", f.Scheduler)
	}
	_, se, ec, err := a.run(args...)
	return a.wrapErr("edit", "ipvsadm "+strings.Join(args, " "), ec, se, err)
}

func (a *realIpvsAdmin) AddBackend(f IpvsFrontendService, b IpvsBackendServer) error {
	args := backendArgs("-a", f, b)
	_, se, ec, err := a.run(args...)
	return a.wrapErr("add", "ipvsadm "+strings.Join(args, " "), ec, se, err)
}

func (a *realIpvsAdmin) DelBackend(f IpvsFrontendService, b IpvsBackendServer) error {
	args := []string{"-d", protoFlag(f.ProtocolType), vipPort(f), "-r", rsPort(b)}
	_, se, ec, err := a.run(args...)
	return a.wrapErr("del", "ipvsadm "+strings.Join(args, " "), ec, se, err)
}

func (a *realIpvsAdmin) EditBackend(f IpvsFrontendService, b IpvsBackendServer) error {
	args := backendArgs("-e", f, b)
	_, se, ec, err := a.run(args...)
	return a.wrapErr("edit", "ipvsadm "+strings.Join(args, " "), ec, se, err)
}

func backendArgs(op string, f IpvsFrontendService, b IpvsBackendServer) []string {
	args := []string{op, protoFlag(f.ProtocolType), vipPort(f), "-r", rsPort(b)}
	switch strings.ToLower(b.ConnectionType) {
	case "-g", "dr", "":
		args = append(args, "-g")
	case "-m", "nat", "fullnat":
		args = append(args, "-m")
	case "-i", "tunnel":
		args = append(args, "-i")
	default:
		args = append(args, b.ConnectionType)
	}
	if b.Weight != "" {
		args = append(args, "-w", b.Weight)
	}
	return args
}

func (a *realIpvsAdmin) Save() ([]IpvsFrontendService, error) {
	conf, err := NewIpvsConfFromSave()
	if err != nil {
		return nil, err
	}
	out := make([]IpvsFrontendService, 0, len(conf.Services))
	for _, fs := range conf.Services {
		if fs == nil {
			continue
		}
		out = append(out, *fs)
	}
	return out, nil
}

// ---- fakeIpvsAdmin ---------------------------------------------------------

// fakeIpvsAdmin keeps an in-memory model of the IPVS table for unit tests.
// It preserves idempotency semantics (re-add ok, del-missing ok) so callers
// can be exercised against the same contract as the real implementation.
type fakeIpvsAdmin struct {
	mu       sync.Mutex
	services map[string]*IpvsFrontendService
	// addLog records all mutating calls in order for assertions.
	addLog []string
}

// NewFakeIpvsAdmin returns an in-memory IpvsAdmin for tests.
func NewFakeIpvsAdmin() *fakeIpvsAdmin {
	return &fakeIpvsAdmin{services: map[string]*IpvsFrontendService{}}
}

func (f *fakeIpvsAdmin) keyOfService(s IpvsFrontendService) string {
	return s.ProtocolType + "|" + s.FrontIp + "|" + s.FrontPort
}

func (f *fakeIpvsAdmin) keyOfBackend(b IpvsBackendServer) string {
	return b.BackendIp + ":" + b.BackendPort
}

func (f *fakeIpvsAdmin) AddService(s IpvsFrontendService) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	k := f.keyOfService(s)
	f.addLog = append(f.addLog, "AddService:"+k)
	if _, ok := f.services[k]; ok {
		return nil
	}
	cp := s
	cp.BackendServers = map[string]*IpvsBackendServer{}
	f.services[k] = &cp
	return nil
}

func (f *fakeIpvsAdmin) DelService(s IpvsFrontendService) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	k := f.keyOfService(s)
	f.addLog = append(f.addLog, "DelService:"+k)
	delete(f.services, k)
	return nil
}

func (f *fakeIpvsAdmin) EditService(s IpvsFrontendService) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	k := f.keyOfService(s)
	f.addLog = append(f.addLog, "EditService:"+k)
	if cur, ok := f.services[k]; ok {
		cur.Scheduler = s.Scheduler
		return nil
	}
	return errors.New("no such service")
}

func (f *fakeIpvsAdmin) AddBackend(s IpvsFrontendService, b IpvsBackendServer) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	k := f.keyOfService(s)
	bk := f.keyOfBackend(b)
	f.addLog = append(f.addLog, "AddBackend:"+k+"->"+bk)
	cur, ok := f.services[k]
	if !ok {
		cp := s
		cp.BackendServers = map[string]*IpvsBackendServer{}
		f.services[k] = &cp
		cur = &cp
	}
	if _, exists := cur.BackendServers[bk]; exists {
		return nil
	}
	cp := b
	cur.BackendServers[bk] = &cp
	return nil
}

func (f *fakeIpvsAdmin) DelBackend(s IpvsFrontendService, b IpvsBackendServer) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	k := f.keyOfService(s)
	bk := f.keyOfBackend(b)
	f.addLog = append(f.addLog, "DelBackend:"+k+"->"+bk)
	if cur, ok := f.services[k]; ok {
		delete(cur.BackendServers, bk)
	}
	return nil
}

func (f *fakeIpvsAdmin) EditBackend(s IpvsFrontendService, b IpvsBackendServer) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	k := f.keyOfService(s)
	bk := f.keyOfBackend(b)
	f.addLog = append(f.addLog, "EditBackend:"+k+"->"+bk)
	if cur, ok := f.services[k]; ok {
		if existing, exists := cur.BackendServers[bk]; exists {
			existing.Weight = b.Weight
			existing.ConnectionType = b.ConnectionType
			return nil
		}
	}
	return errors.New("no such backend")
}

func (f *fakeIpvsAdmin) Save() ([]IpvsFrontendService, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]IpvsFrontendService, 0, len(f.services))
	for _, s := range f.services {
		out = append(out, *s)
	}
	return out, nil
}

// Snapshot returns the in-memory service map.  Test-only.
func (f *fakeIpvsAdmin) Snapshot() map[string]*IpvsFrontendService {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make(map[string]*IpvsFrontendService, len(f.services))
	for k, v := range f.services {
		cp := *v
		out[k] = &cp
	}
	return out
}

// CallLog returns the ordered list of mutating calls.  Test-only.
func (f *fakeIpvsAdmin) CallLog() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string{}, f.addLog...)
}

// ---- shared helpers --------------------------------------------------------

// AtoiOrZero is exported for use by other packages constructing IPVS args
// without re-importing strconv.
func AtoiOrZero(s string) int {
	v, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return v
}
