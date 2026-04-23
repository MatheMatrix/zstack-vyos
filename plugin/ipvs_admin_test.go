package plugin

import (
	"strings"
	"testing"
)

// fakeIpvsAdmin contract: re-add ok, del-missing ok, snapshot accurate.
func TestFakeIpvsAdminContract(t *testing.T) {
	a := NewFakeIpvsAdmin()
	fs := IpvsFrontendService{
		ProtocolType: IpvsProtoTCP,
		FrontIp:      "10.0.0.1",
		FrontPort:    "80",
		Scheduler:    "rr",
	}
	bs := IpvsBackendServer{
		BackendIp:      "192.168.0.10",
		BackendPort:    "8080",
		Weight:         "1",
		ConnectionType: "-m",
	}

	if err := a.AddService(fs); err != nil {
		t.Fatalf("AddService: %v", err)
	}
	// Idempotent re-add.
	if err := a.AddService(fs); err != nil {
		t.Fatalf("AddService idempotent: %v", err)
	}
	if err := a.AddBackend(fs, bs); err != nil {
		t.Fatalf("AddBackend: %v", err)
	}
	if err := a.AddBackend(fs, bs); err != nil {
		t.Fatalf("AddBackend idempotent: %v", err)
	}
	snap, _ := a.Save()
	if len(snap) != 1 || len(snap[0].BackendServers) != 1 {
		t.Fatalf("Save returned %+v", snap)
	}
	if err := a.DelBackend(fs, bs); err != nil {
		t.Fatalf("DelBackend: %v", err)
	}
	// Idempotent del-missing.
	if err := a.DelBackend(fs, bs); err != nil {
		t.Fatalf("DelBackend idempotent: %v", err)
	}
	if err := a.DelService(fs); err != nil {
		t.Fatalf("DelService: %v", err)
	}
	if err := a.DelService(fs); err != nil {
		t.Fatalf("DelService idempotent: %v", err)
	}
	if got := len(a.Snapshot()); got != 0 {
		t.Fatalf("snapshot non-empty after deletes: %d", got)
	}
}

// idempotentExitCode mapping.
func TestIdempotentExitCode(t *testing.T) {
	cases := []struct {
		op       string
		exit     int
		stderr   string
		expected bool
	}{
		{"add", 17, "Service already exists", true},
		{"add", 0, "", false},
		{"add", 1, "weird error", false},
		{"del", 2, "No such service", true},
		{"del", 22, "no such destination", true},
		{"del", 0, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.op+":"+tc.stderr, func(t *testing.T) {
			got := idempotentExitCode(tc.op, tc.exit, tc.stderr)
			if got != tc.expected {
				t.Errorf("got %v want %v", got, tc.expected)
			}
		})
	}
}

// vipPort/rsPort handle IPv6 bracketing.
func TestBracketIPv6(t *testing.T) {
	cases := map[string]string{
		"10.0.0.1":  "10.0.0.1",
		"::1":       "[::1]",
		"fd00::abc": "[fd00::abc]",
		"":          "",
	}
	for in, want := range cases {
		if got := bracketIPv6(in); got != want {
			t.Errorf("bracketIPv6(%q) = %q want %q", in, got, want)
		}
	}
}

// backendArgs translates ConnectionType to ipvsadm flag form.
func TestBackendArgsConnectionType(t *testing.T) {
	fs := IpvsFrontendService{ProtocolType: IpvsProtoTCP, FrontIp: "1.1.1.1", FrontPort: "80"}
	cases := []struct {
		ct     string
		want   string
	}{
		{"dr", "-g"},
		{"-g", "-g"},
		{"", "-g"},
		{"nat", "-m"},
		{"fullnat", "-m"},
		{"-m", "-m"},
		{"tunnel", "-i"},
		{"-i", "-i"},
	}
	for _, tc := range cases {
		t.Run(tc.ct, func(t *testing.T) {
			b := IpvsBackendServer{BackendIp: "10.0.0.5", BackendPort: "8080", ConnectionType: tc.ct, Weight: "1"}
			args := backendArgs("-a", fs, b)
			joined := strings.Join(args, " ")
			if !strings.Contains(joined, tc.want) {
				t.Errorf("ct=%q args=%v expected to contain %q", tc.ct, args, tc.want)
			}
		})
	}
}
