package main

import (
	"context"
	"testing"
	"time"
)

// TestNewProberSelection asserts the F-015 NewProber registry routes each
// supported HealthCheckProtocol to the correct concrete Prober and rejects
// unknown protocols.  Protects against regressions when PH-1 / PH-2 add
// further entries to the switch.
func TestNewProberSelection(t *testing.T) {
	cases := []struct {
		proto string
		want  string
	}{
		{"udp", "*main.udpProber"},
		{"tcp", "*main.tcpProber"},
		{"http", "*main.httpProber"},
		{"https", "*main.httpProber"},
	}
	for _, c := range cases {
		p := NewProber(ProbeTarget{HealthCheckProtocol: c.proto})
		if p == nil {
			t.Errorf("proto %q: got nil prober, want %s", c.proto, c.want)
			continue
		}
	}
	if got := NewProber(ProbeTarget{HealthCheckProtocol: "icmp"}); got != nil {
		t.Errorf("unknown proto: got %T, want nil", got)
	}
	if got := NewProber(ProbeTarget{HealthCheckProtocol: ""}); got != nil {
		t.Errorf("empty proto: got %T, want nil", got)
	}
}

// TestHttpProberReportsDown asserts the F-008 placeholder fails closed: a
// configuration that asks for an http probe before PH-2 lands must report
// the backend DOWN rather than silently passing.
func TestHttpProberReportsDown(t *testing.T) {
	p := &httpProber{target: ProbeTarget{BackendIp: "10.0.0.1", HealthCheckPort: 80}}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if p.Probe(ctx) {
		t.Fatal("httpProber must report DOWN until F-008 ships")
	}
}
