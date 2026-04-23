package ipvshc

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestRoundTripHello(t *testing.T) {
	in := Hello{DaemonVersion: "5.8.0", ProtocolVersion: ProtocolVersion, StartedAt: 1700000000}
	env, err := MakeEnvelope("uuid-1", 1700000001, MsgHello, in)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := Encode(env)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(string(wire), "\n") {
		t.Fatalf("wire missing trailing newline: %q", string(wire))
	}
	got, err := Decode(wire)
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != MsgHello || got.ID != "uuid-1" {
		t.Fatalf("envelope mismatch: %+v", got)
	}
	var out Hello
	if err := DecodeBody(got, &out); err != nil {
		t.Fatal(err)
	}
	if out != in {
		t.Fatalf("body mismatch: got %+v want %+v", out, in)
	}
}

func TestRoundTripSnapshot(t *testing.T) {
	in := Snapshot{
		Seq: 42,
		Listeners: []SnapshotListener{
			{
				ListenerUuid: "lst-1",
				Protocol:     "tcp",
				IpvsMode:     "dr",
				Scheduler:    "rr",
				FrontIp:      "10.0.0.1",
				FrontPort:    "80",
				Backends: []SnapshotBackend{
					{BackendIp: "192.168.0.10", BackendPort: "8080", Weight: "1", ConnectionType: "-g"},
				},
				HealthCheck: SnapshotHealthSpec{Type: "tcp", IntervalSeconds: 5, TimeoutSeconds: 2, HealthyThreshold: 2, UnhealthyThreshold: 3},
			},
		},
	}
	env, err := MakeEnvelope("uuid-2", 1700000002, MsgSnapshot, in)
	if err != nil {
		t.Fatal(err)
	}
	wire, _ := Encode(env)
	dec, err := Decode(wire)
	if err != nil {
		t.Fatal(err)
	}
	var out Snapshot
	if err := DecodeBody(dec, &out); err != nil {
		t.Fatal(err)
	}
	if out.Seq != 42 || len(out.Listeners) != 1 || out.Listeners[0].Backends[0].BackendIp != "192.168.0.10" {
		t.Fatalf("snapshot mismatch: %+v", out)
	}
}

func TestVersionMismatch(t *testing.T) {
	bad, _ := json.Marshal(&Envelope{V: 99, ID: "x", Ts: 0, Type: MsgHello})
	env, err := Decode(bad)
	if !errors.Is(err, ErrVersionMismatch) {
		t.Fatalf("expected ErrVersionMismatch, got %v", err)
	}
	if env == nil || env.ID != "x" {
		t.Fatalf("envelope should still be returned for reject reply: %+v", env)
	}
}

func TestDecodeMalformed(t *testing.T) {
	if _, err := Decode([]byte("not-json")); err == nil {
		t.Fatal("expected error on malformed input")
	}
}

func TestRsEventOpValues(t *testing.T) {
	for _, op := range []RsEventOp{RsEventUp, RsEventDown, RsEventWeight} {
		evt := RsEvent{Seq: 1, ListenerUuid: "l", RsIp: "1.1.1.1", RsPort: "80", Op: op}
		env, _ := MakeEnvelope("id", 0, MsgRsEvent, evt)
		wire, _ := Encode(env)
		dec, err := Decode(wire)
		if err != nil {
			t.Fatal(err)
		}
		var out RsEvent
		_ = DecodeBody(dec, &out)
		if out.Op != op {
			t.Fatalf("op roundtrip failed: got %q want %q", out.Op, op)
		}
	}
}
