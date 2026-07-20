package plugin

import (
	"io"
	"strings"
	"testing"
	"time"

	prom "github.com/prometheus/client_golang/prometheus"
)

func TestZSTAC84903ConntrackScanDoesNotHoldCollectorLock(t *testing.T) {
	collector := &vipCollector{
		previousStats: make(map[string]*SessionStat),
		counters: map[string]*VipCounter{
			"172.24.4.184": {VipUuid: "vip-uuid"},
		},
	}

	reader, writer := io.Pipe()
	defer writer.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		collector.collectConntrackCounters(reader, map[string]string{"172.24.4.184": "vip-uuid"}, time.Now().Unix())
	}()

	locked := make(chan struct{})
	go func() {
		collector.mu.Lock()
		collector.mu.Unlock()
		close(locked)
	}()

	select {
	case <-locked:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("conntrack scan blocked vipCollector.mu")
	}

	reader.Close()
	<-done
}

func TestZSTAC84903ConntrackDeltasApplyToVipCounters(t *testing.T) {
	collector := &vipCollector{
		previousStats: make(map[string]*SessionStat),
		counters: map[string]*VipCounter{
			"172.24.4.184": {VipUuid: "vip-uuid"},
		},
	}

	conntrack := strings.NewReader("ipv4 2 tcp 6 86390 ESTABLISHED src=10.0.0.1 dst=172.24.4.184 sport=12345 dport=80 packets=10 bytes=600 src=172.24.4.184 dst=10.0.0.1 sport=80 dport=12345 packets=8 bytes=480 mark=0 zone=0 use=2\n")
	deltas, stats := collector.collectConntrackCounters(conntrack, map[string]string{"172.24.4.184": "vip-uuid"}, time.Now().Unix())
	collector.applyConntrackDeltas(deltas)

	if stats.matchedSessions != 1 {
		t.Fatalf("expected 1 matched session, got %d", stats.matchedSessions)
	}

	counter := collector.counters["172.24.4.184"]
	if counter.InPackets != 10 || counter.InBytes != 600 || counter.OutPackets != 8 || counter.OutBytes != 480 {
		t.Fatalf("unexpected counter: %+v", counter)
	}
}

func TestZSTAC84903ConntrackCollectIntervalMatchesMetricsScrape(t *testing.T) {
	if conntrackCollectInterval != 10*time.Second {
		t.Fatalf("expected conntrack collect interval to be 10s, got %s", conntrackCollectInterval)
	}
}

func TestZSTAC85393PrometheusUpdateOnlyReadsCachedConntrackCounters(t *testing.T) {
	collector := &vipCollector{
		inByteEntry: prom.NewDesc(
			"zstack_vip_in_bytes",
			"VIP inbound traffic in bytes",
			[]string{LABEL_VIP_UUID}, nil,
		),
		inPktEntry: prom.NewDesc(
			"zstack_vip_in_packages",
			"VIP inbound traffic packages",
			[]string{LABEL_VIP_UUID}, nil,
		),
		outByteEntry: prom.NewDesc(
			"zstack_vip_out_bytes",
			"VIP outbound traffic in bytes",
			[]string{LABEL_VIP_UUID}, nil,
		),
		outPktEntry: prom.NewDesc(
			"zstack_vip_out_packages",
			"VIP outbound traffic packages",
			[]string{LABEL_VIP_UUID}, nil,
		),
		previousStats: make(map[string]*SessionStat),
		counters: map[string]*VipCounter{
			"172.24.4.184": {VipUuid: "vip-uuid", InBytes: 1, InPackets: 2, OutBytes: 3, OutPackets: 4},
		},
	}

	metrics := make(chan prom.Metric, 4)
	if err := collector.Update(metrics); err != nil {
		t.Fatalf("unexpected update error: %v", err)
	}

	if collector.conntrackCollecting.Load() {
		t.Fatal("prometheus update should not start conntrack collection")
	}
	if len(metrics) != 4 {
		t.Fatalf("expected 4 cached VIP metrics, got %d", len(metrics))
	}
}

func TestZSTAC84903RemoveVipClearsPreviousStats(t *testing.T) {
	collector := &vipCollector{
		previousStats: map[string]*SessionStat{
			"vip-in": {
				DstIp:      "172.24.4.184",
				LastUpdate: time.Now().Unix(),
			},
			"vip-reply": {
				ReplyDstIp: "172.24.4.184",
				LastUpdate: time.Now().Unix(),
			},
			"other": {
				DstIp:      "172.24.4.200",
				LastUpdate: time.Now().Unix(),
			},
		},
	}

	collector.removePreviousStatsByVip("172.24.4.184")

	if _, ok := collector.previousStats["vip-in"]; ok {
		t.Fatal("expected previous inbound session to be removed")
	}
	if _, ok := collector.previousStats["vip-reply"]; ok {
		t.Fatal("expected previous reply session to be removed")
	}
	if _, ok := collector.previousStats["other"]; !ok {
		t.Fatal("unexpected unrelated session removal")
	}
}
