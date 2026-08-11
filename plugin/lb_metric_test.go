package plugin

import (
	"strings"
	"testing"

	prom "github.com/prometheus/client_golang/prometheus"
)

func TestTransformToMetricSkipsOnlyDisabledBackendHealthStatus(t *testing.T) {
	const (
		listenerUuid = "listener-1"
		lbUuid       = "lb-1"
		backendIp    = "2001:db8::10"
	)

	disabledGroup := ServerGroupInfo{
		ServerGroupUuid: "group-disabled",
		BackendServers: []BackendServerInfo{{
			Ip:       backendIp,
			Disabled: true,
		}},
	}
	enabledGroup := ServerGroupInfo{
		ServerGroupUuid: "group-enabled",
		BackendServers: []BackendServerInfo{{
			Ip:       backendIp,
			Disabled: false,
		}},
	}
	listener := &HaproxyListener{
		lb: LbInfo{
			LbUuid:       lbUuid,
			ListenerUuid: listenerUuid,
			ServerGroups: []ServerGroupInfo{disabledGroup, enabledGroup},
		},
		maxSession: 100,
		lastCounters: &CachedCounters{counters: []*LbCounter{
			{
				listenerUuid:    listenerUuid,
				serverGroupUuid: disabledGroup.ServerGroupUuid,
				ip:              backendIp,
				Status:          0,
				sessionNumber:   1,
			},
			{
				listenerUuid:    listenerUuid,
				serverGroupUuid: enabledGroup.ServerGroupUuid,
				ip:              backendIp,
				Status:          1,
				sessionNumber:   2,
			},
		}},
	}

	collector := NewLbPrometheusCollector().(*loadBalancerCollector)
	metricCh := make(chan prom.Metric, 64)
	TransformToMetric(collector, listenerUuid, listener, metricCh)
	close(metricCh)

	metricCounts := make(map[string]int)
	for metric := range metricCh {
		desc := metric.Desc().String()
		for _, metricName := range []string{
			"zstack_lb_status",
			"zstack_lb_in_bytes",
			"zstack_lb_cur_session_num",
		} {
			if strings.Contains(desc, `fqName: "`+metricName+`"`) {
				metricCounts[metricName]++
			}
		}
	}

	if metricCounts["zstack_lb_status"] != 1 {
		t.Fatalf("expected only enabled backend health status, got %d metrics",
			metricCounts["zstack_lb_status"])
	}
	if metricCounts["zstack_lb_in_bytes"] != 2 {
		t.Fatalf("expected traffic metrics for both backends, got %d",
			metricCounts["zstack_lb_in_bytes"])
	}
	if metricCounts["zstack_lb_cur_session_num"] != 2 {
		t.Fatalf("expected session metrics for both backends, got %d",
			metricCounts["zstack_lb_cur_session_num"])
	}
}
