package plugin

import (
	"fmt"
	"strings"
	"testing"

	"zstack-vyos/utils"
)

func TestIpvsCommandBuildersUseTcpFullNatBackendPort(t *testing.T) {
	lb := LbInfo{
		LbUuid:           "lb",
		ListenerUuid:     "listener",
		Vip:              "172.24.7.153",
		LoadBalancerPort: 19086,
		InstancePort:     8080,
		Mode:             LB_MODE_TCP,
		DataPlane:        LB_DATA_PLANE_IPVS,
		ForwardMode:      LB_FORWARD_MODE_FULL_NAT,
		Parameters:       []string{"balancerAlgorithm::roundrobin"},
	}
	param := ParseLbParams(lb)
	fs := NewIpvsFrontService(lb, param, lb.Vip, map[string]*IpvsBackendServer{})
	bs := NewIpvsBackendServer("192.168.10.20", "8080", "100", fs)

	if got, want := makeIpvsAddServiceCommand(fs), "ipvsadm -A -t 172.24.7.153:19086 -s rr"; got != want {
		t.Fatalf("unexpected add service command:\nwant: %s\n got: %s", want, got)
	}
	if got, want := makeIpvsAddBackendCommand(bs), "ipvsadm -a -t 172.24.7.153:19086 -r 192.168.10.20:8080 -m -w 100 -x 0 -y 0"; got != want {
		t.Fatalf("unexpected add backend command:\nwant: %s\n got: %s", want, got)
	}
	if got, want := makeIpvsDeleteServiceCommand(fs), "ipvsadm -D -t 172.24.7.153:19086"; got != want {
		t.Fatalf("unexpected delete service command:\nwant: %s\n got: %s", want, got)
	}
}

func TestIpvsEnsureCommandsFallbackToEdit(t *testing.T) {
	lb := LbInfo{
		LbUuid:           "lb",
		ListenerUuid:     "listener",
		Vip:              "172.24.7.153",
		LoadBalancerPort: 19086,
		InstancePort:     8080,
		Mode:             LB_MODE_TCP,
		DataPlane:        LB_DATA_PLANE_IPVS,
		ForwardMode:      LB_FORWARD_MODE_FULL_NAT,
		Parameters:       []string{"balancerAlgorithm::roundrobin"},
	}
	fs := NewIpvsFrontService(lb, ParseLbParams(lb), lb.Vip, map[string]*IpvsBackendServer{})
	bs := NewIpvsBackendServer("192.168.10.20", "8080", "100", fs)

	if got, want := makeIpvsEnsureServiceCommand(fs), "ipvsadm -A -t 172.24.7.153:19086 -s rr || ipvsadm -E -t 172.24.7.153:19086 -s rr"; got != want {
		t.Fatalf("unexpected ensure service command:\nwant: %s\n got: %s", want, got)
	}
	if got, want := makeIpvsEnsureBackendCommand(bs), "ipvsadm -a -t 172.24.7.153:19086 -r 192.168.10.20:8080 -m -w 100 -x 0 -y 0 || ipvsadm -e -t 172.24.7.153:19086 -r 192.168.10.20:8080 -m -w 100 -x 0 -y 0"; got != want {
		t.Fatalf("unexpected ensure backend command:\nwant: %s\n got: %s", want, got)
	}
}

func TestUdpIpvsFullNatUsesMasqBackendPort(t *testing.T) {
	lb := LbInfo{
		LbUuid:           "lb-udp",
		ListenerUuid:     "listener-udp",
		Vip:              "172.24.7.153",
		LoadBalancerPort: 19095,
		InstancePort:     8080,
		Mode:             LB_MODE_UDP,
		DataPlane:        LB_DATA_PLANE_IPVS,
		ForwardMode:      LB_FORWARD_MODE_FULL_NAT,
		Parameters:       []string{"balancerAlgorithm::roundrobin"},
	}
	param := ParseLbParams(lb)
	fs := NewIpvsFrontService(lb, param, lb.Vip, map[string]*IpvsBackendServer{})
	bs := NewIpvsBackendServer("10.2.227.185", "8080", "100", fs)

	if fs.ProtocolType != "-u" {
		t.Fatalf("expected udp protocol, got %s", fs.ProtocolType)
	}
	if fs.ConnectionType != IpvsConnectionTypeNAT.String() {
		t.Fatalf("expected IPVS Masq/NAT connection, got %s", fs.ConnectionType)
	}
	if got, want := makeIpvsAddServiceCommand(fs), "ipvsadm -A -u 172.24.7.153:19095 -s rr"; got != want {
		t.Fatalf("unexpected udp add service command:\nwant: %s\n got: %s", want, got)
	}
	if got, want := makeIpvsAddBackendCommand(bs), "ipvsadm -a -u 172.24.7.153:19095 -r 10.2.227.185:8080 -m -w 100 -x 0 -y 0"; got != want {
		t.Fatalf("unexpected udp backend command:\nwant: %s\n got: %s", want, got)
	}
}

func TestTcpIpvsFullNatUsesSharedVRouterMasqSemantics(t *testing.T) {
	lb := LbInfo{
		LbUuid:           "lb-shared",
		ListenerUuid:     "listener-shared",
		Vip:              "172.24.7.153",
		LoadBalancerPort: 19094,
		InstancePort:     8080,
		Mode:             LB_MODE_TCP,
		DataPlane:        LB_DATA_PLANE_IPVS,
		ForwardMode:      LB_FORWARD_MODE_FULL_NAT,
		NicIps:           []string{"10.2.226.104"},
		Parameters:       []string{"balancerAlgorithm::roundrobin"},
		ServerGroups: []ServerGroupInfo{{
			Name:            "default-server-group",
			ServerGroupUuid: "sg",
			BackendServers:  []BackendServerInfo{{Ip: "10.2.226.104", Weight: 100}},
		}},
	}

	param := ParseLbParams(lb)
	fs := NewIpvsFrontService(lb, param, lb.Vip, map[string]*IpvsBackendServer{})
	bs := NewIpvsBackendServer("10.2.226.104", "8080", "100", fs)
	fs.BackendServers[bs.GetBackendKey()] = bs

	if fs.ProtocolType != "-t" {
		t.Fatalf("expected tcp protocol, got %s", fs.ProtocolType)
	}
	if fs.ConnectionType != IpvsConnectionTypeNAT.String() {
		t.Fatalf("expected IPVS Masq/NAT connection, got %s", fs.ConnectionType)
	}
	if got, want := makeIpvsAddBackendCommand(bs), "ipvsadm -a -t 172.24.7.153:19094 -r 10.2.226.104:8080 -m -w 100 -x 0 -y 0"; got != want {
		t.Fatalf("unexpected shared tcp ipvs backend command:\nwant: %s\n got: %s", want, got)
	}
}

func TestTcpIpvsEmptyNicIpsRefreshRemovesOnlyTargetListener(t *testing.T) {
	current := map[string]map[string]LbInfo{
		"lb-shared": {
			"listener-remove": {
				LbUuid:           "lb-shared",
				ListenerUuid:     "listener-remove",
				Mode:             LB_MODE_TCP,
				DataPlane:        LB_DATA_PLANE_IPVS,
				ForwardMode:      LB_FORWARD_MODE_FULL_NAT,
				NicIps:           []string{"10.2.226.104"},
				ServerGroups:     []ServerGroupInfo{{BackendServers: []BackendServerInfo{{Ip: "10.2.226.104", Weight: 100}}}},
				InstancePort:     8080,
				PublicNic:        "fa:00:00:00:00:01",
				LoadBalancerPort: 19094,
			},
			"listener-keep": {
				LbUuid:           "lb-shared",
				ListenerUuid:     "listener-keep",
				Mode:             LB_MODE_TCP,
				DataPlane:        LB_DATA_PLANE_IPVS,
				ForwardMode:      LB_FORWARD_MODE_FULL_NAT,
				NicIps:           []string{"10.2.226.105"},
				ServerGroups:     []ServerGroupInfo{{BackendServers: []BackendServerInfo{{Ip: "10.2.226.105", Weight: 100}}}},
				InstancePort:     8081,
				PublicNic:        "fa:00:00:00:00:01",
				LoadBalancerPort: 19095,
			},
		},
	}
	updates := map[string]LbInfo{
		"listener-remove": {
			LbUuid:       "lb-shared",
			ListenerUuid: "listener-remove",
			Mode:         LB_MODE_TCP,
			DataPlane:    LB_DATA_PLANE_IPVS,
			ForwardMode:  LB_FORWARD_MODE_FULL_NAT,
			NicIps:       []string{},
		},
	}

	merged := mergeIpvsServiceUpdates(current, updates)
	if _, ok := merged["lb-shared"]["listener-remove"]; ok {
		t.Fatal("expected empty nicIps update to remove only the target listener")
	}
	if got := merged["lb-shared"]["listener-keep"].ListenerUuid; got != "listener-keep" {
		t.Fatalf("expected sibling listener to be preserved, got %s", got)
	}
}

func TestUdpIpvsEmptyNicIpsRefreshRemovesOnlyTargetListener(t *testing.T) {
	current := map[string]map[string]LbInfo{
		"lb-shared": {
			"listener-remove": {
				LbUuid:           "lb-shared",
				ListenerUuid:     "listener-remove",
				Mode:             LB_MODE_UDP,
				DataPlane:        LB_DATA_PLANE_IPVS,
				ForwardMode:      LB_FORWARD_MODE_FULL_NAT,
				NicIps:           []string{"10.2.227.185"},
				ServerGroups:     []ServerGroupInfo{{BackendServers: []BackendServerInfo{{Ip: "10.2.227.185", Weight: 100}}}},
				InstancePort:     8080,
				PublicNic:        "fa:00:00:00:00:01",
				LoadBalancerPort: 19095,
			},
			"listener-keep": {
				LbUuid:           "lb-shared",
				ListenerUuid:     "listener-keep",
				Mode:             LB_MODE_UDP,
				DataPlane:        LB_DATA_PLANE_IPVS,
				ForwardMode:      LB_FORWARD_MODE_FULL_NAT,
				NicIps:           []string{"10.2.227.186"},
				ServerGroups:     []ServerGroupInfo{{BackendServers: []BackendServerInfo{{Ip: "10.2.227.186", Weight: 100}}}},
				InstancePort:     8081,
				PublicNic:        "fa:00:00:00:00:01",
				LoadBalancerPort: 19096,
			},
		},
	}
	updates := map[string]LbInfo{
		"listener-remove": {
			LbUuid:       "lb-shared",
			ListenerUuid: "listener-remove",
			Mode:         LB_MODE_UDP,
			DataPlane:    LB_DATA_PLANE_IPVS,
			ForwardMode:  LB_FORWARD_MODE_FULL_NAT,
			NicIps:       []string{},
		},
	}

	merged := mergeIpvsServiceUpdates(current, updates)
	if _, ok := merged["lb-shared"]["listener-remove"]; ok {
		t.Fatal("expected empty nicIps update to remove only the target listener")
	}
	if got := merged["lb-shared"]["listener-keep"].ListenerUuid; got != "listener-keep" {
		t.Fatalf("expected sibling listener to be preserved, got %s", got)
	}
}

func TestTcpIpvsListenerIsRoutedToIpvsDataPlane(t *testing.T) {
	lb := LbInfo{
		Mode:        LB_MODE_TCP,
		DataPlane:   LB_DATA_PLANE_IPVS,
		ForwardMode: LB_FORWARD_MODE_FULL_NAT,
	}

	if !isIpvsListener(lb) {
		t.Fatal("expected tcp ipvs full_nat listener to use ipvs path")
	}

	lb.DataPlane = ""
	lb.ForwardMode = ""
	if isIpvsListener(lb) {
		t.Fatal("expected default tcp listener to stay on haproxy path")
	}
}

func TestIpvsCommandBuildersQuoteIPv6Address(t *testing.T) {
	lb := LbInfo{
		LbUuid:           "lb",
		ListenerUuid:     "listener",
		Vip6:             "2001:db8::10",
		LoadBalancerPort: 19086,
		Mode:             LB_MODE_TCP,
		DataPlane:        LB_DATA_PLANE_IPVS,
		ForwardMode:      LB_FORWARD_MODE_FULL_NAT,
		Parameters:       []string{"balancerAlgorithm::rr"},
	}
	param := ParseLbParams(lb)
	fs := NewIpvsFrontService(lb, param, lb.Vip6, map[string]*IpvsBackendServer{})
	bs := NewIpvsBackendServer("2001:db8::20", "8080", "1", fs)

	if got, want := makeIpvsAddServiceCommand(fs), "ipvsadm -A -t [2001:db8::10]:19086 -s rr"; got != want {
		t.Fatalf("unexpected ipv6 add service command:\nwant: %s\n got: %s", want, got)
	}
	if got, want := makeIpvsDeleteBackendCommand(bs), "ipvsadm -d -t [2001:db8::10]:19086 -r [2001:db8::20]:8080"; got != want {
		t.Fatalf("unexpected ipv6 delete backend command:\nwant: %s\n got: %s", want, got)
	}
}

func TestIpvsCommandBuildersRejectInvalidAddress(t *testing.T) {
	lb := LbInfo{
		Vip:              "172.24.7.153;touch /tmp/pwned",
		LoadBalancerPort: 19086,
		Mode:             LB_MODE_TCP,
		DataPlane:        LB_DATA_PLANE_IPVS,
		ForwardMode:      LB_FORWARD_MODE_FULL_NAT,
	}
	param := ParseLbParams(lb)
	fs := NewIpvsFrontService(lb, param, lb.Vip, map[string]*IpvsBackendServer{})

	if err := validateIpvsFrontendService(fs); err == nil {
		t.Fatal("expected invalid frontend address to be rejected")
	}
}

func TestSameIpvsBackendComparesConnectionLimits(t *testing.T) {
	current := &IpvsBackendServer{
		ConnectionType: "-m",
		Weight:         "100",
		IpvsFrontendService: &IpvsFrontendService{
			LbParams: LbParams{
				maxConnection: 10,
				minConnection: 1,
			},
		},
	}
	desired := &IpvsBackendServer{
		ConnectionType: "-m",
		Weight:         "100",
		IpvsFrontendService: &IpvsFrontendService{
			LbParams: LbParams{
				maxConnection: 20,
				minConnection: 1,
			},
		},
	}

	if sameIpvsBackend(current, desired) {
		t.Fatal("expected maxConnection change to require backend edit")
	}
}

func TestParseIpvsKeepsBackendConnectionLimits(t *testing.T) {
	conf := &IpvsConf{}
	err := conf.ParseIpvs(`
-A -t 172.24.7.153:19086 -s rr
-a -t 172.24.7.153:19086 -r 192.168.10.20:8080 -m -w 100 -x 20 -y 3
`)
	if err != nil {
		t.Fatal(err)
	}

	service := conf.Services["-t-172.24.7.153-19086"]
	if service == nil {
		t.Fatal("expected parsed service")
	}
	backend := service.BackendServers["tcp-172.24.7.153-19086-192.168.10.20-8080"]
	if backend == nil {
		t.Fatal("expected parsed backend")
	}
	if backend.maxConnection != 20 || backend.minConnection != 3 {
		t.Fatalf("unexpected connection limits: max=%d min=%d", backend.maxConnection, backend.minConnection)
	}
}

func TestIpvsConnectionTypeFollowsForwardMode(t *testing.T) {
	if got := getIpvsConnectionTypeFromForwardMode(LB_FORWARD_MODE_FULL_NAT); got != IpvsConnectionTypeNAT {
		t.Fatalf("unexpected full_nat connection type: %s", got.String())
	}
	if got := getIpvsConnectionTypeFromForwardMode(LB_FORWARD_MODE_NAT); got != IpvsConnectionTypeNAT {
		t.Fatalf("unexpected nat connection type: %s", got.String())
	}
	if got := getIpvsConnectionTypeFromForwardMode(LB_FORWARD_MODE_DR); got != IpvsConnectionTypeDR {
		t.Fatalf("unexpected dr connection type: %s", got.String())
	}
}

func TestTcpIpvsNatAndDrCommandBuilders(t *testing.T) {
	cases := []struct {
		name        string
		forwardMode string
		connection  string
	}{
		{name: "nat", forwardMode: LB_FORWARD_MODE_NAT, connection: "-m"},
		{name: "dr", forwardMode: LB_FORWARD_MODE_DR, connection: "-g"},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			lb := LbInfo{
				LbUuid:           "lb",
				ListenerUuid:     "listener-" + tt.name,
				Vip:              "172.24.7.153",
				LoadBalancerPort: 19086,
				InstancePort:     8080,
				Mode:             LB_MODE_TCP,
				DataPlane:        LB_DATA_PLANE_IPVS,
				ForwardMode:      tt.forwardMode,
				Parameters:       []string{"balancerAlgorithm::roundrobin"},
			}
			param := ParseLbParams(lb)
			fs := NewIpvsFrontService(lb, param, lb.Vip, map[string]*IpvsBackendServer{})
			bs := NewIpvsBackendServer("192.168.10.20", "8080", "100", fs)

			if fs.ConnectionType != tt.connection {
				t.Fatalf("unexpected connection type: want %s got %s", tt.connection, fs.ConnectionType)
			}
			want := fmt.Sprintf("ipvsadm -a -t 172.24.7.153:19086 -r 192.168.10.20:8080 %s -w 100 -x 0 -y 0", tt.connection)
			if got := makeIpvsAddBackendCommand(bs); got != want {
				t.Fatalf("unexpected add backend command:\nwant: %s\n got: %s", want, got)
			}
		})
	}
}

func TestIpvsFullNatSnatRulesSkipNatAndDrModes(t *testing.T) {
	services := map[string]*IpvsFrontendService{}

	for _, mode := range []string{LB_FORWARD_MODE_NAT, LB_FORWARD_MODE_DR} {
		lb := LbInfo{
			LbUuid:           "lb",
			ListenerUuid:     "listener-" + mode,
			Vip:              "172.24.7.153",
			LoadBalancerPort: 19086,
			InstancePort:     8080,
			Mode:             LB_MODE_TCP,
			DataPlane:        LB_DATA_PLANE_IPVS,
			ForwardMode:      mode,
			Parameters:       []string{"balancerAlgorithm::roundrobin"},
		}
		fs := NewIpvsFrontService(lb, ParseLbParams(lb), lb.Vip, map[string]*IpvsBackendServer{})
		bs := NewIpvsBackendServer("192.168.10.20", "8080", "100", fs)
		fs.BackendServers[bs.GetBackendKey()] = bs
		services[mode] = fs
	}

	if rules := makeIpvsFullNatSnatRules(services); len(rules) != 0 {
		t.Fatalf("expected nat/dr modes to skip full_nat snat rules, got %d", len(rules))
	}
}

func TestVyosSlbRejectsTcpIpvsServices(t *testing.T) {
	oldBootstrapInfo := utils.BootstrapInfo
	utils.BootstrapInfo = map[string]interface{}{
		"applianceVmSubType": utils.APPLIANCETYPE_SLB,
	}
	defer func() {
		utils.BootstrapInfo = oldBootstrapInfo
	}()

	lb := LbInfo{
		LbUuid:       "lb-slb",
		ListenerUuid: "listener-tcp-ipvs",
		Mode:         LB_MODE_TCP,
		DataPlane:    LB_DATA_PLANE_IPVS,
		ForwardMode:  LB_FORWARD_MODE_FULL_NAT,
	}
	err := validateIpvsServicesSupportedByAppliance(map[string]LbInfo{lb.ListenerUuid: lb})
	if err == nil {
		t.Fatal("expected vyos slb tcp ipvs listener to be rejected")
	}
	if !strings.Contains(err.Error(), "vyos slb doesn't support tcp ipvs listener listener-tcp-ipvs") {
		t.Fatalf("unexpected error: %v", err)
	}

	lb.Mode = LB_MODE_UDP
	if err := validateIpvsServicesSupportedByAppliance(map[string]LbInfo{lb.ListenerUuid: lb}); err != nil {
		t.Fatalf("expected udp ipvs listener to stay supported on slb, got %v", err)
	}
}

func TestIpvsFullNatSnatRulesKeepUdpCompatibility(t *testing.T) {
	cases := []struct {
		name        string
		mode        string
		forwardMode string
		want        bool
	}{
		{name: "tcp-full-nat", mode: LB_MODE_TCP, forwardMode: LB_FORWARD_MODE_FULL_NAT, want: true},
		{name: "tcp-nat", mode: LB_MODE_TCP, forwardMode: LB_FORWARD_MODE_NAT, want: false},
		{name: "tcp-dr", mode: LB_MODE_TCP, forwardMode: LB_FORWARD_MODE_DR, want: false},
		{name: "udp-without-forward-mode", mode: LB_MODE_UDP, forwardMode: "", want: true},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			lb := LbInfo{
				LbUuid:           "lb",
				ListenerUuid:     "listener-" + tt.name,
				Vip:              "172.24.7.153",
				LoadBalancerPort: 19086,
				InstancePort:     8080,
				Mode:             tt.mode,
				DataPlane:        LB_DATA_PLANE_IPVS,
				ForwardMode:      tt.forwardMode,
				Parameters:       []string{"balancerAlgorithm::roundrobin"},
			}
			fs := NewIpvsFrontService(lb, ParseLbParams(lb), lb.Vip, map[string]*IpvsBackendServer{})
			if got := shouldInstallIpvsFullNatSnat(fs); got != tt.want {
				t.Fatalf("unexpected full_nat snat decision: want %t got %t", tt.want, got)
			}
		})
	}
}

func TestIpvsNatAndDrInstallPrivateNicSnatBypassRules(t *testing.T) {
	cases := []struct {
		name        string
		forwardMode string
		wantDst     string
		wantDport   string
	}{
		{name: "nat", forwardMode: LB_FORWARD_MODE_NAT, wantDst: "192.168.10.20/32", wantDport: "8080"},
		{name: "dr", forwardMode: LB_FORWARD_MODE_DR, wantDst: "172.24.7.153/32", wantDport: "19086"},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			lb := LbInfo{
				LbUuid:           "lb",
				ListenerUuid:     "listener-" + tt.forwardMode,
				Vip:              "172.24.7.153",
				LoadBalancerPort: 19086,
				InstancePort:     8080,
				Mode:             LB_MODE_TCP,
				DataPlane:        LB_DATA_PLANE_IPVS,
				ForwardMode:      tt.forwardMode,
				Parameters:       []string{"balancerAlgorithm::roundrobin"},
			}
			fs := NewIpvsFrontService(lb, ParseLbParams(lb), lb.Vip, map[string]*IpvsBackendServer{})
			bs := NewIpvsBackendServer("192.168.10.20", "8080", "100", fs)
			fs.BackendServers[bs.GetBackendKey()] = bs

			rules := makeIpvsPrivateNicSnatBypassRules(map[string]*IpvsFrontendService{tt.name: fs})
			if len(rules) != 1 {
				t.Fatalf("expected %s mode to install one private-nic snat bypass rule, got %d", tt.name, len(rules))
			}

			ruleText := rules[0].String()
			for _, want := range []string{
				"-A POSTROUTING",
				"-m ipvs --ipvs --vaddr 172.24.7.153 --vport  19086",
				"-d " + tt.wantDst,
				"-p tcp -m tcp --dport " + tt.wantDport,
				"-m comment --comment \"ipvs-rule@POSTROUTING\"",
				"-j ACCEPT",
			} {
				if !strings.Contains(ruleText, want) {
					t.Fatalf("expected bypass rule to contain %q, got %s", want, ruleText)
				}
			}
			if strings.Contains(ruleText, "SNAT") {
				t.Fatalf("bypass rule must not snat packets: %s", ruleText)
			}
		})
	}
}

func TestIpvsPrivateNicSnatBypassRulesSkipIPv6Vip(t *testing.T) {
	for _, forwardMode := range []string{LB_FORWARD_MODE_NAT, LB_FORWARD_MODE_DR} {
		t.Run(forwardMode, func(t *testing.T) {
			lb := LbInfo{
				LbUuid:           "lb",
				ListenerUuid:     "listener-" + forwardMode + "-ipv6",
				Vip6:             "2001:db8::10",
				LoadBalancerPort: 19086,
				InstancePort:     8080,
				Mode:             LB_MODE_TCP,
				DataPlane:        LB_DATA_PLANE_IPVS,
				ForwardMode:      forwardMode,
				Parameters:       []string{"balancerAlgorithm::roundrobin"},
			}
			fs := NewIpvsFrontService(lb, ParseLbParams(lb), lb.Vip6, map[string]*IpvsBackendServer{})
			bs := NewIpvsBackendServer("192.168.10.20", "8080", "100", fs)
			fs.BackendServers[bs.GetBackendKey()] = bs

			rules := makeIpvsPrivateNicSnatBypassRules(map[string]*IpvsFrontendService{forwardMode + "-ipv6": fs})
			if len(rules) != 0 {
				for _, rule := range rules {
					t.Log(rule.String())
				}
				t.Fatalf("expected ipv6 %s vip to skip ipv4 iptables bypass rules, got %d", forwardMode, len(rules))
			}
		})
	}
}

func TestIpvsFullNatSnatRulesSkipIPv6Vip(t *testing.T) {
	lb := LbInfo{
		LbUuid:           "lb",
		ListenerUuid:     "listener-full-nat-ipv6",
		Vip6:             "2001:db8::10",
		LoadBalancerPort: 19086,
		InstancePort:     8080,
		Mode:             LB_MODE_TCP,
		DataPlane:        LB_DATA_PLANE_IPVS,
		ForwardMode:      LB_FORWARD_MODE_FULL_NAT,
		Parameters:       []string{"balancerAlgorithm::roundrobin"},
	}
	fs := NewIpvsFrontService(lb, ParseLbParams(lb), lb.Vip6, map[string]*IpvsBackendServer{})
	bs := NewIpvsBackendServer("192.168.10.20", "8080", "100", fs)
	fs.BackendServers[bs.GetBackendKey()] = bs

	rules := makeIpvsFullNatSnatRules(map[string]*IpvsFrontendService{"full-nat-ipv6": fs})
	if len(rules) != 0 {
		for _, rule := range rules {
			t.Log(rule.String())
		}
		t.Fatalf("expected ipv6 full_nat vip to skip ipv4 iptables snat rules, got %d", len(rules))
	}
}

func TestIpvsPrivateNicSnatBypassRulesSkipFullNatAndUdp(t *testing.T) {
	cases := []struct {
		name        string
		mode        string
		forwardMode string
	}{
		{name: "tcp-full-nat", mode: LB_MODE_TCP, forwardMode: LB_FORWARD_MODE_FULL_NAT},
		{name: "udp-without-forward-mode", mode: LB_MODE_UDP},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			lb := LbInfo{
				LbUuid:           "lb",
				ListenerUuid:     "listener-" + tt.name,
				Vip:              "172.24.7.153",
				LoadBalancerPort: 19086,
				InstancePort:     8080,
				Mode:             tt.mode,
				DataPlane:        LB_DATA_PLANE_IPVS,
				ForwardMode:      tt.forwardMode,
				Parameters:       []string{"balancerAlgorithm::roundrobin"},
			}
			fs := NewIpvsFrontService(lb, ParseLbParams(lb), lb.Vip, map[string]*IpvsBackendServer{})
			bs := NewIpvsBackendServer("192.168.10.20", "8080", "100", fs)
			fs.BackendServers[bs.GetBackendKey()] = bs

			if rules := makeIpvsPrivateNicSnatBypassRules(map[string]*IpvsFrontendService{tt.name: fs}); len(rules) != 0 {
				t.Fatalf("expected %s to skip private-nic snat bypass rules, got %d", tt.name, len(rules))
			}
		})
	}
}

func TestIpvsNatAndDrBypassRulesOnlyApplyToSharedVRouter(t *testing.T) {
	lb := LbInfo{
		LbUuid:           "lb",
		ListenerUuid:     "listener-nat",
		Vip:              "172.24.7.153",
		LoadBalancerPort: 19086,
		InstancePort:     8080,
		Mode:             LB_MODE_TCP,
		DataPlane:        LB_DATA_PLANE_IPVS,
		ForwardMode:      LB_FORWARD_MODE_NAT,
		Parameters:       []string{"balancerAlgorithm::roundrobin"},
	}
	fs := NewIpvsFrontService(lb, ParseLbParams(lb), lb.Vip, map[string]*IpvsBackendServer{})
	bs := NewIpvsBackendServer("192.168.10.20", "8080", "100", fs)
	fs.BackendServers[bs.GetBackendKey()] = bs
	services := map[string]*IpvsFrontendService{"nat": fs}

	sharedRules := makeIpvsNatRulesForAppliance(services, false)
	if len(sharedRules) != 1 || !strings.Contains(sharedRules[0].String(), "-j ACCEPT") {
		t.Fatalf("expected shared vrouter to install one nat/dr bypass rule, got %#v", sharedRules)
	}

	slbRules := makeIpvsNatRulesForAppliance(services, true)
	if len(slbRules) != 0 {
		for _, rule := range slbRules {
			t.Log(rule.String())
		}
		t.Fatalf("expected separate SLB nat/dr path to skip private-nic snat bypass, got %d rules", len(slbRules))
	}
}

func TestParseIpvsAclConfigKeepsIPv6Entries(t *testing.T) {
	aclType, entries, enabled := parseIpvsAclConfig([]string{
		"accessControlStatus::enable",
		"aclType::white",
		"aclEntry::2001:db8::1/128, 192.168.10.0/24",
	})

	if !enabled {
		t.Fatal("expected acl to be enabled")
	}
	if aclType != "white" {
		t.Fatalf("unexpected acl type: %s", aclType)
	}
	if len(entries) != 2 || entries[0] != "2001:db8::1/128" || entries[1] != "192.168.10.0/24" {
		t.Fatalf("unexpected acl entries: %#v", entries)
	}
}

func TestIpvsFullNatSnatRulesMatchFrontendService(t *testing.T) {
	lb := LbInfo{
		LbUuid:           "lb",
		ListenerUuid:     "listener-full-nat",
		Vip:              "172.24.7.153",
		LoadBalancerPort: 19086,
		InstancePort:     8080,
		Mode:             LB_MODE_TCP,
		DataPlane:        LB_DATA_PLANE_IPVS,
		ForwardMode:      LB_FORWARD_MODE_FULL_NAT,
		Parameters:       []string{"balancerAlgorithm::roundrobin"},
	}
	fs := NewIpvsFrontService(lb, ParseLbParams(lb), lb.Vip, map[string]*IpvsBackendServer{})
	bs := NewIpvsBackendServer("192.168.10.20", "8080", "100", fs)
	fs.BackendServers[bs.GetBackendKey()] = bs

	rule := makeIpvsFullNatSnatRule(fs, bs, utils.IPTABLES_PROTO_TCP, "192.168.10.1")
	if !rule.GetIpvs() || rule.GetIpvsVaddr() != lb.Vip || rule.GetIpvsVport() != "19086" {
		t.Fatalf("full_nat snat rule must be scoped to frontend service: %s", rule.String())
	}
}

func TestIpvsFullLogRulesFollowListenerFullLogFlag(t *testing.T) {
	oldEnableLog := gEnableLog
	defer func() {
		gEnableLog = oldEnableLog
	}()

	logged := LbInfo{
		LbUuid:           "lb",
		ListenerUuid:     "listener-logged",
		Vip:              "172.24.7.153",
		LoadBalancerPort: 19086,
		Mode:             LB_MODE_TCP,
		DataPlane:        LB_DATA_PLANE_IPVS,
		ForwardMode:      LB_FORWARD_MODE_FULL_NAT,
		EnableFullLog:    true,
	}
	notLogged := LbInfo{
		LbUuid:           "lb",
		ListenerUuid:     "listener-not-logged",
		Vip:              "172.24.7.154",
		LoadBalancerPort: 19087,
		Mode:             LB_MODE_TCP,
		DataPlane:        LB_DATA_PLANE_IPVS,
		ForwardMode:      LB_FORWARD_MODE_FULL_NAT,
		EnableFullLog:    false,
	}

	gEnableLog = true
	rules := makeIpvsFullLogRules(map[string]*IpvsFrontendService{
		"logged":    NewIpvsFrontService(logged, ParseLbParams(logged), logged.Vip, map[string]*IpvsBackendServer{}),
		"notLogged": NewIpvsFrontService(notLogged, ParseLbParams(notLogged), notLogged.Vip, map[string]*IpvsBackendServer{}),
	})
	if len(rules) != 1 {
		t.Fatalf("expected only one ipvs full log rule, got %d", len(rules))
	}

	rule := rules[0]
	if !rule.GetIpvs() || rule.GetIpvsVaddr() != "172.24.7.153" || rule.GetIpvsVport() != "19086" {
		t.Fatalf("unexpected ipvs full log matcher: %s", rule.String())
	}
	if rule.GetAction() != "LOG" {
		t.Fatalf("unexpected ipvs full log target: %s", rule.String())
	}

	gEnableLog = false
	if rules := makeIpvsFullLogRules(map[string]*IpvsFrontendService{
		"logged": NewIpvsFrontService(logged, ParseLbParams(logged), logged.Vip, map[string]*IpvsBackendServer{}),
	}); len(rules) != 0 {
		t.Fatalf("expected global log switch to suppress ipvs full log rules, got %d", len(rules))
	}
}

func TestTcpIpvsCountersUseTcpKeyAndKeepDesiredMissingActualDown(t *testing.T) {
	oldConf := gIpvsConf
	defer func() {
		gIpvsConf = oldConf
	}()

	lb := LbInfo{
		LbUuid:           "lb",
		ListenerUuid:     "listener",
		Vip:              "172.24.7.153",
		LoadBalancerPort: 19086,
		InstancePort:     8080,
		Mode:             LB_MODE_TCP,
		DataPlane:        LB_DATA_PLANE_IPVS,
		ForwardMode:      LB_FORWARD_MODE_FULL_NAT,
		ServerGroups: []ServerGroupInfo{
			{
				ServerGroupUuid: "sg",
				BackendServers: []BackendServerInfo{
					{Ip: "192.168.10.20", Weight: 100},
					{Ip: "192.168.10.21", Weight: 100},
				},
			},
		},
	}
	param := ParseLbParams(lb)
	fs := NewIpvsFrontService(lb, param, lb.Vip, map[string]*IpvsBackendServer{})
	upBackend := NewIpvsBackendServer("192.168.10.20", "8080", "100", fs)
	downBackend := NewIpvsBackendServer("192.168.10.21", "8080", "100", fs)
	fs.BackendServers[upBackend.GetBackendKey()] = upBackend
	fs.BackendServers[downBackend.GetBackendKey()] = downBackend
	gIpvsConf = &IpvsConf{Services: map[string]*IpvsFrontendService{
		fs.getFrontendServiceKey(): fs,
	}}

	resetIpvsCounters()
	updateIpvsCountersFromStats(`
IP Virtual Server version 1.2.1 (size=4096)
Prot LocalAddress:Port               Conns   InPkts  OutPkts  InBytes OutBytes
  -> RemoteAddress:Port
TCP  172.24.7.153:19086                  0        0        0        0        0
  -> 192.168.10.20:8080                  0        0        0      123      456
`)
	updateIpvsCountersFromThresholds(`
IP Virtual Server version 1.2.1 (size=4096)
Prot LocalAddress:Port            Uthreshold Lthreshold ActiveConn InActConn
  -> RemoteAddress:Port
TCP  172.24.7.153:19086 rr
  -> 192.168.10.20:8080             0          0          7          2
`)

	if upBackend.Counter.Status != 1 {
		t.Fatalf("expected actual TCP backend to be up, got %d", upBackend.Counter.Status)
	}
	if upBackend.Counter.bytesIn != 123 || upBackend.Counter.bytesOut != 456 {
		t.Fatalf("unexpected traffic counters: in=%d out=%d", upBackend.Counter.bytesIn, upBackend.Counter.bytesOut)
	}
	if upBackend.Counter.sessionNumber != 7 || upBackend.Counter.refusedSessionNumber != 2 || upBackend.Counter.totalSessionNumber != 9 {
		t.Fatalf("unexpected session counters: active=%d refused=%d total=%d",
			upBackend.Counter.sessionNumber, upBackend.Counter.refusedSessionNumber, upBackend.Counter.totalSessionNumber)
	}
	if downBackend.Counter.Status != 0 {
		t.Fatalf("expected desired backend missing from actual IPVS to stay down, got %d", downBackend.Counter.Status)
	}

	resetIpvsCounters()
	updateIpvsCountersFromStats(`
IP Virtual Server version 1.2.1 (size=4096)
Prot LocalAddress:Port               Conns   InPkts  OutPkts  InBytes OutBytes
  -> RemoteAddress:Port
TCP  172.24.7.153:19086                  0        0        0        0        0
`)
	if upBackend.Counter.Status != 0 {
		t.Fatalf("expected missing TCP backend to be reset down, got %d", upBackend.Counter.Status)
	}
	if upBackend.Counter.bytesIn != 0 || upBackend.Counter.bytesOut != 0 ||
		upBackend.Counter.sessionNumber != 0 || upBackend.Counter.refusedSessionNumber != 0 ||
		upBackend.Counter.totalSessionNumber != 0 || upBackend.Counter.concurrentSessionNumber != 0 {
		t.Fatalf("expected missing TCP backend counters to reset, got %+v", upBackend.Counter)
	}

	resetIpvsCounters()
	updateIpvsCountersFromThresholds(`
IP Virtual Server version 1.2.1 (size=4096)
Prot LocalAddress:Port            Uthreshold Lthreshold ActiveConn InActConn
  -> RemoteAddress:Port
TCP  172.24.7.153:19086 rr
  -> 192.168.10.20:8080             0          0          3          1
`)
	if upBackend.Counter.Status != 1 {
		t.Fatalf("expected thresholds parser to mark actual TCP backend up, got %d", upBackend.Counter.Status)
	}
}

func TestLbSessionMetricsExposeServerGroupUuidLabel(t *testing.T) {
	collector := NewLbPrometheusCollector().(*loadBalancerCollector)
	for name, desc := range map[string]string{
		"cur":        fmt.Sprint(collector.curSessionNumEntry),
		"refused":    fmt.Sprint(collector.refusedSessionNumEntry),
		"total":      fmt.Sprint(collector.totalSessionNumEntry),
		"concurrent": fmt.Sprint(collector.concurrentSessionUsageEntry),
	} {
		if !strings.Contains(desc, LB_ServerGroup_UUID) {
			t.Fatalf("expected %s session metric to expose %s label: %s", name, LB_ServerGroup_UUID, desc)
		}
	}
}
