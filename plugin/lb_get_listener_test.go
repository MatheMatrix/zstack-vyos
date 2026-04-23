package plugin

import "testing"

// TestGetListenerDispatch verifies the F-012 dispatch table:
// IpvsMode wins over Mode; "" + udp falls through to IPVS-fullnat.
func TestGetListenerDispatch(t *testing.T) {
	cases := []struct {
		name      string
		mode      string
		ipvsMode  string
		wantType  string
	}{
		{"dr-tcp", "tcp", IpvsModeDR, "*plugin.IpvsDRListener"},
		{"dr-udp", "udp", IpvsModeDR, "*plugin.IpvsDRListener"},
		{"fullnat-tcp", "tcp", IpvsModeFullNat, "*plugin.IpvsFullNatListener"},
		{"fullnat-udp", "udp", IpvsModeFullNat, "*plugin.IpvsFullNatListener"},
		{"legacy-udp", "udp", "", "*plugin.IpvsFullNatListener"},
		{"legacy-tcp", "tcp", "", "*plugin.HaproxyListener"},
		{"legacy-http", "http", "", "*plugin.HaproxyListener"},
		{"legacy-https", "https", "", "*plugin.HaproxyListener"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lb := LbInfo{
				LbUuid:           "lb-1",
				ListenerUuid:     "lr-1",
				Vip:              "1.1.1.1",
				Mode:             tc.mode,
				IpvsMode:         tc.ipvsMode,
				LoadBalancerPort: 80,
			}
			got := GetListener(lb)
			if got == nil {
				t.Fatalf("GetListener returned nil for %+v", tc)
			}
			gotType := typeName(got)
			if gotType != tc.wantType {
				t.Errorf("got %s, want %s", gotType, tc.wantType)
			}
		})
	}
}

func typeName(v interface{}) string {
	switch v.(type) {
	case *IpvsDRListener:
		return "*plugin.IpvsDRListener"
	case *IpvsFullNatListener:
		return "*plugin.IpvsFullNatListener"
	case *HaproxyListener:
		return "*plugin.HaproxyListener"
	case *GBListener:
		return "*plugin.GBListener"
	default:
		return "unknown"
	}
}
