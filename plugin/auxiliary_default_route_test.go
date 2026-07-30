package plugin

import (
	"testing"

	"zstack-vyos/utils"
)

func TestRetainUnchangedDefaultRoutes(t *testing.T) {
	tests := []struct {
		name                string
		destination         string
		changeDefaultRoute  bool
		changeDefaultRoute6 bool
		wantRetained        bool
	}{
		{
			name:         "retain IPv4 default when omitted",
			destination:  "0.0.0.0/0",
			wantRetained: true,
		},
		{
			name:                "retain IPv6 default when omitted",
			destination:         "::/0",
			changeDefaultRoute:  true,
			changeDefaultRoute6: false,
			wantRetained:        true,
		},
		{
			name:               "replace IPv4 default when requested",
			destination:        "0.0.0.0/0",
			changeDefaultRoute: true,
			wantRetained:       false,
		},
		{
			name:                "replace IPv6 default when requested",
			destination:         "::/0",
			changeDefaultRoute6: true,
			wantRetained:        false,
		},
		{
			name:         "delete non-default route when omitted",
			destination:  "192.168.100.0/24",
			wantRetained: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			old := &utils.ZebraRoute{Dst: tt.destination}
			routes, retained := retainUnchangedDefaultRoute(nil, old, tt.changeDefaultRoute, tt.changeDefaultRoute6)
			if retained != tt.wantRetained {
				t.Fatalf("retainUnchangedDefaultRoute(%q, %t, %t) retained = %t, want %t", tt.destination, tt.changeDefaultRoute, tt.changeDefaultRoute6, retained, tt.wantRetained)
			}
			if retained && (len(routes) != 1 || routes[0] != old) {
				t.Fatalf("retained route must remain in persisted routes, got %#v", routes)
			}
			if !retained && len(routes) != 0 {
				t.Fatalf("unretained route must not be persisted, got %#v", routes)
			}
		})
	}
}
