package plugin

import (
	"testing"

	"zstack-vyos/utils"
)

func TestIsProtectedSystemRoute(t *testing.T) {
	originalBootstrapInfo := utils.BootstrapInfo
	defer func() {
		utils.BootstrapInfo = originalBootstrapInfo
	}()

	utils.BootstrapInfo = map[string]interface{}{
		managementNodeCidrBootstrapKey: "172.24.0.0/16",
	}

	tests := []struct {
		name  string
		route RouteInfo
		want  bool
	}{
		{
			name: "keeps default route",
			route: RouteInfo{
				Destination: "0.0.0.0/0",
				Target:      "192.168.190.1",
			},
			want: true,
		},
		{
			name: "keeps management return route",
			route: RouteInfo{
				Destination: "172.24.0.0/16",
				Target:      "192.168.190.1",
			},
			want: true,
		},
		{
			name: "does not keep stale custom route",
			route: RouteInfo{
				Destination: "198.51.100.60/32",
				Target:      "192.168.190.1",
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isProtectedSystemRoute(tt.route); got != tt.want {
				t.Fatalf("expected %v, got %v", tt.want, got)
			}
		})
	}
}
