package plugin

import (
	"strings"
	"testing"
)

func TestStrictTLSSecurityPolicies(t *testing.T) {
	const (
		strictTLS12Ciphers = "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384"
		tls13Ciphersuites  = "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256"
	)

	tests := []struct {
		name                  string
		policy                string
		wantTLS12Ciphers      string
		wantTLS13Ciphersuites string
		wantOptions           string
	}{
		{
			name:             "TLS 1.2 strict",
			policy:           TLS_CIPHER_POLICY_1_2_STRICT,
			wantTLS12Ciphers: strictTLS12Ciphers,
			wantOptions:      "no-sslv3 no-tlsv10 no-tlsv11 no-tlsv13 no-tls-tickets",
		},
		{
			name:                  "TLS 1.2 and 1.3 strict",
			policy:                TLS_CIPHER_POLICY_1_2_STRICT_WITH_1_3,
			wantTLS12Ciphers:      strictTLS12Ciphers,
			wantTLS13Ciphersuites: tls13Ciphersuites,
			wantOptions:           "no-sslv3 no-tlsv10 no-tlsv11 no-tls-tickets",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parameters, err := parseListenerPrameter(LbInfo{SecurityPolicyType: tt.policy})
			if err != nil {
				t.Fatalf("parse listener parameters: %v", err)
			}

			configuration, ok := parameters["SecurityOptions"].(string)
			if !ok {
				t.Fatalf("security options were not generated for policy %s", tt.policy)
			}

			assertHaproxyDirective(t, configuration, "ssl-default-bind-ciphers", tt.wantTLS12Ciphers)
			assertHaproxyDirective(t, configuration, "ssl-default-bind-ciphersuites", tt.wantTLS13Ciphersuites)
			assertHaproxyDirective(t, configuration, "ssl-default-bind-options", tt.wantOptions)
		})
	}
}

func assertHaproxyDirective(t *testing.T, configuration, directive, want string) {
	t.Helper()

	for _, line := range strings.Split(configuration, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != directive {
			continue
		}

		got := strings.Join(fields[1:], " ")
		if got != want {
			t.Fatalf("unexpected %s: got %q, want %q", directive, got, want)
		}
		return
	}

	if want != "" {
		t.Fatalf("missing %s", directive)
	}
}
