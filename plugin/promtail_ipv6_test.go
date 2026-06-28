package plugin

import "testing"

func TestBuildPromtailLokiURL(t *testing.T) {
	cases := map[string]string{
		"192.168.1.10": "http://192.168.1.10:3100/loki/api/v1/push",
		"2001:db8::10": "http://[2001:db8::10]:3100/loki/api/v1/push",
	}

	for logTarget, expected := range cases {
		if actual := buildPromtailLokiURL(logTarget); actual != expected {
			t.Fatalf("expect loki URL %s for %s, got %s", expected, logTarget, actual)
		}
	}
}
