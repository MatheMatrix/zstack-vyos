package checker

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"
)

func TestTCP(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen on TCP test port: %v", err)
	}

	host, port := splitHostPort(t, listener.Addr().String())
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	if err := TCP(ctx, host, port); err != nil {
		cancel()
		t.Fatalf("TCP health check should succeed while the port is listening: %v", err)
	}
	cancel()

	if err := listener.Close(); err != nil {
		t.Fatalf("close TCP test listener: %v", err)
	}
	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := TCP(ctx, host, port); err == nil {
		t.Fatal("TCP health check should fail after the listener is closed")
	}
}

func TestTCPIPv6(t *testing.T) {
	listener, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback is unavailable: %v", err)
	}
	defer listener.Close()

	host, port := splitHostPort(t, listener.Addr().String())
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := TCP(ctx, host, port); err != nil {
		t.Fatalf("IPv6 TCP health check should succeed: %v", err)
	}
}

func TestHTTP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/ok":
			response.WriteHeader(http.StatusNoContent)
		case "/redirect":
			http.Redirect(response, request, "/ok", http.StatusFound)
		case "/missing":
			response.WriteHeader(http.StatusNotFound)
		case "/fail":
			response.WriteHeader(http.StatusServiceUnavailable)
		case "/get":
			if request.Method != http.MethodGet {
				response.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			response.WriteHeader(http.StatusOK)
		case "/head":
			if request.Method != http.MethodHead {
				response.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			response.WriteHeader(http.StatusOK)
		default:
			response.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	host, port := splitServerURL(t, server.URL)
	tests := []struct {
		name                string
		method              string
		uri                 string
		expectedCodeClasses string
		want                bool
		wantStatus          int
	}{
		{name: "HEAD URI and 2xx", method: http.MethodHead, uri: "/head", expectedCodeClasses: "http_2xx", want: true, wantStatus: http.StatusOK},
		{name: "GET method", method: http.MethodGet, uri: "/get", expectedCodeClasses: "http_2xx", want: true, wantStatus: http.StatusOK},
		{name: "204 is 2xx", method: http.MethodHead, uri: "/ok", expectedCodeClasses: "http_2xx", want: true, wantStatus: http.StatusNoContent},
		{name: "302 rejected by 2xx", method: http.MethodHead, uri: "/redirect", expectedCodeClasses: "http_2xx", want: false, wantStatus: http.StatusFound},
		{name: "302 accepted by 2xx and 3xx", method: http.MethodHead, uri: "/redirect", expectedCodeClasses: "http_2xx,http_3xx", want: true, wantStatus: http.StatusFound},
		{name: "404 rejected by 2xx", method: http.MethodHead, uri: "/missing", expectedCodeClasses: "http_2xx", want: false, wantStatus: http.StatusNotFound},
		{name: "503 rejected by 2xx", method: http.MethodHead, uri: "/fail", expectedCodeClasses: "http_2xx", want: false, wantStatus: http.StatusServiceUnavailable},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()

			got, statusCode, err := HTTP(ctx, HTTPConfig{
				BackendIP:           host,
				Port:                port,
				Method:              test.method,
				URI:                 test.uri,
				ExpectedCodeClasses: test.expectedCodeClasses,
			})
			if err != nil {
				t.Fatalf("HTTP health check failed: %v", err)
			}
			if got != test.want || statusCode != test.wantStatus {
				t.Fatalf("HTTP health check = (%v, %d), want (%v, %d)",
					got, statusCode, test.want, test.wantStatus)
			}
		})
	}
}

func TestHTTPIPv6(t *testing.T) {
	listener, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback is unavailable: %v", err)
	}

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusNoContent)
	}))
	server.Listener = listener
	server.Start()
	defer server.Close()

	host, port := splitHostPort(t, listener.Addr().String())
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result, statusCode, err := HTTP(ctx, HTTPConfig{
		BackendIP:           host,
		Port:                port,
		Method:              http.MethodHead,
		URI:                 "/",
		ExpectedCodeClasses: "http_2xx",
	})
	if err != nil || !result || statusCode != http.StatusNoContent {
		t.Fatalf("IPv6 HTTP health check = (%v, %d, %v), want (true, 204, nil)",
			result, statusCode, err)
	}
}

func TestHTTPTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		time.Sleep(500 * time.Millisecond)
		response.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	host, port := splitServerURL(t, server.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	started := time.Now()
	result, _, err := HTTP(ctx, HTTPConfig{
		BackendIP:           host,
		Port:                port,
		Method:              http.MethodHead,
		URI:                 "/",
		ExpectedCodeClasses: "http_2xx",
	})
	if err == nil || result {
		t.Fatal("HTTP health check should fail when the response exceeds the timeout")
	}
	if elapsed := time.Since(started); elapsed >= 400*time.Millisecond {
		t.Fatalf("HTTP health check did not honor the context timeout: %s", elapsed)
	}
}

func TestHTTPS(t *testing.T) {
	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodHead || request.URL.Path != "/health" {
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		response.WriteHeader(http.StatusOK)
	}))
	defer tlsServer.Close()

	host, port := splitServerURL(t, tlsServer.URL)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	result, statusCode, err := HTTP(ctx, HTTPConfig{
		BackendIP:           host,
		Port:                port,
		Method:              http.MethodHead,
		URI:                 "/health",
		ExpectedCodeClasses: "http_2xx",
		TLS:                 true,
	})
	cancel()
	if err != nil || !result || statusCode != http.StatusOK {
		t.Fatalf("HTTPS health check = (%v, %d, %v), want (true, 200, nil)",
			result, statusCode, err)
	}

	plainServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusOK)
	}))
	defer plainServer.Close()

	host, port = splitServerURL(t, plainServer.URL)
	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result, _, err = HTTP(ctx, HTTPConfig{
		BackendIP:           host,
		Port:                port,
		Method:              http.MethodHead,
		URI:                 "/",
		ExpectedCodeClasses: "http_2xx",
		TLS:                 true,
	})
	if err == nil || result {
		t.Fatal("HTTPS health check should fail against a plain HTTP backend")
	}
}

func TestHTTPDefaultsAndValidation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodHead || request.URL.Path != "/" {
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		response.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	host, port := splitServerURL(t, server.URL)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	result, statusCode, err := HTTP(ctx, HTTPConfig{
		BackendIP: host,
		Port:      port,
	})
	cancel()
	if err != nil || !result || statusCode != http.StatusNoContent {
		t.Fatalf("default HTTP health check = (%v, %d, %v), want (true, 204, nil)",
			result, statusCode, err)
	}

	for _, config := range []HTTPConfig{
		{BackendIP: host, Port: port, Method: http.MethodPost, URI: "/"},
		{BackendIP: host, Port: port, Method: http.MethodHead, URI: "health"},
	} {
		ctx, cancel = context.WithTimeout(context.Background(), time.Second)
		_, _, err = HTTP(ctx, config)
		cancel()
		if err == nil {
			t.Fatalf("invalid HTTP health check config should fail: %+v", config)
		}
	}
}

func TestIsExpectedHTTPStatus(t *testing.T) {
	tests := []struct {
		statusCode          int
		expectedCodeClasses string
		want                bool
	}{
		{statusCode: http.StatusNoContent, expectedCodeClasses: "", want: true},
		{statusCode: http.StatusFound, expectedCodeClasses: "http_2xx", want: false},
		{statusCode: http.StatusFound, expectedCodeClasses: "http_2xx,http_3xx", want: true},
		{statusCode: http.StatusNotFound, expectedCodeClasses: "http_4xx", want: true},
		{statusCode: http.StatusServiceUnavailable, expectedCodeClasses: "http_5xx", want: true},
		{statusCode: http.StatusOK, expectedCodeClasses: "invalid", want: false},
	}

	for _, test := range tests {
		t.Run(strconv.Itoa(test.statusCode)+"/"+test.expectedCodeClasses, func(t *testing.T) {
			if got := IsExpectedHTTPStatus(test.statusCode, test.expectedCodeClasses); got != test.want {
				t.Fatalf("IsExpectedHTTPStatus(%d, %q) = %v, want %v",
					test.statusCode, test.expectedCodeClasses, got, test.want)
			}
		})
	}
}

func splitServerURL(t *testing.T, rawURL string) (string, int) {
	t.Helper()

	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse test server URL %q: %v", rawURL, err)
	}
	return splitHostPort(t, parsed.Host)
}

func splitHostPort(t *testing.T, address string) (string, int) {
	t.Helper()

	host, rawPort, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatalf("split address %q: %v", address, err)
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil {
		t.Fatalf("parse port %q from %q: %v", rawPort, address, err)
	}
	return host, port
}
