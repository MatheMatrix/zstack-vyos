package checker

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
)

type HTTPConfig struct {
	BackendIP           string
	Port                int
	Method              string
	URI                 string
	ExpectedCodeClasses string
	TLS                 bool
}

func TCP(ctx context.Context, backendIP string, port int) error {
	address := net.JoinHostPort(backendIP, strconv.Itoa(port))
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
	if err != nil {
		return err
	}
	defer conn.Close()
	return nil
}

func HTTP(ctx context.Context, config HTTPConfig) (bool, int, error) {
	method := strings.ToUpper(strings.TrimSpace(config.Method))
	if method == "" {
		method = http.MethodHead
	}
	if method != http.MethodGet && method != http.MethodHead {
		return false, 0, fmt.Errorf("unsupported health check method %q", config.Method)
	}

	uri := strings.TrimSpace(config.URI)
	if uri == "" {
		uri = "/"
	}
	if !strings.HasPrefix(uri, "/") {
		return false, 0, fmt.Errorf("health check URI must start with '/': %q", config.URI)
	}

	scheme := "http"
	if config.TLS {
		scheme = "https"
	}
	address := net.JoinHostPort(config.BackendIP, strconv.Itoa(config.Port))
	target := scheme + "://" + address + uri

	request, err := http.NewRequestWithContext(ctx, method, target, nil)
	if err != nil {
		return false, 0, fmt.Errorf("create health check request: %w", err)
	}
	request.Close = true

	transport := &http.Transport{
		DisableKeepAlives: true,
		TLSClientConfig: &tls.Config{
			// Backend health checks only verify the TLS and HTTP behavior.
			// They are intentionally independent of listener certificates.
			InsecureSkipVerify: true, //nolint:gosec
		},
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	response, err := client.Do(request)
	if err != nil {
		return false, 0, err
	}
	defer response.Body.Close()

	return IsExpectedHTTPStatus(
		response.StatusCode,
		config.ExpectedCodeClasses,
	), response.StatusCode, nil
}

func IsExpectedHTTPStatus(statusCode int, expectedCodeClasses string) bool {
	if expectedCodeClasses == "" {
		expectedCodeClasses = "http_2xx"
	}

	actualClass := statusCode / 100
	for _, expected := range strings.Split(expectedCodeClasses, ",") {
		switch strings.ToLower(strings.TrimSpace(expected)) {
		case "http_2xx":
			if actualClass == 2 {
				return true
			}
		case "http_3xx":
			if actualClass == 3 {
				return true
			}
		case "http_4xx":
			if actualClass == 4 {
				return true
			}
		case "http_5xx":
			if actualClass == 5 {
				return true
			}
		}
	}

	return false
}
