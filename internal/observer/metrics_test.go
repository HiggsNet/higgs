package observer

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

type metricsTestProvider struct{ testProvider }

func (metricsTestProvider) OpenMetrics() (string, error) {
	return "photon_link_probe_packets_lost{} 9\n# EOF\n", nil
}

func TestMetricsEndpointUsesOpenMetricsContentType(t *testing.T) {
	server := NewServer(metricsTestProvider{}, Config{Enabled: true})
	request := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", response.Code, response.Body.String())
	}
	if got := response.Header().Get("Content-Type"); got != "application/openmetrics-text; version=1.0.0; charset=utf-8" {
		t.Fatalf("content type = %q", got)
	}
	if got := response.Body.String(); got != "photon_link_probe_packets_lost{} 9\n# EOF\n" {
		t.Fatalf("body = %q", got)
	}
}
