package observer

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

type testProvider struct{}

func (testProvider) Status() (any, error)       { return map[string]any{}, nil }
func (testProvider) Zones(string) (any, error)  { return map[string]any{}, nil }
func (testProvider) Peers(string) (any, error)  { return map[string]any{}, nil }
func (testProvider) Links(string) (any, error)  { return map[string]any{}, nil }
func (testProvider) Health(string) (any, error) { return map[string]any{}, nil }
func (testProvider) HealthSeries(string, map[string]string) (any, error) {
	return map[string]any{}, nil
}
func (testProvider) Routes() (any, error) { return map[string]any{}, nil }
func (testProvider) Bird() (any, error)   { return map[string]any{}, nil }

func newTestServer() *Server {
	return NewServer(testProvider{}, Config{Enabled: true, BindAddr: "127.0.0.1", Port: 8080})
}

func TestStaticHandler(t *testing.T) {
	srv := newTestServer()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("status code = %d, want %d", rr.Code, http.StatusOK)
	}
	body := rr.Body.String()
	if body == "" {
		t.Error("static file response should not be empty")
	}
}

func TestStaticHandlerSPAFallbackContentType(t *testing.T) {
	srv := newTestServer()
	req := httptest.NewRequest(http.MethodGet, "/overlay/links", nil)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("status code = %d, want %d", rr.Code, http.StatusOK)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Errorf("content type = %q, want text/html; charset=utf-8", ct)
	}
}

func TestStaticHandlerCSS(t *testing.T) {
	srv := newTestServer()
	req := httptest.NewRequest(http.MethodGet, "/style.css", nil)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("status code = %d, want %d", rr.Code, http.StatusOK)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "text/css; charset=utf-8" {
		t.Errorf("content type = %q, want text/css; charset=utf-8", ct)
	}
}

func TestStaticHandlerJS(t *testing.T) {
	srv := newTestServer()
	req := httptest.NewRequest(http.MethodGet, "/app.js", nil)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("status code = %d, want %d", rr.Code, http.StatusOK)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/javascript; charset=utf-8" {
		t.Errorf("content type = %q, want application/javascript; charset=utf-8", ct)
	}
}

func TestStaticHandlerMethodNotAllowed(t *testing.T) {
	srv := newTestServer()
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("status code = %d, want %d", rr.Code, http.StatusMethodNotAllowed)
	}
}
