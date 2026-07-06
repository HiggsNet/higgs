package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestObserverEventsMethodNotAllowed(t *testing.T) {
	srv := newTestObserverServer()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/events", nil)
	rr := httptest.NewRecorder()
	srv.handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("status code = %d, want %d", rr.Code, http.StatusMethodNotAllowed)
	}
}

func TestObserverEventsInitialFrame(t *testing.T) {
	srv := newTestObserverServer()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/api/v1/events", nil)
	rr := httptest.NewRecorder()
	srv.handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", rr.Code, http.StatusOK)
	}
	if body := rr.Body.String(); !strings.Contains(body, "event: connected") {
		t.Fatalf("initial connected SSE frame was not written: %q", body)
	}
}
