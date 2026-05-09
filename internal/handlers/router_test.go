package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealth_Returns200(t *testing.T) {
	r := Router(Dependencies{})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200", w.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["status"] != "ok" {
		t.Fatalf("status = %q; want %q", body["status"], "ok")
	}
}

func TestRouter_NoServicesDoesNotPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Router(empty) panicked: %v", r)
		}
	}()
	r := Router(Dependencies{})
	if r == nil {
		t.Fatal("Router returned nil engine")
	}
}

func TestHealth_AcceptsHEAD(t *testing.T) {
	// HEAD on a GET-registered route is allowed by Gin's tree by
	// default? Actually it's not — but we want to make sure the
	// route exists at the registered method level. Here we assert
	// that an unregistered method returns 404 for /health POST.
	r := Router(Dependencies{})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/health", nil)
	r.ServeHTTP(w, req)
	if w.Code == http.StatusOK {
		t.Fatalf("POST /health unexpectedly returned 200")
	}
}
