package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSwaggerHandler_ServesJSON(t *testing.T) {
	r := Router(Dependencies{})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/swagger.json", nil)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var spec map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &spec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if spec["openapi"] == nil {
		t.Fatalf("openapi key missing: %v", spec)
	}
}

func TestSwaggerHandler_ServesYAML(t *testing.T) {
	r := Router(Dependencies{})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/swagger.yaml", nil)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "openapi:") {
		t.Fatalf("yaml body missing openapi key: %q", w.Body.String())
	}
}

func TestSwaggerHandler_LiveAtAliasPath(t *testing.T) {
	r := Router(Dependencies{})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/swagger", nil)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
}

func TestSwaggerHandler_MissingFile_404(t *testing.T) {
	r := Router(Dependencies{})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/swagger.unknown", nil)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
}
