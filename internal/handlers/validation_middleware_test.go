package handlers

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func newValidationRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(JSONValidationMiddleware())
	r.POST("/access/requests", func(c *gin.Context) {
		// Echo the body back to confirm the middleware rewound the
		// stream for the downstream handler.
		body, _ := io.ReadAll(c.Request.Body)
		c.Data(http.StatusOK, "application/json", body)
	})
	r.GET("/access/requests", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })
	return r
}

func TestJSONValidationMiddleware_AcceptsValidJSON(t *testing.T) {
	r := newValidationRouter()
	body := bytes.NewBufferString(`{"workspace_id":"ws-1","requester_user_id":"u-1"}`)
	req := httptest.NewRequest(http.MethodPost, "/access/requests", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for valid JSON, got %d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "workspace_id") {
		t.Fatalf("expected downstream handler to see body, got %s", w.Body.String())
	}
}

func TestJSONValidationMiddleware_Rejects400OnInvalidJSON(t *testing.T) {
	r := newValidationRouter()
	body := bytes.NewBufferString(`{not-json}`)
	req := httptest.NewRequest(http.MethodPost, "/access/requests", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for malformed JSON, got %d body=%s", w.Code, w.Body.String())
	}
	var parsed map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &parsed); err != nil {
		t.Fatalf("response is not JSON: %v\n%s", err, w.Body.String())
	}
	if parsed["error"] != "invalid_json" {
		t.Fatalf("expected error=invalid_json, got %v", parsed["error"])
	}
	if parsed["code"] != "validation_failed" {
		t.Fatalf("expected code=validation_failed, got %v", parsed["code"])
	}
	if msg, _ := parsed["message"].(string); msg == "" {
		t.Fatalf("expected non-empty message, got %v", parsed["message"])
	}
}

func TestJSONValidationMiddleware_RejectsTrailingTokens(t *testing.T) {
	r := newValidationRouter()
	body := bytes.NewBufferString(`{"a":1}{"b":2}`)
	req := httptest.NewRequest(http.MethodPost, "/access/requests", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for trailing JSON values, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestJSONValidationMiddleware_RejectsWrongContentType(t *testing.T) {
	r := newValidationRouter()
	body := bytes.NewBufferString(`a=1`)
	req := httptest.NewRequest(http.MethodPost, "/access/requests", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("expected 415, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestJSONValidationMiddleware_AllowsJSONCharsetParameter(t *testing.T) {
	r := newValidationRouter()
	body := bytes.NewBufferString(`{"ok":true}`)
	req := httptest.NewRequest(http.MethodPost, "/access/requests", body)
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 with charset parameter, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestJSONValidationMiddleware_AllowsApplicationSubtypePlusJSON(t *testing.T) {
	r := newValidationRouter()
	body := bytes.NewBufferString(`{"ok":true}`)
	req := httptest.NewRequest(http.MethodPost, "/access/requests", body)
	req.Header.Set("Content-Type", "application/vnd.foo+json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for application/*+json, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestJSONValidationMiddleware_GETBypasses(t *testing.T) {
	r := newValidationRouter()
	req := httptest.NewRequest(http.MethodGet, "/access/requests", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 on GET, got %d", w.Code)
	}
}

func TestJSONValidationMiddleware_EmptyPOSTBodyPasses(t *testing.T) {
	r := newValidationRouter()
	req := httptest.NewRequest(http.MethodPost, "/access/requests", nil)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected POST with empty body to pass (handler decides if body required), got %d", w.Code)
	}
}

func TestJSONValidationMiddleware_RejectsOversizeBody(t *testing.T) {
	r := newValidationRouter()
	// Generate a payload comfortably over the 1 MiB cap.
	big := bytes.Repeat([]byte("a"), maxRequestBodyBytes+2048)
	body := append([]byte(`{"junk":"`), big...)
	body = append(body, []byte(`"}`)...)
	req := httptest.NewRequest(http.MethodPost, "/access/requests", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestJSONValidationMiddleware_SCIMPathBypasses(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(JSONValidationMiddleware())
	r.POST("/scim/Users", func(c *gin.Context) {
		// Even though the body is "not JSON" by application/json
		// standards, SCIM uses application/scim+json (which our
		// isJSONContentType *does* accept anyway); the path bypass
		// here is the belt-and-braces guard for handlers that
		// validate their own SCIM content-type vocabulary.
		c.Status(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodPost, "/scim/Users", bytes.NewBufferString(`not-json-but-scim-handler-validates`))
	req.Header.Set("Content-Type", "application/scim+json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected SCIM path to bypass JSON validator, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestWriteFieldErrors_EmitsFieldArray(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/x", func(c *gin.Context) {
		WriteFieldErrors(c, []FieldError{
			{Field: "workspace_id", Message: "required"},
			{Field: "resource_external_id", Message: "must be non-empty"},
		})
	})
	req := httptest.NewRequest(http.MethodPost, "/x", bytes.NewBufferString(`{}`))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
	var parsed map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &parsed); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, w.Body.String())
	}
	if parsed["error"] != "validation_failed" {
		t.Fatalf("expected error=validation_failed, got %v", parsed["error"])
	}
	fields, ok := parsed["fields"].([]any)
	if !ok || len(fields) != 2 {
		t.Fatalf("expected 2-element fields array, got %v", parsed["fields"])
	}
}

func TestWriteFieldErrors_EmptyFieldsStillEmits400(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/x", func(c *gin.Context) {
		WriteFieldErrors(c, nil)
	})
	req := httptest.NewRequest(http.MethodPost, "/x", bytes.NewBufferString(`{}`))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 fallback, got %d", w.Code)
	}
}
