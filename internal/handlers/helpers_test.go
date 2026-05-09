package handlers

import (
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func newTestContext(t *testing.T, params gin.Params, query string) *gin.Context {
	t.Helper()
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	target := "/?" + query
	c.Request = httptest.NewRequest("GET", target, nil)
	c.Params = params
	return c
}

func TestGetStringParam_PresentAndStripped(t *testing.T) {
	c := newTestContext(t, gin.Params{{Key: "id", Value: "01H..."}}, "")
	if got := GetStringParam(c, "id"); got != "01H..." {
		t.Fatalf("GetStringParam(\"id\") = %q; want %q", got, "01H...")
	}
}

func TestGetStringParam_AbsentReturnsEmpty(t *testing.T) {
	c := newTestContext(t, gin.Params{}, "")
	if got := GetStringParam(c, "id"); got != "" {
		t.Fatalf("GetStringParam(\"id\") = %q; want \"\"", got)
	}
}

func TestGetStringParam_NilContextReturnsEmpty(t *testing.T) {
	if got := GetStringParam(nil, "id"); got != "" {
		t.Fatalf("GetStringParam(nil, \"id\") = %q; want \"\"", got)
	}
}

func TestGetStringParam_EmptyKeyReturnsEmpty(t *testing.T) {
	c := newTestContext(t, gin.Params{{Key: "id", Value: "x"}}, "")
	if got := GetStringParam(c, ""); got != "" {
		t.Fatalf("GetStringParam(c, \"\") = %q; want \"\"", got)
	}
}

func TestGetPtrStringQuery_PresentReturnsPointer(t *testing.T) {
	c := newTestContext(t, nil, "workspace_id=ws-1")
	got := GetPtrStringQuery(c, "workspace_id")
	if got == nil {
		t.Fatal("GetPtrStringQuery returned nil; want pointer")
	}
	if *got != "ws-1" {
		t.Fatalf("got = %q; want %q", *got, "ws-1")
	}
}

func TestGetPtrStringQuery_AbsentReturnsNil(t *testing.T) {
	c := newTestContext(t, nil, "")
	if got := GetPtrStringQuery(c, "workspace_id"); got != nil {
		t.Fatalf("GetPtrStringQuery returned %v; want nil", *got)
	}
}

func TestGetPtrStringQuery_PresentButEmptyReturnsPointerToEmpty(t *testing.T) {
	c := newTestContext(t, nil, "workspace_id=")
	got := GetPtrStringQuery(c, "workspace_id")
	if got == nil {
		t.Fatal("GetPtrStringQuery returned nil; want pointer to empty string")
	}
	if *got != "" {
		t.Fatalf("got = %q; want \"\"", *got)
	}
}

func TestGetPtrStringQuery_NilContextReturnsNil(t *testing.T) {
	if got := GetPtrStringQuery(nil, "x"); got != nil {
		t.Fatal("GetPtrStringQuery(nil) returned non-nil; want nil")
	}
}

func TestGetPtrStringQuery_EmptyKeyReturnsNil(t *testing.T) {
	c := newTestContext(t, nil, "x=y")
	if got := GetPtrStringQuery(c, ""); got != nil {
		t.Fatal("GetPtrStringQuery(c, \"\") returned non-nil; want nil")
	}
}
