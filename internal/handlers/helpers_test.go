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

func TestGetStringParam_PresentReturnsValue(t *testing.T) {
	c := newTestContext(t, gin.Params{{Key: "id", Value: "01H..."}}, "")
	if got := GetStringParam(c, "id"); got != "01H..." {
		t.Fatalf("GetStringParam(\"id\") = %q; want %q", got, "01H...")
	}
}

// TestGetStringParam_StripsSurroundingWhitespace exercises the
// documented sanitisation contract on GetStringParam: a path param
// that arrives with leading/trailing whitespace (e.g. URL-encoded
// %20) must come back trimmed so downstream DB lookups and ID
// comparisons cannot silently mismatch on padding.
func TestGetStringParam_StripsSurroundingWhitespace(t *testing.T) {
	cases := []struct {
		name  string
		value string
		want  string
	}{
		{name: "leading", value: "  01H...", want: "01H..."},
		{name: "trailing", value: "01H...  ", want: "01H..."},
		{name: "both", value: "  01H...  ", want: "01H..."},
		{name: "tab and newline", value: "\t01H...\n", want: "01H..."},
		{name: "only whitespace", value: "   ", want: ""},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			c := newTestContext(t, gin.Params{{Key: "id", Value: tc.value}}, "")
			if got := GetStringParam(c, "id"); got != tc.want {
				t.Fatalf("GetStringParam(%q) = %q; want %q", tc.value, got, tc.want)
			}
		})
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

// TestGetPtrStringQuery_StripsSurroundingWhitespace mirrors the
// GetStringParam contract for query parameters. A query value that
// arrives with surrounding whitespace must trim down to the bare
// value, but the returned pointer must remain non-nil even when the
// trimmed result is "" — callers distinguish "not sent" (nil) from
// "sent blank" (pointer to "") and that distinction must survive
// trimming of pure-whitespace values.
func TestGetPtrStringQuery_StripsSurroundingWhitespace(t *testing.T) {
	cases := []struct {
		name  string
		query string
		want  string
	}{
		{name: "leading", query: "workspace_id=%20%20ws-1", want: "ws-1"},
		{name: "trailing", query: "workspace_id=ws-1%20%20", want: "ws-1"},
		{name: "both", query: "workspace_id=%20%20ws-1%20%20", want: "ws-1"},
		{name: "only whitespace", query: "workspace_id=%20%20%20", want: ""},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			c := newTestContext(t, nil, tc.query)
			got := GetPtrStringQuery(c, "workspace_id")
			if got == nil {
				t.Fatalf("GetPtrStringQuery(%q) = nil; want pointer to %q (trimmed value, non-nil even when blank)", tc.query, tc.want)
			}
			if *got != tc.want {
				t.Fatalf("GetPtrStringQuery(%q) = %q; want %q", tc.query, *got, tc.want)
			}
		})
	}
}
