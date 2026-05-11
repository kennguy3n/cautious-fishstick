package handlers

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

// fakeConnectorListReader is the in-memory ConnectorListReader used
// by the handler tests so we don't pay the cost of seeding access_
// connectors rows + the access_sync_state join + the registry hook
// just to exercise the HTTP surface.
type fakeConnectorListReader struct {
	out []access.ConnectorSummary
	err error
}

func (f *fakeConnectorListReader) ListConnectors(_ context.Context, _ access.ListConnectorsQuery) ([]access.ConnectorSummary, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.out, nil
}

func TestConnectorListHandler_HappyPath(t *testing.T) {
	now := time.Now()
	reader := &fakeConnectorListReader{
		out: []access.ConnectorSummary{
			{
				ID:            "01H00000000000000CONN0001",
				WorkspaceID:   "01H000000000000000WORKSPACE",
				Provider:      "okta",
				ConnectorType: "saas",
				Status:        "connected",
				LastSyncTimes: map[string]time.Time{"identity": now},
				Capabilities:  access.ConnectorCapabilities{Registered: true, GetAccessLog: true},
			},
		},
	}
	r := Router(Dependencies{ConnectorListReader: reader})
	w := doJSON(t, r, http.MethodGet, "/access/connectors?workspace_id=01H000000000000000WORKSPACE", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s; want 200", w.Code, w.Body.String())
	}
	var got []access.ConnectorSummary
	decodeJSON(t, w, &got)
	if len(got) != 1 {
		t.Fatalf("len(got) = %d; want 1", len(got))
	}
	if got[0].Provider != "okta" {
		t.Fatalf("Provider = %q; want %q", got[0].Provider, "okta")
	}
	if !got[0].Capabilities.GetAccessLog {
		t.Fatal("Capabilities.GetAccessLog = false; want true")
	}
}

func TestConnectorListHandler_MissingWorkspaceReturns400(t *testing.T) {
	r := Router(Dependencies{ConnectorListReader: &fakeConnectorListReader{}})
	w := doJSON(t, r, http.MethodGet, "/access/connectors", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s; want 400", w.Code, w.Body.String())
	}
}

func TestConnectorListHandler_EmptyResultReturnsArray(t *testing.T) {
	r := Router(Dependencies{ConnectorListReader: &fakeConnectorListReader{out: nil}})
	w := doJSON(t, r, http.MethodGet, "/access/connectors?workspace_id=01H000000000000000WORKSPACE", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", w.Code, w.Body.String())
	}
	// JSON serialisation of an empty slice must be `[]` (not `null`)
	// so the operator UI does not need a null-check.
	if got := w.Body.String(); got != "[]" {
		t.Fatalf("body = %q; want %q", got, "[]")
	}
}
