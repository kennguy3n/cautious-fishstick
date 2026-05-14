package handlers

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

// fakeConnectorCatalogueReader is the in-memory ConnectorCatalogueReader
// the handler tests use so we don't pay the cost of seeding the
// registry + access_connectors rows just to exercise the HTTP layer.
type fakeConnectorCatalogueReader struct {
	out []access.ConnectorCatalogueEntry
	err error
	got access.ConnectorCatalogueQuery
}

func (f *fakeConnectorCatalogueReader) ListCatalogue(_ context.Context, q access.ConnectorCatalogueQuery) ([]access.ConnectorCatalogueEntry, error) {
	f.got = q
	if f.err != nil {
		return nil, f.err
	}
	return f.out, nil
}

func TestConnectorCatalogueHandler_HappyPath(t *testing.T) {
	reader := &fakeConnectorCatalogueReader{
		out: []access.ConnectorCatalogueEntry{
			{
				Provider:     "okta",
				Capabilities: access.ConnectorCatalogueCapabilities{Registered: true, GetAccessLog: true},
				Connected:    true,
				ConnectorID:  "01H00000000000000CONN0001",
				Status:       "connected",
			},
			{
				Provider:     "slack",
				Capabilities: access.ConnectorCatalogueCapabilities{Registered: true, SyncGroups: true},
				Connected:    false,
			},
		},
	}
	r := Router(Dependencies{ConnectorCatalogueReader: reader})
	w := doJSON(t, r, http.MethodGet, "/access/connectors/catalogue?workspace_id=01H000000000000000WORKSPACE", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s; want 200", w.Code, w.Body.String())
	}
	var got []access.ConnectorCatalogueEntry
	decodeJSON(t, w, &got)
	if len(got) != 2 {
		t.Fatalf("len(got) = %d; want 2", len(got))
	}
	if reader.got.WorkspaceID != "01H000000000000000WORKSPACE" {
		t.Fatalf("forwarded workspace_id = %q; want propagated value", reader.got.WorkspaceID)
	}
	if !got[0].Connected || got[0].ConnectorID == "" {
		t.Fatalf("first entry should be connected with a connector id; got %+v", got[0])
	}
	if !got[1].Capabilities.SyncGroups {
		t.Fatal("second entry should report SyncGroups=true")
	}
}

func TestConnectorCatalogueHandler_MissingWorkspaceID_Returns400(t *testing.T) {
	reader := &fakeConnectorCatalogueReader{}
	r := Router(Dependencies{ConnectorCatalogueReader: reader})
	w := doJSON(t, r, http.MethodGet, "/access/connectors/catalogue", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s; want 400", w.Code, w.Body.String())
	}
}

func TestConnectorCatalogueHandler_ReaderError_Returns500(t *testing.T) {
	reader := &fakeConnectorCatalogueReader{err: errors.New("db down")}
	r := Router(Dependencies{ConnectorCatalogueReader: reader})
	w := doJSON(t, r, http.MethodGet, "/access/connectors/catalogue?workspace_id=01H000000000000000WORKSPACE", nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d body=%s; want 500", w.Code, w.Body.String())
	}
}

func TestConnectorCatalogueHandler_NilSlice_Returns200WithEmptyArray(t *testing.T) {
	reader := &fakeConnectorCatalogueReader{out: nil}
	r := Router(Dependencies{ConnectorCatalogueReader: reader})
	w := doJSON(t, r, http.MethodGet, "/access/connectors/catalogue?workspace_id=01H000000000000000WORKSPACE", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s; want 200", w.Code, w.Body.String())
	}
	if got := w.Body.String(); got != "[]" && got != "[]\n" {
		t.Fatalf("body = %q; want %q", got, "[]")
	}
}
