package handlers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

// fakeEntitlementsReader is the in-memory GrantEntitlementsReader
// used in the handler-level tests. It avoids spinning up the full
// (DB row → credential decrypt → registered connector) chain so
// the HTTP surface assertions stay focused.
type fakeEntitlementsReader struct {
	out []access.Entitlement
	err error
}

func (f *fakeEntitlementsReader) ListGrantEntitlements(_ context.Context, _ string) ([]access.Entitlement, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.out, nil
}

// entitlementsEngine wires the AccessGrantHandler with both readers
// so the test exercises the full route registration path. The
// underlying DB is seeded with one active grant just so the
// /access/grants route is operational; the entitlements route does
// not touch the DB at the handler level.
func entitlementsEngine(t *testing.T, reader GrantEntitlementsReader) http.Handler {
	t.Helper()
	db := newTestDB(t)
	svc := access.NewAccessGrantQueryService(db)
	now := time.Now()
	if err := db.Create(&models.AccessGrant{
		ID:                 "01H00000000000000GRANT0001",
		WorkspaceID:        "01H000000000000000WORKSPACE",
		UserID:             "01H000000000000000USER0001",
		ConnectorID:        "01H000000000000000CONN0001",
		ResourceExternalID: "host-001",
		Role:               "viewer",
		GrantedAt:          now,
		CreatedAt:          now,
		UpdatedAt:          now,
	}).Error; err != nil {
		t.Fatalf("seed grant: %v", err)
	}
	return Router(Dependencies{
		AccessGrantReader:       &AccessGrantReaderAdapter{Inner: svc},
		GrantEntitlementsReader: reader,
	})
}

func TestAccessGrantHandler_Entitlements_HappyPath(t *testing.T) {
	reader := &fakeEntitlementsReader{out: []access.Entitlement{
		{ResourceExternalID: "projects/foo", Role: "viewer", Source: "okta"},
		{ResourceExternalID: "projects/bar", Role: "editor", Source: "okta"},
	}}
	r := entitlementsEngine(t, reader)
	w := doJSON(t, r, http.MethodGet, "/access/grants/01H00000000000000GRANT0001/entitlements", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s; want 200", w.Code, w.Body.String())
	}
	var got struct {
		GrantID      string               `json:"grant_id"`
		Entitlements []access.Entitlement `json:"entitlements"`
	}
	decodeJSON(t, w, &got)
	if got.GrantID != "01H00000000000000GRANT0001" {
		t.Fatalf("grant_id = %q; want GRANT0001", got.GrantID)
	}
	if len(got.Entitlements) != 2 {
		t.Fatalf("len(entitlements) = %d; want 2", len(got.Entitlements))
	}
}

func TestAccessGrantHandler_Entitlements_ConnectorErrorMapsTo500(t *testing.T) {
	reader := &fakeEntitlementsReader{err: errors.New("upstream connector unreachable")}
	r := entitlementsEngine(t, reader)
	w := doJSON(t, r, http.MethodGet, "/access/grants/01H00000000000000GRANT0001/entitlements", nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d body=%s; want 500", w.Code, w.Body.String())
	}
}

func TestAccessGrantHandler_Entitlements_NotFoundMapsTo404(t *testing.T) {
	reader := &fakeEntitlementsReader{err: fmt.Errorf("%w: missing", access.ErrGrantNotFound)}
	r := entitlementsEngine(t, reader)
	w := doJSON(t, r, http.MethodGet, "/access/grants/01H00000000000000GRANT0001/entitlements", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d body=%s; want 404", w.Code, w.Body.String())
	}
}

func TestAccessGrantHandler_Entitlements_RouteUnregisteredReturns404(t *testing.T) {
	// When the entitlements reader is nil the route is intentionally
	// not registered; gin returns a vanilla 404.
	db := newTestDB(t)
	svc := access.NewAccessGrantQueryService(db)
	r := Router(Dependencies{
		AccessGrantReader: &AccessGrantReaderAdapter{Inner: svc},
	})
	w := doJSON(t, r, http.MethodGet, "/access/grants/01H00000000000000GRANT0001/entitlements", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d body=%s; want 404 (route not registered)", w.Code, w.Body.String())
	}
}
