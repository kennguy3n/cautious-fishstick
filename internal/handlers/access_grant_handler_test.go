package handlers

import (
	"net/http"
	"testing"
	"time"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

func newGrantEngine(t *testing.T) (http.Handler, *access.AccessGrantQueryService) {
	t.Helper()
	db := newTestDB(t)
	svc := access.NewAccessGrantQueryService(db)
	r := Router(Dependencies{AccessGrantReader: &AccessGrantReaderAdapter{Inner: svc}})

	// Seed two grants under different users / connectors.
	now := time.Now()
	g1 := &models.AccessGrant{
		ID:                 "01H00000000000000GRANT0001",
		WorkspaceID:        "01H000000000000000WORKSPACE",
		UserID:             "01H000000000000000USER0001",
		ConnectorID:        "01H000000000000000CONN0001",
		ResourceExternalID: "host-001",
		Role:               "viewer",
		GrantedAt:          now,
		CreatedAt:          now,
		UpdatedAt:          now,
	}
	g2 := &models.AccessGrant{
		ID:                 "01H00000000000000GRANT0002",
		WorkspaceID:        "01H000000000000000WORKSPACE",
		UserID:             "01H000000000000000USER0002",
		ConnectorID:        "01H000000000000000CONN0002",
		ResourceExternalID: "host-002",
		Role:               "admin",
		GrantedAt:          now,
		CreatedAt:          now,
		UpdatedAt:          now,
	}
	if err := db.Create(g1).Error; err != nil {
		t.Fatalf("seed g1: %v", err)
	}
	if err := db.Create(g2).Error; err != nil {
		t.Fatalf("seed g2: %v", err)
	}
	return r, svc
}

func TestAccessGrantHandler_ListByUser(t *testing.T) {
	r, _ := newGrantEngine(t)
	w := doJSON(t, r, http.MethodGet, "/access/grants?user_id=01H000000000000000USER0001", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s; want 200", w.Code, w.Body.String())
	}
	var got []models.AccessGrant
	decodeJSON(t, w, &got)
	if len(got) != 1 {
		t.Fatalf("got %d grants; want 1", len(got))
	}
	if got[0].UserID != "01H000000000000000USER0001" {
		t.Fatalf("UserID = %q; want USER0001", got[0].UserID)
	}
}

func TestAccessGrantHandler_ListByConnector(t *testing.T) {
	r, _ := newGrantEngine(t)
	w := doJSON(t, r, http.MethodGet, "/access/grants?connector_id=01H000000000000000CONN0002", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s; want 200", w.Code, w.Body.String())
	}
	var got []models.AccessGrant
	decodeJSON(t, w, &got)
	if len(got) != 1 {
		t.Fatalf("got %d grants; want 1", len(got))
	}
}

func TestAccessGrantHandler_NoFilterReturns400(t *testing.T) {
	r, _ := newGrantEngine(t)
	w := doJSON(t, r, http.MethodGet, "/access/grants", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d; want 400", w.Code)
	}
}
