package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// newTestEngine returns a *gorm.DB backed by an in-memory SQLite
// instance with every table the handler tests touch already
// migrated. The handler tests never round-trip through PostgreSQL —
// the service-layer tests (which do) cover the postgres-specific
// sql edge cases.
func newTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(
		&models.AccessRequest{},
		&models.AccessRequestStateHistory{},
		&models.AccessGrant{},
		&models.AccessWorkflow{},
		&models.Policy{},
		&models.Team{},
		&models.TeamMember{},
		&models.Resource{},
		&models.AccessReview{},
		&models.AccessReviewDecision{},
		&models.AccessConnector{},
		&models.AccessJob{},
		&models.AccessSyncState{},
		&models.AccessGrantEntitlement{},
	); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}
	return db
}

// doJSON serialises body to JSON and dispatches it via the supplied
// gin engine. Returns the captured response recorder for assertion.
func doJSON(t *testing.T, h http.Handler, method, path string, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	var rdr *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		rdr = bytes.NewReader(b)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rdr)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

// decodeJSON unmarshals the response recorder's body into out. Test
// helper so each test case stays terse.
func decodeJSON(t *testing.T, w *httptest.ResponseRecorder, out interface{}) {
	t.Helper()
	if err := json.Unmarshal(w.Body.Bytes(), out); err != nil {
		t.Fatalf("decode response (%s): %v", w.Body.String(), err)
	}
}
