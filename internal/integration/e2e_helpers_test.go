// Package integration — end-to-end smoke tests that drive the real
// Gin router against an in-memory SQLite database and the same
// service constructors cmd/ztna-api/main.go wires at boot.
//
// Tests in this package intentionally exercise the full stack
// (HTTP → handler → service → GORM → SQLite) so a regression in any
// layer surfaces here. The only mock we accept is a
// *access.MockAccessConnector (or a deterministic stub for the AI
// RiskAssessor) — everything else is the real production type.
package integration_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/handlers"
	"github.com/kennguy3n/cautious-fishstick/internal/models"
	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

// newE2EDB constructs a SQLite in-memory DB with every access-platform
// model migrated. Kept narrow so unrelated schemas don't slow tests.
func newE2EDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:?cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(
		&models.AccessConnector{},
		&models.AccessRequest{},
		&models.AccessRequestStateHistory{},
		&models.AccessGrant{},
		&models.AccessGrantEntitlement{},
		&models.AccessWorkflow{},
		&models.AccessJob{},
		&models.AccessSyncState{},
		&models.AccessReview{},
		&models.AccessReviewDecision{},
		&models.Team{},
		&models.TeamMember{},
		&models.Policy{},
		&models.Resource{},
		// PAM tables — kept in this shared helper rather than a
		// pam-specific newPAMTestDB so the existing access-platform
		// e2e tests keep running against a single migrated schema
		// (no behavioural change: the access tables above are
		// orthogonal to the pam_* tables below) and so the
		// integration suite can drive a mixed access + PAM scenario
		// out of one DB if a future test needs to.
		&models.PAMAsset{},
		&models.PAMAccount{},
		&models.PAMSecret{},
		&models.PAMSession{},
		&models.PAMSessionCommand{},
		&models.PAMLease{},
		&models.PAMCommandPolicy{},
		&models.PAMRotationSchedule{},
	); err != nil {
		t.Fatalf("auto migrate e2e db: %v", err)
	}
	return db
}

// doJSON issues an HTTP request through r and returns the recorded
// status code and decoded JSON body. Body argument may be nil for
// requests without a payload.
func doJSON(t *testing.T, r http.Handler, method, path string, body any) (int, map[string]any) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal %s %s: %v", method, path, err)
		}
		reader = bytes.NewReader(buf)
	}
	req := httptest.NewRequest(method, path, reader)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	var out map[string]any
	if w.Body.Len() > 0 {
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			// Some responses (e.g. metrics) are plain text — surface
			// the raw body so test failures stay debuggable.
			out = map[string]any{"_raw": w.Body.String()}
		}
	}
	return w.Code, out
}

// silenceLogs swaps the handlers package logger out for a noop logger
// for the duration of a test so the JSON request log doesn't fill the
// test output. Returns a cleanup func.
func silenceLogs(t *testing.T) func() {
	t.Helper()
	prev := handlers.Logger()
	handlers.SetLogger(nil)
	return func() { handlers.SetLogger(prev) }
}

// stubAccessConnector builds a MockAccessConnector wired with no-op
// defaults. Tests override FuncSyncIdentities / FuncProvisionAccess /
// FuncRevokeAccess as needed.
func stubAccessConnector() *access.MockAccessConnector {
	return &access.MockAccessConnector{
		FuncValidate:          func(context.Context, map[string]interface{}, map[string]interface{}) error { return nil },
		FuncConnect:           func(context.Context, map[string]interface{}, map[string]interface{}) error { return nil },
		FuncVerifyPermissions: func(context.Context, map[string]interface{}, map[string]interface{}, []string) ([]string, error) { return nil, nil },
		FuncGetCredentialsMetadata: func(context.Context, map[string]interface{}, map[string]interface{}) (map[string]interface{}, error) {
			return nil, nil
		},
		FuncSyncIdentities: func(_ context.Context, _, _ map[string]interface{}, _ string, handler func([]*access.Identity, string) error) error {
			return handler(nil, "checkpoint")
		},
		FuncProvisionAccess: func(context.Context, map[string]interface{}, map[string]interface{}, access.AccessGrant) error { return nil },
		FuncRevokeAccess:    func(context.Context, map[string]interface{}, map[string]interface{}, access.AccessGrant) error { return nil },
	}
}
