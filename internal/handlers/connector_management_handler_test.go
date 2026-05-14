package handlers

import (
	"context"
	"net/http"
	"testing"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

// newConnectorManagementEngine returns a real Gin router wired to a
// real ConnectorManagementService backed by a real in-memory SQLite
// DB. The MockAccessConnector substitutes for the external SaaS API
// boundary — every other component (encryptor, DB, router) is real.
func newConnectorManagementEngine(t *testing.T, mock *access.MockAccessConnector) (http.Handler, *access.ConnectorManagementService) {
	t.Helper()
	db := newTestDB(t)
	access.SwapConnector(t, "test_provider", mock)
	svc := access.NewConnectorManagementService(db, access.PassthroughEncryptor{}, nil, nil)
	r := Router(Dependencies{ConnectorManagementService: svc})
	return r, svc
}

func happyMock() *access.MockAccessConnector {
	return &access.MockAccessConnector{
		FuncValidate: func(context.Context, map[string]interface{}, map[string]interface{}) error { return nil },
		FuncConnect:  func(context.Context, map[string]interface{}, map[string]interface{}) error { return nil },
		FuncVerifyPermissions: func(context.Context, map[string]interface{}, map[string]interface{}, []string) ([]string, error) {
			return nil, nil
		},
		FuncGetCredentialsMetadata: func(context.Context, map[string]interface{}, map[string]interface{}) (map[string]interface{}, error) {
			return nil, nil
		},
	}
}

func validCreateConnectorBody() map[string]interface{} {
	return map[string]interface{}{
		"workspace_id":   "01H000000000000000WORKSPACE",
		"provider":       "test_provider",
		"connector_type": "directory",
		"config":         map[string]interface{}{"tenant": "acme"},
		"secrets":        map[string]interface{}{"api_key": "shhh"},
		"capabilities":   []string{"read"},
	}
}

func TestConnectorManagementHandler_Create_HappyPath(t *testing.T) {
	r, svc := newConnectorManagementEngine(t, happyMock())
	w := doJSON(t, r, http.MethodPost, "/access/connectors", validCreateConnectorBody())
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d body=%s; want 201", w.Code, w.Body.String())
	}
	var got access.ConnectResult
	decodeJSON(t, w, &got)
	if got.ConnectorID == "" || got.JobID == "" {
		t.Fatalf("missing IDs in response: %+v", got)
	}
	// Verify real DB row exists.
	var conn models.AccessConnector
	if err := svc.DBForTest().Where("id = ?", got.ConnectorID).First(&conn).Error; err != nil {
		t.Fatalf("connector row not persisted: %v", err)
	}
	if conn.Status != models.StatusConnected {
		t.Fatalf("status = %q; want %q", conn.Status, models.StatusConnected)
	}
	if conn.Credentials == "" {
		t.Fatal("credentials column not populated")
	}
	// Verify real access_jobs row exists.
	var job models.AccessJob
	if err := svc.DBForTest().Where("id = ?", got.JobID).First(&job).Error; err != nil {
		t.Fatalf("job row not persisted: %v", err)
	}
	if job.JobType != models.AccessJobTypeSyncIdentities {
		t.Fatalf("job type = %q; want %q", job.JobType, models.AccessJobTypeSyncIdentities)
	}
}

func TestConnectorManagementHandler_Create_Duplicate_Returns409(t *testing.T) {
	r, _ := newConnectorManagementEngine(t, happyMock())
	if w := doJSON(t, r, http.MethodPost, "/access/connectors", validCreateConnectorBody()); w.Code != http.StatusCreated {
		t.Fatalf("seed: %d body=%s", w.Code, w.Body.String())
	}
	w := doJSON(t, r, http.MethodPost, "/access/connectors", validCreateConnectorBody())
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d body=%s; want 409", w.Code, w.Body.String())
	}
}

func TestConnectorManagementHandler_Create_UnknownProvider_Returns400(t *testing.T) {
	r, _ := newConnectorManagementEngine(t, happyMock())
	body := validCreateConnectorBody()
	body["provider"] = "no_such_provider"
	w := doJSON(t, r, http.MethodPost, "/access/connectors", body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s; want 400", w.Code, w.Body.String())
	}
}

func TestConnectorManagementHandler_Create_ValidationFails_Returns400(t *testing.T) {
	mock := happyMock()
	mock.FuncValidate = func(context.Context, map[string]interface{}, map[string]interface{}) error {
		return access.ErrValidation
	}
	r, _ := newConnectorManagementEngine(t, mock)
	w := doJSON(t, r, http.MethodPost, "/access/connectors", validCreateConnectorBody())
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s; want 400", w.Code, w.Body.String())
	}
}

func TestConnectorManagementHandler_Delete_HappyPath(t *testing.T) {
	r, svc := newConnectorManagementEngine(t, happyMock())
	createW := doJSON(t, r, http.MethodPost, "/access/connectors", validCreateConnectorBody())
	if createW.Code != http.StatusCreated {
		t.Fatalf("seed: %d", createW.Code)
	}
	var created access.ConnectResult
	decodeJSON(t, createW, &created)

	w := doJSON(t, r, http.MethodDelete, "/access/connectors/"+created.ConnectorID, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s; want 200", w.Code, w.Body.String())
	}
	// Verify real DB soft-delete.
	var conn models.AccessConnector
	if err := svc.DBForTest().Unscoped().Where("id = ?", created.ConnectorID).First(&conn).Error; err != nil {
		t.Fatalf("connector row missing: %v", err)
	}
	if !conn.DeletedAt.Valid {
		t.Fatal("expected deleted_at to be set after disconnect")
	}
}

func TestConnectorManagementHandler_Delete_NotFound_Returns404(t *testing.T) {
	r, _ := newConnectorManagementEngine(t, happyMock())
	w := doJSON(t, r, http.MethodDelete, "/access/connectors/01HCONN0NOTFOUND0000000001", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d body=%s; want 404", w.Code, w.Body.String())
	}
}

func TestConnectorManagementHandler_RotateSecret_HappyPath(t *testing.T) {
	r, svc := newConnectorManagementEngine(t, happyMock())
	createW := doJSON(t, r, http.MethodPost, "/access/connectors", validCreateConnectorBody())
	if createW.Code != http.StatusCreated {
		t.Fatalf("seed: %d", createW.Code)
	}
	var created access.ConnectResult
	decodeJSON(t, createW, &created)

	// Capture the original ciphertext to confirm rotation changed it.
	var before models.AccessConnector
	if err := svc.DBForTest().Where("id = ?", created.ConnectorID).First(&before).Error; err != nil {
		t.Fatalf("load before: %v", err)
	}

	rotateBody := map[string]interface{}{
		"secrets": map[string]interface{}{"api_key": "rotated-secret"},
	}
	w := doJSON(t, r, http.MethodPut, "/access/connectors/"+created.ConnectorID+"/secret", rotateBody)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s; want 200", w.Code, w.Body.String())
	}
	var after models.AccessConnector
	if err := svc.DBForTest().Where("id = ?", created.ConnectorID).First(&after).Error; err != nil {
		t.Fatalf("load after: %v", err)
	}
	if after.Credentials == before.Credentials {
		t.Fatal("expected credentials column to change after rotation")
	}
}

func TestConnectorManagementHandler_TriggerSync_HappyPath(t *testing.T) {
	r, svc := newConnectorManagementEngine(t, happyMock())
	createW := doJSON(t, r, http.MethodPost, "/access/connectors", validCreateConnectorBody())
	if createW.Code != http.StatusCreated {
		t.Fatalf("seed: %d", createW.Code)
	}
	var created access.ConnectResult
	decodeJSON(t, createW, &created)

	w := doJSON(t, r, http.MethodPost, "/access/connectors/"+created.ConnectorID+"/sync", nil)
	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d body=%s; want 202", w.Code, w.Body.String())
	}
	var got map[string]string
	decodeJSON(t, w, &got)
	if got["job_id"] == "" {
		t.Fatal("missing job_id in response")
	}
	// Verify real access_jobs row exists.
	var jobs []models.AccessJob
	if err := svc.DBForTest().Where("connector_id = ?", created.ConnectorID).Find(&jobs).Error; err != nil {
		t.Fatalf("list jobs: %v", err)
	}
	if len(jobs) < 2 {
		t.Fatalf("expected at least 2 jobs (initial + manual), got %d", len(jobs))
	}
}

// TestConnectorManagementHandler_Patch_AccessMode_HappyPath asserts
// PATCH /access/connectors/:id flips access_mode from the default
// "api_only" to "tunnel" and persists the new value to the DB.
func TestConnectorManagementHandler_Patch_AccessMode_HappyPath(t *testing.T) {
	r, svc := newConnectorManagementEngine(t, happyMock())
	createW := doJSON(t, r, http.MethodPost, "/access/connectors", validCreateConnectorBody())
	if createW.Code != http.StatusCreated {
		t.Fatalf("seed: %d", createW.Code)
	}
	var created access.ConnectResult
	decodeJSON(t, createW, &created)

	body := map[string]interface{}{"access_mode": "tunnel"}
	w := doJSON(t, r, http.MethodPatch, "/access/connectors/"+created.ConnectorID, body)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s; want 200", w.Code, w.Body.String())
	}
	var got map[string]string
	decodeJSON(t, w, &got)
	if got["access_mode"] != models.AccessModeTunnel {
		t.Fatalf("response access_mode=%q, want %q", got["access_mode"], models.AccessModeTunnel)
	}
	var row models.AccessConnector
	if err := svc.DBForTest().Where("id = ?", created.ConnectorID).First(&row).Error; err != nil {
		t.Fatalf("load row: %v", err)
	}
	if row.AccessMode != models.AccessModeTunnel {
		t.Fatalf("row.AccessMode=%q, want %q", row.AccessMode, models.AccessModeTunnel)
	}
}

// TestConnectorManagementHandler_Patch_AccessMode_Validation covers
// the two 400 paths: malformed access_mode and an empty body. Both
// must return 400 with the validation_failed code so the admin UI
// surfaces the reason inline.
func TestConnectorManagementHandler_Patch_AccessMode_Validation(t *testing.T) {
	r, _ := newConnectorManagementEngine(t, happyMock())
	createW := doJSON(t, r, http.MethodPost, "/access/connectors", validCreateConnectorBody())
	if createW.Code != http.StatusCreated {
		t.Fatalf("seed: %d", createW.Code)
	}
	var created access.ConnectResult
	decodeJSON(t, createW, &created)

	w := doJSON(t, r, http.MethodPatch, "/access/connectors/"+created.ConnectorID,
		map[string]interface{}{"access_mode": "nonsense"})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("malformed mode: status=%d body=%s; want 400", w.Code, w.Body.String())
	}

	w = doJSON(t, r, http.MethodPatch, "/access/connectors/"+created.ConnectorID,
		map[string]interface{}{})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("empty body: status=%d body=%s; want 400", w.Code, w.Body.String())
	}
}

// TestConnectorManagementHandler_Patch_AccessMode_NotFound asserts
// PATCH on a missing connector ID returns 404 (via the
// ErrConnectorRowNotFound sentinel mapping).
func TestConnectorManagementHandler_Patch_AccessMode_NotFound(t *testing.T) {
	r, _ := newConnectorManagementEngine(t, happyMock())
	body := map[string]interface{}{"access_mode": "tunnel"}
	w := doJSON(t, r, http.MethodPatch, "/access/connectors/01HDOES_NOT_EXIST00000000", body)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status=%d body=%s; want 404", w.Code, w.Body.String())
	}
}
