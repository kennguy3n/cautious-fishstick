package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

func newConnectorHealthDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("sqlite open: %v", err)
	}
	if err := db.AutoMigrate(&models.AccessConnector{}, &models.AccessSyncState{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

func TestConnectorHealth_ReturnsAssembledView(t *testing.T) {
	db := newConnectorHealthDB(t)
	expiry := time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
	conn := &models.AccessConnector{
		ID:                    "01HZZCONN12345678901234",
		WorkspaceID:           "01HZZW0RKSPACE0000000000",
		Provider:              "okta",
		ConnectorType:         "idp",
		Status:                models.StatusConnected,
		CredentialExpiredTime: &expiry,
	}
	if err := db.Create(conn).Error; err != nil {
		t.Fatalf("create connector: %v", err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	for _, st := range []models.AccessSyncState{
		{ID: "01HZZSYNC1IDENTITY0000000", ConnectorID: conn.ID, Kind: models.SyncStateKindIdentity, DeltaLink: "id-cur", UpdatedAt: now.Add(-time.Hour)},
		{ID: "01HZZSYNC2AUDIT000000000A", ConnectorID: conn.ID, Kind: models.SyncStateKindAudit, DeltaLink: "au-cur", UpdatedAt: now.Add(-3 * time.Hour)},
	} {
		if err := db.Create(&st).Error; err != nil {
			t.Fatalf("create sync state: %v", err)
		}
	}
	svc := NewConnectorHealthService(db)
	r := Router(Dependencies{ConnectorHealthReader: svc})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/access/connectors/"+conn.ID+"/health", nil)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d (%s); want 200", w.Code, w.Body.String())
	}
	var out ConnectorHealth
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Provider != "okta" || out.Status != models.StatusConnected {
		t.Errorf("out = %+v", out)
	}
	if _, ok := out.LastSyncTimes[models.SyncStateKindIdentity]; !ok {
		t.Error("identity sync time missing")
	}
	if _, ok := out.LastSyncTimes[models.SyncStateKindAudit]; !ok {
		t.Error("audit sync time missing")
	}
	if out.CredentialExpiredTime == nil {
		t.Error("credential expiry should be propagated")
	}
	if out.StaleAudit {
		t.Errorf("stale_audit = true; want false (sync was 3h ago)")
	}
}

func TestConnectorHealth_StaleAuditAt24h(t *testing.T) {
	db := newConnectorHealthDB(t)
	conn := &models.AccessConnector{
		ID: "01HZZCONNXSTALE0000000A", WorkspaceID: "ws", Provider: "okta",
		ConnectorType: "idp", Status: models.StatusConnected,
	}
	if err := db.Create(conn).Error; err != nil {
		t.Fatalf("create: %v", err)
	}
	old := time.Now().Add(-72 * time.Hour)
	state := models.AccessSyncState{ID: "01HZZSYNCSTALE0000000000", ConnectorID: conn.ID, Kind: models.SyncStateKindAudit, UpdatedAt: old}
	if err := db.Create(&state).Error; err != nil {
		t.Fatalf("create state: %v", err)
	}
	// Force UpdatedAt; GORM resets it on Create.
	if err := db.Model(&models.AccessSyncState{}).
		Where("id = ?", state.ID).
		Update("updated_at", old).Error; err != nil {
		t.Fatalf("force updated_at: %v", err)
	}
	svc := NewConnectorHealthService(db)
	r := Router(Dependencies{ConnectorHealthReader: svc})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/access/connectors/"+conn.ID+"/health", nil)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d (%s)", w.Code, w.Body.String())
	}
	var out ConnectorHealth
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if !out.StaleAudit {
		t.Errorf("stale_audit = false; want true")
	}
}

func TestConnectorHealth_NotFound(t *testing.T) {
	db := newConnectorHealthDB(t)
	svc := NewConnectorHealthService(db)
	r := Router(Dependencies{ConnectorHealthReader: svc})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/access/connectors/01HZZNONE000000000000000/health", nil)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d; want 404", w.Code)
	}
}

func TestConnectorHealth_NotRegisteredWithoutDep(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	r := Router(Dependencies{})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/access/connectors/anything/health", nil)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d; want 404 (route not registered)", w.Code)
	}
}
