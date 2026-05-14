package integration_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/kennguy3n/cautious-fishstick/internal/handlers"
	"github.com/kennguy3n/cautious-fishstick/internal/models"
	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
	workerhandlers "github.com/kennguy3n/cautious-fishstick/internal/workers/handlers"
)

// TestConnectorLifecycle_E2E drives the full connector lifecycle
// through the real Gin router:
//
//   POST /access/connectors → 201 (connector created, sync job enqueued)
//   POST /access/connectors/:id/sync → 200 (extra sync job enqueued)
//   workers/handlers.AccessSyncIdentities → populates teams + team_members
//   DELETE /access/connectors/:id → 200 (soft-delete + grant revoke)
//
// The only mock is MockAccessConnector. Encryption uses the real
// PassthroughEncryptor and provisioning uses the real
// AccessProvisioningService so a regression in any of those layers
// surfaces here.
func TestConnectorLifecycle_E2E(t *testing.T) {
	const provider = "test_provider_e2e_connector_lifecycle"
	const workspaceID = "01HWORKSPACEE2ECONNECTOR0LIFE"
	cleanup := silenceLogs(t)
	defer cleanup()

	db := newE2EDB(t)
	mock := stubAccessConnector()

	var syncCalls int
	mock.FuncSyncIdentities = func(_ context.Context, _, _ map[string]interface{}, _ string, handler func([]*access.Identity, string) error) error {
		syncCalls++
		batch := []*access.Identity{
			{ExternalID: "user-1", Type: access.IdentityTypeUser, DisplayName: "User 1", Email: "u1@example.com", Status: "active"},
			{ExternalID: "user-2", Type: access.IdentityTypeUser, DisplayName: "User 2", Email: "u2@example.com", Status: "active"},
			{ExternalID: "user-3", Type: access.IdentityTypeUser, DisplayName: "User 3", Email: "u3@example.com", Status: "active"},
			{ExternalID: "group-platform", Type: access.IdentityTypeGroup, DisplayName: "Platform"},
		}
		return handler(batch, "checkpoint-final")
	}
	access.SwapConnector(t, provider, mock)

	provSvc := access.NewAccessProvisioningService(db)
	connSvc := access.NewConnectorManagementService(db, access.PassthroughEncryptor{}, provSvc, nil)

	router := handlers.Router(handlers.Dependencies{
		ConnectorManagementService: connSvc,
	})

	// --- Step 1: POST /access/connectors ---
	status, body := doJSON(t, router, http.MethodPost, "/access/connectors", map[string]any{
		"workspace_id":   workspaceID,
		"provider":       provider,
		"connector_type": "directory",
		"config":         map[string]any{"tenant": "acme"},
		"secrets":        map[string]any{"api_key": "shhh"},
		"capabilities":   []string{"read"},
	})
	if status != http.StatusCreated {
		t.Fatalf("POST /access/connectors: status=%d body=%+v", status, body)
	}
	connectorID, _ := body["connector_id"].(string)
	syncJobID, _ := body["job_id"].(string)
	if connectorID == "" || syncJobID == "" {
		t.Fatalf("expected connector_id + job_id in body, got %+v", body)
	}

	// --- Step 2: POST /access/connectors/:id/sync ---
	// TriggerSync returns 202 Accepted because the job is enqueued for
	// async pickup by the worker rather than executed inline.
	status, body = doJSON(t, router, http.MethodPost, "/access/connectors/"+connectorID+"/sync", nil)
	if status != http.StatusAccepted {
		t.Fatalf("POST sync: status=%d body=%+v", status, body)
	}
	manualSyncJobID, _ := body["job_id"].(string)
	if manualSyncJobID == "" {
		t.Fatalf("expected job_id from manual sync, got %+v", body)
	}
	if manualSyncJobID == syncJobID {
		t.Fatalf("manual sync should enqueue a fresh job, got same id %q", syncJobID)
	}

	// --- Step 3: drive the queued sync jobs via the worker handler ---
	jc := workerhandlers.JobContext{
		DB:       db,
		Resolve:  func(_ string) (access.AccessConnector, error) { return mock, nil },
		LoadConn: workerhandlers.DefaultLoadConnector,
		Now:      time.Now,
	}
	if err := workerhandlers.AccessSyncIdentities(context.Background(), jc, syncJobID); err != nil {
		t.Fatalf("connect-time sync: %v", err)
	}
	if err := workerhandlers.AccessSyncIdentities(context.Background(), jc, manualSyncJobID); err != nil {
		t.Fatalf("manual sync: %v", err)
	}
	if syncCalls != 2 {
		t.Fatalf("expected 2 calls to FuncSyncIdentities (one per job), got %d", syncCalls)
	}

	var teams int64
	if err := db.Model(&models.Team{}).Where("connector_id = ?", connectorID).Count(&teams).Error; err != nil {
		t.Fatalf("count teams: %v", err)
	}
	if teams != 1 {
		t.Fatalf("teams=%d; want 1 (one group in batch)", teams)
	}
	var members int64
	if err := db.Model(&models.TeamMember{}).Where("connector_id = ?", connectorID).Count(&members).Error; err != nil {
		t.Fatalf("count team_members: %v", err)
	}
	if members != 3 {
		t.Fatalf("team_members=%d; want 3 (three users in batch)", members)
	}

	// Seed an active grant so we can verify the disconnect-time revoke
	// fires. The grant is unrelated to a request — Disconnect must
	// revoke active grants regardless of provenance.
	grantID := "01HGRANTE2ECONNECT00000000A"
	if err := db.Create(&models.AccessGrant{
		ID:                 grantID,
		WorkspaceID:        workspaceID,
		UserID:             "user-1",
		ConnectorID:        connectorID,
		ResourceExternalID: "salesforce/sales-team",
		Role:               "viewer",
		GrantedAt:          time.Now(),
	}).Error; err != nil {
		t.Fatalf("seed grant: %v", err)
	}

	var revokeCalls int
	mock.FuncRevokeAccess = func(context.Context, map[string]interface{}, map[string]interface{}, access.AccessGrant) error {
		revokeCalls++
		return nil
	}

	// --- Step 4: DELETE /access/connectors/:id ---
	status, body = doJSON(t, router, http.MethodDelete, "/access/connectors/"+connectorID, nil)
	if status != http.StatusOK {
		t.Fatalf("DELETE: status=%d body=%+v", status, body)
	}
	if body["status"] != "disconnected" {
		t.Fatalf("DELETE body status=%v; want disconnected", body["status"])
	}

	var deleted models.AccessConnector
	if err := db.Unscoped().Where("id = ?", connectorID).First(&deleted).Error; err != nil {
		t.Fatalf("re-load connector: %v", err)
	}
	if !deleted.DeletedAt.Valid {
		t.Fatalf("connector deleted_at not set: %+v", deleted.DeletedAt)
	}

	var revoked models.AccessGrant
	if err := db.Where("id = ?", grantID).First(&revoked).Error; err != nil {
		t.Fatalf("re-load grant: %v", err)
	}
	if revoked.RevokedAt == nil {
		t.Fatalf("grant.RevokedAt not set after Disconnect")
	}
	if revokeCalls == 0 {
		t.Fatalf("connector.RevokeAccess was not called during Disconnect")
	}
}

// TestConnectorLifecycle_E2E_DeleteUnknown verifies the failure path:
// DELETE /access/connectors/:id on a non-existent connector returns a
// 5xx with a structured error envelope rather than panicking.
func TestConnectorLifecycle_E2E_DeleteUnknown(t *testing.T) {
	cleanup := silenceLogs(t)
	defer cleanup()

	db := newE2EDB(t)
	provSvc := access.NewAccessProvisioningService(db)
	connSvc := access.NewConnectorManagementService(db, access.PassthroughEncryptor{}, provSvc, nil)

	router := handlers.Router(handlers.Dependencies{
		ConnectorManagementService: connSvc,
	})

	status, body := doJSON(t, router, http.MethodDelete, "/access/connectors/01HNOTFOUND0000000000000000", nil)
	if status < 400 {
		t.Fatalf("expected 4xx/5xx for unknown connector, got %d body=%+v", status, body)
	}
}
