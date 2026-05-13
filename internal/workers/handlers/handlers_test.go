package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

// --- Helpers ---

func newHandlerDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(
		&models.AccessJob{},
		&models.AccessConnector{},
		&models.AccessSyncState{},
		&models.AccessGrantEntitlement{},
		&models.Team{},
		&models.TeamMember{},
	); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}
	return db
}

func seedJob(t *testing.T, db *gorm.DB, id, connectorID, jobType string, payload interface{}) {
	t.Helper()
	var raw []byte
	if payload != nil {
		var err error
		raw, err = json.Marshal(payload)
		if err != nil {
			t.Fatalf("marshal payload: %v", err)
		}
	}
	row := &models.AccessJob{
		ID:          id,
		ConnectorID: connectorID,
		JobType:     jobType,
		Status:      models.AccessJobStatusPending,
		Payload:     raw,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
	if err := db.Create(row).Error; err != nil {
		t.Fatalf("seed job: %v", err)
	}
}

func seedTestConnector(t *testing.T, db *gorm.DB, id, provider string) {
	t.Helper()
	row := &models.AccessConnector{
		ID:            id,
		WorkspaceID:   "01HWORKSPACE0000000000000A",
		Provider:      provider,
		ConnectorType: "test",
		Config:        []byte(`{}`),
		Credentials:   `{}`,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
	if err := db.Create(row).Error; err != nil {
		t.Fatalf("seed connector: %v", err)
	}
}

// stubResolve returns a ConnectorResolver that always returns the
// supplied connector.
func stubResolve(conn access.AccessConnector) ConnectorResolver {
	return func(_ string) (access.AccessConnector, error) {
		return conn, nil
	}
}

func newJC(db *gorm.DB, conn access.AccessConnector) JobContext {
	return JobContext{
		DB:       db,
		Resolve:  stubResolve(conn),
		LoadConn: DefaultLoadConnector,
		Now:      time.Now,
	}
}

func readJob(t *testing.T, db *gorm.DB, id string) models.AccessJob {
	t.Helper()
	var j models.AccessJob
	if err := db.Where("id = ?", id).First(&j).Error; err != nil {
		t.Fatalf("readback job %s: %v", id, err)
	}
	return j
}

// --- Tests: AccessSyncIdentities ---

func TestAccessSyncIdentities_HappyPath(t *testing.T) {
	db := newHandlerDB(t)
	seedTestConnector(t, db, "01HCONN00000000000000000001", "test_provider")
	seedJob(t, db, "01HJOB000000000000000000001", "01HCONN00000000000000000001", models.AccessJobTypeSyncIdentities, nil)

	called := false
	mock := &access.MockAccessConnector{
		FuncSyncIdentities: func(_ context.Context, _, _ map[string]interface{}, _ string, handler func([]*access.Identity, string) error) error {
			called = true
			return handler([]*access.Identity{{ExternalID: "u-1"}}, "next-cp")
		},
	}
	if err := AccessSyncIdentities(context.Background(), newJC(db, mock), "01HJOB000000000000000000001"); err != nil {
		t.Fatalf("AccessSyncIdentities: %v", err)
	}
	if !called {
		t.Error("SyncIdentities was not called on the connector")
	}
	j := readJob(t, db, "01HJOB000000000000000000001")
	if j.Status != models.AccessJobStatusCompleted {
		t.Errorf("status = %q; want completed", j.Status)
	}
	if j.CompletedAt == nil {
		t.Error("completed_at is nil; want non-nil")
	}
	if j.StartedAt == nil {
		t.Error("started_at is nil; want non-nil")
	}
}

func TestAccessSyncIdentities_ConnectorError_JobFailed(t *testing.T) {
	db := newHandlerDB(t)
	seedTestConnector(t, db, "01HCONN00000000000000000002", "test_provider")
	seedJob(t, db, "01HJOB000000000000000000002", "01HCONN00000000000000000002", models.AccessJobTypeSyncIdentities, nil)

	mock := &access.MockAccessConnector{
		FuncSyncIdentities: func(_ context.Context, _, _ map[string]interface{}, _ string, _ func([]*access.Identity, string) error) error {
			return errors.New("rate limited")
		},
	}
	err := AccessSyncIdentities(context.Background(), newJC(db, mock), "01HJOB000000000000000000002")
	if err == nil {
		t.Fatal("expected error from sync")
	}
	j := readJob(t, db, "01HJOB000000000000000000002")
	if j.Status != models.AccessJobStatusFailed {
		t.Errorf("status = %q; want failed", j.Status)
	}
	if j.LastError == "" {
		t.Error("last_error is empty; want error message")
	}
}

// --- Tests: AccessProvision ---

func TestAccessProvision_HappyPath(t *testing.T) {
	db := newHandlerDB(t)
	seedTestConnector(t, db, "01HCONN00000000000000000003", "test_provider")
	payload := provisionAccessPayload{
		UserExternalID:     "alice",
		ResourceExternalID: "repo-1",
		Role:               "admin",
	}
	seedJob(t, db, "01HJOB000000000000000000003", "01HCONN00000000000000000003", models.AccessJobTypeProvisionAccess, payload)

	var captured access.AccessGrant
	mock := &access.MockAccessConnector{
		FuncProvisionAccess: func(_ context.Context, _, _ map[string]interface{}, g access.AccessGrant) error {
			captured = g
			return nil
		},
	}
	if err := AccessProvision(context.Background(), newJC(db, mock), "01HJOB000000000000000000003"); err != nil {
		t.Fatalf("AccessProvision: %v", err)
	}
	if captured.UserExternalID != "alice" || captured.Role != "admin" {
		t.Errorf("captured = %+v; want alice/admin", captured)
	}
	j := readJob(t, db, "01HJOB000000000000000000003")
	if j.Status != models.AccessJobStatusCompleted {
		t.Errorf("status = %q; want completed", j.Status)
	}
}

func TestAccessProvision_ConnectorError_JobFailed(t *testing.T) {
	db := newHandlerDB(t)
	seedTestConnector(t, db, "01HCONN00000000000000000004", "test_provider")
	payload := provisionAccessPayload{UserExternalID: "bob", ResourceExternalID: "r1", Role: "viewer"}
	seedJob(t, db, "01HJOB000000000000000000004", "01HCONN00000000000000000004", models.AccessJobTypeProvisionAccess, payload)

	mock := &access.MockAccessConnector{
		FuncProvisionAccess: func(_ context.Context, _, _ map[string]interface{}, _ access.AccessGrant) error {
			return errors.New("forbidden")
		},
	}
	err := AccessProvision(context.Background(), newJC(db, mock), "01HJOB000000000000000000004")
	if err == nil {
		t.Fatal("expected error")
	}
	j := readJob(t, db, "01HJOB000000000000000000004")
	if j.Status != models.AccessJobStatusFailed {
		t.Errorf("status = %q; want failed", j.Status)
	}
}

// --- Tests: AccessRevoke ---

func TestAccessRevoke_HappyPath(t *testing.T) {
	db := newHandlerDB(t)
	seedTestConnector(t, db, "01HCONN00000000000000000005", "test_provider")
	payload := revokeAccessPayload{UserExternalID: "alice", ResourceExternalID: "r1", Role: "admin"}
	seedJob(t, db, "01HJOB000000000000000000005", "01HCONN00000000000000000005", models.AccessJobTypeRevokeAccess, payload)

	mock := &access.MockAccessConnector{}
	if err := AccessRevoke(context.Background(), newJC(db, mock), "01HJOB000000000000000000005"); err != nil {
		t.Fatalf("AccessRevoke: %v", err)
	}
	if mock.RevokeAccessCalls != 1 {
		t.Errorf("RevokeAccessCalls = %d; want 1", mock.RevokeAccessCalls)
	}
	j := readJob(t, db, "01HJOB000000000000000000005")
	if j.Status != models.AccessJobStatusCompleted {
		t.Errorf("status = %q; want completed", j.Status)
	}
}

func TestAccessRevoke_ConnectorError_JobFailed(t *testing.T) {
	db := newHandlerDB(t)
	seedTestConnector(t, db, "01HCONN00000000000000000006", "test_provider")
	payload := revokeAccessPayload{UserExternalID: "bob", ResourceExternalID: "r2", Role: "viewer"}
	seedJob(t, db, "01HJOB000000000000000000006", "01HCONN00000000000000000006", models.AccessJobTypeRevokeAccess, payload)

	mock := &access.MockAccessConnector{
		FuncRevokeAccess: func(_ context.Context, _, _ map[string]interface{}, _ access.AccessGrant) error {
			return errors.New("timeout")
		},
	}
	err := AccessRevoke(context.Background(), newJC(db, mock), "01HJOB000000000000000000006")
	if err == nil {
		t.Fatal("expected error")
	}
	j := readJob(t, db, "01HJOB000000000000000000006")
	if j.Status != models.AccessJobStatusFailed {
		t.Errorf("status = %q; want failed", j.Status)
	}
}

// --- Tests: AccessListEntitlements ---

func TestAccessListEntitlements_HappyPath(t *testing.T) {
	db := newHandlerDB(t)
	seedTestConnector(t, db, "01HCONN00000000000000000007", "test_provider")
	payload := listEntitlementsPayload{UserExternalID: "alice"}
	seedJob(t, db, "01HJOB000000000000000000007", "01HCONN00000000000000000007", models.AccessJobTypeListEntitlements, payload)

	mock := &access.MockAccessConnector{
		FuncListEntitlements: func(_ context.Context, _, _ map[string]interface{}, uid string) ([]access.Entitlement, error) {
			if uid != "alice" {
				t.Errorf("uid = %q; want alice", uid)
			}
			return []access.Entitlement{{ResourceExternalID: "r-1", Role: "admin"}}, nil
		},
	}
	if err := AccessListEntitlements(context.Background(), newJC(db, mock), "01HJOB000000000000000000007"); err != nil {
		t.Fatalf("AccessListEntitlements: %v", err)
	}
	j := readJob(t, db, "01HJOB000000000000000000007")
	if j.Status != models.AccessJobStatusCompleted {
		t.Errorf("status = %q; want completed", j.Status)
	}
}

func TestAccessListEntitlements_MissingUserExternalID(t *testing.T) {
	db := newHandlerDB(t)
	seedTestConnector(t, db, "01HCONN00000000000000000008", "test_provider")
	payload := listEntitlementsPayload{UserExternalID: ""}
	seedJob(t, db, "01HJOB000000000000000000008", "01HCONN00000000000000000008", models.AccessJobTypeListEntitlements, payload)

	mock := &access.MockAccessConnector{}
	err := AccessListEntitlements(context.Background(), newJC(db, mock), "01HJOB000000000000000000008")
	if err == nil {
		t.Fatal("expected error for missing user_external_id")
	}
	j := readJob(t, db, "01HJOB000000000000000000008")
	if j.Status != models.AccessJobStatusFailed {
		t.Errorf("status = %q; want failed", j.Status)
	}
}

// --- Tests: runJob / missing dependencies ---

func TestRunJob_MissingDependencies(t *testing.T) {
	err := AccessSyncIdentities(context.Background(), JobContext{}, "bogus")
	if !errors.Is(err, ErrMissingDependency) {
		t.Errorf("err = %v; want ErrMissingDependency", err)
	}
}

func TestRunJob_JobNotFound(t *testing.T) {
	db := newHandlerDB(t)
	mock := &access.MockAccessConnector{}
	err := AccessSyncIdentities(context.Background(), newJC(db, mock), "01HJOB_DOES_NOT_EXIST")
	if err == nil {
		t.Fatal("expected error for missing job")
	}
}
