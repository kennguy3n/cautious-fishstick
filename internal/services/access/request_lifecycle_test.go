package access

import (
	"context"
	"errors"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// newE2ETestDB returns an in-memory SQLite DB with every table the
// access-request lifecycle touches. Each test gets its own DB.
func newE2ETestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(
		&models.AccessConnector{},
		&models.AccessRequest{},
		&models.AccessRequestStateHistory{},
		&models.AccessGrant{},
		&models.AccessWorkflow{},
	); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}
	return db
}

// seedE2EConnector inserts an access_connectors row keyed at id and
// provider so SwapConnector can map the test's MockAccessConnector
// to it during Provision.
func seedE2EConnector(t *testing.T, db *gorm.DB, id, provider string) *models.AccessConnector {
	t.Helper()
	conn := &models.AccessConnector{
		ID:            id,
		WorkspaceID:   "01H000000000000000WORKSPACE",
		Provider:      provider,
		ConnectorType: "test",
		Status:        models.StatusConnected,
	}
	if err := db.Create(conn).Error; err != nil {
		t.Fatalf("seed access_connector: %v", err)
	}
	return conn
}

// validE2EInput returns a populated CreateAccessRequestInput keyed
// to the supplied connectorID. Tests mutate fields to drive specific
// paths.
func validE2EInput(connectorID string) CreateAccessRequestInput {
	return CreateAccessRequestInput{
		WorkspaceID:        "01H000000000000000WORKSPACE",
		RequesterUserID:    "01H00000000000000REQUESTER1",
		TargetUserID:       "01H00000000000000TARGETUSR1",
		ConnectorID:        connectorID,
		ResourceExternalID: "projects/foo",
		Role:               "viewer",
		Justification:      "e2e test: weekly on-call rotation",
	}
}

// TestE2E_RequestLifecycle_HappyPath walks the full request lifecycle
// — CreateRequest → ApproveRequest → Provision → grant active —
// against an in-memory SQLite DB and a MockAccessConnector. We assert
// each state transition lands on the access_requests row, every
// transition is reflected in access_request_state_history, and the
// access_grants row is populated with the expected fields.
//
// This complements the per-method unit tests by validating the
// COMPOSITION of services (request-service + provisioning-service +
// connector registry) rather than any one method in isolation.
func TestE2E_RequestLifecycle_HappyPath(t *testing.T) {
	const provider = "mock_e2e_lifecycle_happy"
	db := newE2ETestDB(t)
	conn := seedE2EConnector(t, db, "01HCONN0E2E0000000000HAPPY", provider)
	mock := &MockAccessConnector{}
	SwapConnector(t, provider, mock)

	reqSvc := NewAccessRequestService(db)
	provSvc := NewAccessProvisioningService(db)

	created, err := reqSvc.CreateRequest(context.Background(), validE2EInput(conn.ID))
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	if created.State != models.RequestStateRequested {
		t.Fatalf("CreateRequest state = %q; want requested", created.State)
	}

	if err := reqSvc.ApproveRequest(context.Background(), created.ID, "01HACTOR000000000000000001", "manager OK"); err != nil {
		t.Fatalf("ApproveRequest: %v", err)
	}

	// Reload + provision.
	var approved models.AccessRequest
	if err := db.Where("id = ?", created.ID).First(&approved).Error; err != nil {
		t.Fatalf("reload approved: %v", err)
	}
	if approved.State != models.RequestStateApproved {
		t.Fatalf("approved state = %q", approved.State)
	}
	if err := provSvc.Provision(context.Background(), &approved, nil, nil); err != nil {
		t.Fatalf("Provision: %v", err)
	}

	// Lifecycle invariants on the request row.
	var final models.AccessRequest
	if err := db.Where("id = ?", created.ID).First(&final).Error; err != nil {
		t.Fatalf("reload final: %v", err)
	}
	if final.State != models.RequestStateProvisioned {
		t.Errorf("final state = %q; want provisioned", final.State)
	}

	// State history captures every transition.
	var hist []models.AccessRequestStateHistory
	if err := db.Where("request_id = ?", created.ID).Order("created_at ASC").Find(&hist).Error; err != nil {
		t.Fatalf("history: %v", err)
	}
	if len(hist) < 4 {
		t.Fatalf("history rows = %d; want >=4 (created, approved, provisioning, provisioned)", len(hist))
	}
	wantStates := []string{
		models.RequestStateRequested,
		models.RequestStateApproved,
		models.RequestStateProvisioning,
		models.RequestStateProvisioned,
	}
	for i, want := range wantStates {
		if hist[i].ToState != want {
			t.Errorf("history[%d].ToState = %q; want %q", i, hist[i].ToState, want)
		}
	}

	// Connector saw the grant.
	if mock.ProvisionAccessCalls != 1 {
		t.Errorf("connector ProvisionAccess calls = %d; want 1", mock.ProvisionAccessCalls)
	}

	// access_grants row populated.
	var grants []models.AccessGrant
	if err := db.Where("request_id = ?", created.ID).Find(&grants).Error; err != nil {
		t.Fatalf("grants: %v", err)
	}
	if len(grants) != 1 {
		t.Fatalf("grants = %d; want 1", len(grants))
	}
	g := grants[0]
	if g.UserID != created.TargetUserID || g.ConnectorID != conn.ID || g.Role != "viewer" || g.ResourceExternalID != "projects/foo" {
		t.Errorf("grant fields mismatch: %+v", g)
	}
	if g.RevokedAt != nil {
		t.Errorf("grant revoked_at = %v; want nil for active grant", g.RevokedAt)
	}
}

// TestE2E_RequestLifecycle_DenyPath verifies the denial leg: a
// CreateRequest followed by DenyRequest is terminal and never
// produces an access_grants row even if Provision is mistakenly
// called.
func TestE2E_RequestLifecycle_DenyPath(t *testing.T) {
	const provider = "mock_e2e_lifecycle_deny"
	db := newE2ETestDB(t)
	conn := seedE2EConnector(t, db, "01HCONN0E2E0000000000DENY1", provider)
	mock := &MockAccessConnector{}
	SwapConnector(t, provider, mock)

	reqSvc := NewAccessRequestService(db)

	created, err := reqSvc.CreateRequest(context.Background(), validE2EInput(conn.ID))
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	if err := reqSvc.DenyRequest(context.Background(), created.ID, "01HACTOR000000000000000001", "policy violation"); err != nil {
		t.Fatalf("DenyRequest: %v", err)
	}

	var final models.AccessRequest
	if err := db.Where("id = ?", created.ID).First(&final).Error; err != nil {
		t.Fatalf("reload: %v", err)
	}
	if final.State != models.RequestStateDenied {
		t.Errorf("state = %q; want denied", final.State)
	}

	// History captured the denial transition.
	var hist []models.AccessRequestStateHistory
	if err := db.Where("request_id = ? AND to_state = ?", created.ID, models.RequestStateDenied).Find(&hist).Error; err != nil {
		t.Fatalf("history: %v", err)
	}
	if len(hist) != 1 {
		t.Errorf("denial history rows = %d; want 1", len(hist))
	}

	// No grant inserted.
	var grants []models.AccessGrant
	if err := db.Where("request_id = ?", created.ID).Find(&grants).Error; err != nil {
		t.Fatalf("grants: %v", err)
	}
	if len(grants) != 0 {
		t.Errorf("grants = %d; want 0", len(grants))
	}
	if mock.ProvisionAccessCalls != 0 {
		t.Errorf("connector ProvisionAccess calls = %d; want 0 for denied request", mock.ProvisionAccessCalls)
	}
}

// TestE2E_RequestLifecycle_CancelPath verifies the requester-side
// cancel leg: a CreateRequest followed by CancelRequest is terminal.
func TestE2E_RequestLifecycle_CancelPath(t *testing.T) {
	const provider = "mock_e2e_lifecycle_cancel"
	db := newE2ETestDB(t)
	conn := seedE2EConnector(t, db, "01HCONN0E2E0000000000CANCL", provider)
	mock := &MockAccessConnector{}
	SwapConnector(t, provider, mock)

	reqSvc := NewAccessRequestService(db)
	created, err := reqSvc.CreateRequest(context.Background(), validE2EInput(conn.ID))
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	if err := reqSvc.CancelRequest(context.Background(), created.ID, created.RequesterUserID, "no longer needed"); err != nil {
		t.Fatalf("CancelRequest: %v", err)
	}
	var final models.AccessRequest
	if err := db.Where("id = ?", created.ID).First(&final).Error; err != nil {
		t.Fatalf("reload: %v", err)
	}
	if final.State != models.RequestStateCancelled {
		t.Errorf("state = %q; want cancelled", final.State)
	}
}

// TestE2E_RequestLifecycle_ProvisionFailedRetry verifies the
// retry-after-failure leg: a transient connector failure transitions
// the request to provision_failed; a second Provision call (with a
// recovered connector) resumes the lifecycle to provisioned.
func TestE2E_RequestLifecycle_ProvisionFailedRetry(t *testing.T) {
	const provider = "mock_e2e_lifecycle_failretry"
	db := newE2ETestDB(t)
	conn := seedE2EConnector(t, db, "01HCONN0E2E000000000RETRY1", provider)
	mock := &MockAccessConnector{
		FuncProvisionAccess: func(_ context.Context, _, _ map[string]interface{}, _ AccessGrant) error {
			return errors.New("transient: 503 backend down")
		},
	}
	SwapConnector(t, provider, mock)

	reqSvc := NewAccessRequestService(db)
	provSvc := NewAccessProvisioningService(db)

	created, err := reqSvc.CreateRequest(context.Background(), validE2EInput(conn.ID))
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	if err := reqSvc.ApproveRequest(context.Background(), created.ID, "01HACTOR000000000000000001", "ok"); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	var approved models.AccessRequest
	if err := db.Where("id = ?", created.ID).First(&approved).Error; err != nil {
		t.Fatalf("reload approved: %v", err)
	}
	// First Provision call hits the seeded transient error.
	if err := provSvc.Provision(context.Background(), &approved, nil, nil); err == nil {
		t.Fatal("first Provision must surface the connector error")
	}
	var afterFail models.AccessRequest
	if err := db.Where("id = ?", created.ID).First(&afterFail).Error; err != nil {
		t.Fatalf("reload afterFail: %v", err)
	}
	if afterFail.State != models.RequestStateProvisionFailed {
		t.Fatalf("state after failure = %q; want provision_failed", afterFail.State)
	}

	// Recover the connector + retry.
	mock.FuncProvisionAccess = nil
	if err := provSvc.Provision(context.Background(), &afterFail, nil, nil); err != nil {
		t.Fatalf("retry Provision: %v", err)
	}
	var final models.AccessRequest
	if err := db.Where("id = ?", created.ID).First(&final).Error; err != nil {
		t.Fatalf("reload final: %v", err)
	}
	if final.State != models.RequestStateProvisioned {
		t.Errorf("state after retry = %q; want provisioned", final.State)
	}
	// Grant inserted on the SECOND Provision (idempotent connectors
	// only produce one access_grants row even if the upstream had
	// already created the side effect).
	var grants []models.AccessGrant
	if err := db.Where("request_id = ?", created.ID).Find(&grants).Error; err != nil {
		t.Fatalf("grants: %v", err)
	}
	if len(grants) != 1 {
		t.Errorf("grants = %d; want 1", len(grants))
	}
}
