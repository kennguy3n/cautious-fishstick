package access

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// newProvisioningTestDB returns a fresh in-memory SQLite DB with all
// Phase 0–2 tables migrated. Provisioning tests need access_connectors in
// addition to the four Phase 2 tables because lookupProvider reads the
// connector row to resolve the provider key.
func newProvisioningTestDB(t *testing.T) *gorm.DB {
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

// seedConnector inserts an access_connectors row pointing at the provided
// provider key. Tests use a unique key per case so SwapConnector can wire
// a mock without colliding with the production registry.
func seedConnector(t *testing.T, db *gorm.DB, provider string) *models.AccessConnector {
	t.Helper()
	conn := &models.AccessConnector{
		ID:            "01H000000000000000CONNECTOR",
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

// approvedRequest creates a request and immediately approves it — the
// canonical "ready to be provisioned" starting state.
func approvedRequest(t *testing.T, db *gorm.DB, connectorID string) *models.AccessRequest {
	t.Helper()
	svc := NewAccessRequestService(db)
	in := validInput()
	in.ConnectorID = connectorID
	req, err := svc.CreateRequest(context.Background(), in)
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	if err := svc.ApproveRequest(context.Background(), req.ID, "manager", "ok"); err != nil {
		t.Fatalf("ApproveRequest: %v", err)
	}
	// Reload from DB so the test sees the up-to-date State column.
	var fresh models.AccessRequest
	if err := db.Where("id = ?", req.ID).First(&fresh).Error; err != nil {
		t.Fatalf("reload request: %v", err)
	}
	return &fresh
}

// TestProvision_HappyPath drives the standard approved → provisioning →
// provisioned flow with a mock connector and asserts the grant row
// exists at the end.
func TestProvision_HappyPath(t *testing.T) {
	const provider = "mock_provision_happy"
	db := newProvisioningTestDB(t)
	conn := seedConnector(t, db, provider)
	req := approvedRequest(t, db, conn.ID)

	mock := &MockAccessConnector{}
	SwapConnector(t, provider, mock)

	svc := NewAccessProvisioningService(db)
	if err := svc.Provision(context.Background(), req, nil, nil); err != nil {
		t.Fatalf("Provision: %v", err)
	}

	if mock.ProvisionAccessCalls != 1 {
		t.Errorf("ProvisionAccess calls = %d; want 1", mock.ProvisionAccessCalls)
	}

	var stored models.AccessRequest
	if err := db.Where("id = ?", req.ID).First(&stored).Error; err != nil {
		t.Fatalf("reload request: %v", err)
	}
	if stored.State != models.RequestStateProvisioned {
		t.Errorf("State = %q; want %q", stored.State, models.RequestStateProvisioned)
	}

	var grants []models.AccessGrant
	if err := db.Where("request_id = ?", req.ID).Find(&grants).Error; err != nil {
		t.Fatalf("read grants: %v", err)
	}
	if len(grants) != 1 {
		t.Fatalf("grants = %d; want 1", len(grants))
	}
	g := grants[0]
	if g.UserID != req.TargetUserID {
		t.Errorf("grant UserID = %q; want %q", g.UserID, req.TargetUserID)
	}
	if g.Role != req.Role {
		t.Errorf("grant Role = %q; want %q", g.Role, req.Role)
	}
	if g.RevokedAt != nil {
		t.Errorf("grant RevokedAt = %v; want nil", g.RevokedAt)
	}

	// State-history should now show: ""→requested, requested→approved,
	// approved→provisioning, provisioning→provisioned.
	var history []models.AccessRequestStateHistory
	if err := db.Where("request_id = ?", req.ID).Order("created_at asc").Find(&history).Error; err != nil {
		t.Fatalf("read history: %v", err)
	}
	wantStates := []string{"", "requested", "approved", "provisioning"}
	wantTo := []string{"requested", "approved", "provisioning", "provisioned"}
	if len(history) != len(wantStates) {
		t.Fatalf("history rows = %d; want %d", len(history), len(wantStates))
	}
	for i := range wantStates {
		if history[i].FromState != wantStates[i] || history[i].ToState != wantTo[i] {
			t.Errorf("history[%d] = %q -> %q; want %q -> %q", i, history[i].FromState, history[i].ToState, wantStates[i], wantTo[i])
		}
	}
}

// TestProvision_ConnectorErrorTransitionsToProvisionFailed asserts that a
// connector error flips the request to provision_failed (recoverable) and
// records the error in the history Reason column. No grant row should be
// created.
func TestProvision_ConnectorErrorTransitionsToProvisionFailed(t *testing.T) {
	const provider = "mock_provision_err"
	db := newProvisioningTestDB(t)
	conn := seedConnector(t, db, provider)
	req := approvedRequest(t, db, conn.ID)

	connectorErr := fmt.Errorf("upstream 502")
	mock := &MockAccessConnector{
		FuncProvisionAccess: func(ctx context.Context, _, _ map[string]interface{}, _ AccessGrant) error {
			return connectorErr
		},
	}
	SwapConnector(t, provider, mock)

	svc := NewAccessProvisioningService(db)
	err := svc.Provision(context.Background(), req, nil, nil)
	if err == nil {
		t.Fatal("Provision returned nil; want connector error")
	}
	if !errors.Is(err, connectorErr) {
		t.Errorf("err = %v; want it to wrap %v", err, connectorErr)
	}

	var stored models.AccessRequest
	if err := db.Where("id = ?", req.ID).First(&stored).Error; err != nil {
		t.Fatalf("reload request: %v", err)
	}
	if stored.State != models.RequestStateProvisionFailed {
		t.Errorf("State = %q; want %q", stored.State, models.RequestStateProvisionFailed)
	}

	var grants []models.AccessGrant
	if err := db.Where("request_id = ?", req.ID).Find(&grants).Error; err != nil {
		t.Fatalf("read grants: %v", err)
	}
	if len(grants) != 0 {
		t.Errorf("grants = %d; want 0 on failure", len(grants))
	}

	// The most recent history row should record the error reason.
	var history []models.AccessRequestStateHistory
	if err := db.Where("request_id = ?", req.ID).Order("created_at desc").Limit(1).Find(&history).Error; err != nil {
		t.Fatalf("read history: %v", err)
	}
	if len(history) == 0 {
		t.Fatal("expected at least one history row")
	}
	if history[0].ToState != models.RequestStateProvisionFailed {
		t.Errorf("latest history ToState = %q; want %q", history[0].ToState, models.RequestStateProvisionFailed)
	}
	if history[0].Reason == "" || history[0].Reason == "provision succeeded" {
		t.Errorf("latest history Reason = %q; want it to mention the error", history[0].Reason)
	}
}

// TestProvision_UnknownProviderReturnsConnectorNotFound covers the case
// where access_connectors carries a provider key no init() side-effect has
// wired. The request must NOT advance to "provisioning" — fail fast.
func TestProvision_UnknownProviderReturnsConnectorNotFound(t *testing.T) {
	const provider = "totally_not_registered_xyz"
	db := newProvisioningTestDB(t)
	conn := seedConnector(t, db, provider)
	req := approvedRequest(t, db, conn.ID)

	svc := NewAccessProvisioningService(db)
	err := svc.Provision(context.Background(), req, nil, nil)
	if err == nil {
		t.Fatal("Provision returned nil; want ErrConnectorNotFound")
	}
	if !errors.Is(err, ErrConnectorNotFound) {
		t.Errorf("err = %v; want ErrConnectorNotFound", err)
	}

	// Request must still be in "approved" (the initial state); we
	// rejected before any state mutation.
	var stored models.AccessRequest
	if err := db.Where("id = ?", req.ID).First(&stored).Error; err != nil {
		t.Fatalf("reload request: %v", err)
	}
	if stored.State != models.RequestStateApproved {
		t.Errorf("State = %q; want %q (no mutation on connector lookup failure)", stored.State, models.RequestStateApproved)
	}
}

// TestProvision_ConnectorRowMissingReturnsConnectorNotFound covers the
// "the access_connectors row was deleted between approval and
// provisioning" race.
func TestProvision_ConnectorRowMissingReturnsConnectorNotFound(t *testing.T) {
	db := newProvisioningTestDB(t)
	// No seedConnector — request points at a nonexistent connector ID.
	req := &models.AccessRequest{
		ID:                 "01H000000000000000REQABCDEFG",
		WorkspaceID:        "01H000000000000000WORKSPACE",
		RequesterUserID:    "01H000000000000000REQUESTER",
		TargetUserID:       "01H000000000000000TARGETUSR",
		ConnectorID:        "01H000000000000000MISSINGCN",
		ResourceExternalID: "projects/foo",
		Role:               "viewer",
		State:              models.RequestStateApproved,
	}
	if err := db.Create(req).Error; err != nil {
		t.Fatalf("seed request: %v", err)
	}

	svc := NewAccessProvisioningService(db)
	err := svc.Provision(context.Background(), req, nil, nil)
	if err == nil {
		t.Fatal("Provision returned nil; want ErrConnectorNotFound")
	}
	if !errors.Is(err, ErrConnectorNotFound) {
		t.Errorf("err = %v; want ErrConnectorNotFound", err)
	}
}

// TestRevoke_HappyPath asserts that a successful Revoke calls the
// connector and stamps RevokedAt on the grant.
func TestRevoke_HappyPath(t *testing.T) {
	const provider = "mock_revoke_happy"
	db := newProvisioningTestDB(t)
	conn := seedConnector(t, db, provider)

	grant := &models.AccessGrant{
		ID:                 "01H000000000000000GRANTABCDE",
		WorkspaceID:        "01H000000000000000WORKSPACE",
		UserID:             "01H000000000000000USERABCDEF",
		ConnectorID:        conn.ID,
		ResourceExternalID: "projects/foo",
		Role:               "viewer",
	}
	if err := db.Create(grant).Error; err != nil {
		t.Fatalf("seed grant: %v", err)
	}

	mock := &MockAccessConnector{}
	SwapConnector(t, provider, mock)

	svc := NewAccessProvisioningService(db)
	if err := svc.Revoke(context.Background(), grant, nil, nil); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if mock.RevokeAccessCalls != 1 {
		t.Errorf("RevokeAccess calls = %d; want 1", mock.RevokeAccessCalls)
	}
	if grant.RevokedAt == nil {
		t.Errorf("grant.RevokedAt = nil after Revoke; want non-nil")
	}

	var stored models.AccessGrant
	if err := db.Where("id = ?", grant.ID).First(&stored).Error; err != nil {
		t.Fatalf("reload grant: %v", err)
	}
	if stored.RevokedAt == nil {
		t.Errorf("stored RevokedAt = nil; want non-nil")
	}
}

// TestRevoke_ConnectorErrorReturnsError asserts that a connector failure
// surfaces and the grant is not stamped revoked. Operators can retry.
func TestRevoke_ConnectorErrorReturnsError(t *testing.T) {
	const provider = "mock_revoke_err"
	db := newProvisioningTestDB(t)
	conn := seedConnector(t, db, provider)

	grant := &models.AccessGrant{
		ID:                 "01H000000000000000GRANTREVKE",
		WorkspaceID:        "01H000000000000000WORKSPACE",
		UserID:             "01H000000000000000USERABCDEF",
		ConnectorID:        conn.ID,
		ResourceExternalID: "projects/foo",
		Role:               "viewer",
	}
	if err := db.Create(grant).Error; err != nil {
		t.Fatalf("seed grant: %v", err)
	}

	connectorErr := fmt.Errorf("upstream 503")
	mock := &MockAccessConnector{
		FuncRevokeAccess: func(ctx context.Context, _, _ map[string]interface{}, _ AccessGrant) error {
			return connectorErr
		},
	}
	SwapConnector(t, provider, mock)

	svc := NewAccessProvisioningService(db)
	err := svc.Revoke(context.Background(), grant, nil, nil)
	if err == nil {
		t.Fatal("Revoke returned nil; want connector error")
	}
	if !errors.Is(err, connectorErr) {
		t.Errorf("err = %v; want it to wrap %v", err, connectorErr)
	}
	if grant.RevokedAt != nil {
		t.Errorf("grant.RevokedAt = %v on connector failure; want nil", grant.RevokedAt)
	}
}

// TestRevoke_AlreadyRevokedReturnsErrAlreadyRevoked covers the
// double-revoke programmer error.
func TestRevoke_AlreadyRevokedReturnsErrAlreadyRevoked(t *testing.T) {
	db := newProvisioningTestDB(t)
	already := approvedRequest(t, db, seedConnector(t, db, "noop_provider").ID)
	revokedAt := already.CreatedAt
	grant := &models.AccessGrant{
		ID:                 "01H000000000000000GRANTDONE0",
		WorkspaceID:        "01H000000000000000WORKSPACE",
		UserID:             "01H000000000000000USERABCDEF",
		ConnectorID:        already.ConnectorID,
		ResourceExternalID: "projects/foo",
		Role:               "viewer",
		RevokedAt:          &revokedAt,
	}
	if err := db.Create(grant).Error; err != nil {
		t.Fatalf("seed grant: %v", err)
	}

	svc := NewAccessProvisioningService(db)
	err := svc.Revoke(context.Background(), grant, nil, nil)
	if !errors.Is(err, ErrAlreadyRevoked) {
		t.Errorf("err = %v; want ErrAlreadyRevoked", err)
	}
}

// TestProvision_NilRequestReturnsValidation guards the trivial nil-pointer
// path so a future refactor can't quietly reintroduce it.
func TestProvision_NilRequestReturnsValidation(t *testing.T) {
	db := newProvisioningTestDB(t)
	svc := NewAccessProvisioningService(db)
	err := svc.Provision(context.Background(), nil, nil, nil)
	if !errors.Is(err, ErrValidation) {
		t.Errorf("err = %v; want ErrValidation", err)
	}
}

// TestRevoke_NilGrantReturnsValidation mirrors TestProvision_NilRequest.
func TestRevoke_NilGrantReturnsValidation(t *testing.T) {
	db := newProvisioningTestDB(t)
	svc := NewAccessProvisioningService(db)
	err := svc.Revoke(context.Background(), nil, nil, nil)
	if !errors.Is(err, ErrValidation) {
		t.Errorf("err = %v; want ErrValidation", err)
	}
}
