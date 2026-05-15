package integration_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/handlers"
	"github.com/kennguy3n/cautious-fishstick/internal/models"
	"github.com/kennguy3n/cautious-fishstick/internal/pkg/database"
	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

// TestProductionWiring_Smoke is the "do the three binaries actually
// boot end-to-end" gate. It mirrors the wiring cmd/ztna-api/main.go
// performs at startup: open a DB, run every migration in
// internal/migrations, construct the full service set, wire them into
// handlers.Dependencies and serve the router.
//
// The test runs against an in-memory SQLite (no external Postgres) so
// it can run on every `go test ./...` invocation in CI. Migrations
// are AutoMigrate-based and SQLite-compatible per
// internal/migrations/migrations_test.go.
//
// The smoke run drives a minimal business flow:
//
//  1. seed an access_connectors row (the same way the connector
//     lifecycle E2E does — POST /access/connectors is exercised
//     separately in connector_lifecycle_e2e_test.go),
//  2. create an access request via the real service constructors,
//     approve it, provision through the real provisioning service,
//  3. list active grants through the real query service,
//  4. revoke the grant and confirm the grant transitions to revoked.
//
// If any of these layers regresses on its constructor signature, the
// real production wiring path stops compiling and this test stops
// compiling with it — which is the whole point.
func TestProductionWiring_Smoke(t *testing.T) {
	const provider = "test_provider_smoke_wiring"
	const workspaceID = "01HWORKSPACEPRODUCTIONWIRESM"
	cleanup := silenceLogs(t)
	defer cleanup()

	// Step 1 — open SQLite and run the same migrations the production
	// binaries run. database.RunMigrations is the helper
	// cmd/ztna-api and cmd/access-connector-worker both call at
	// boot, so exercising it here keeps the helper from drifting.
	db, err := gorm.Open(sqlite.Open(":memory:?cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := database.RunMigrations(db); err != nil {
		t.Fatalf("run migrations: %v", err)
	}

	// Step 2 — construct the full service set the production binary
	// wires. Any constructor that changes signature breaks the
	// compile, which is exactly the regression this test is here to
	// catch.
	encryptor := access.PassthroughEncryptor{}
	policySvc := access.NewPolicyService(db)
	requestSvc := access.NewAccessRequestService(db)
	provSvc := access.NewAccessProvisioningService(db)
	reviewSvc := access.NewAccessReviewService(db, provSvc)
	connMgmtSvc := access.NewConnectorManagementService(db, encryptor, provSvc, nil)
	connListSvc := access.NewAccessConnectorListService(db)
	credLoader := access.NewConnectorCredentialsLoader(db, encryptor)
	orphanReconciler := access.NewOrphanReconciler(db, provSvc, credLoader)
	jmlSvc := access.NewJMLService(db, provSvc)
	grantQuerySvc := access.NewAccessGrantQueryService(db)

	// Cheap presence assertions — every service must be non-nil for
	// the production wiring to be considered live.
	for name, svc := range map[string]any{
		"PolicyService":              policySvc,
		"AccessRequestService":       requestSvc,
		"AccessProvisioningService":  provSvc,
		"AccessReviewService":        reviewSvc,
		"ConnectorManagementService": connMgmtSvc,
		"AccessConnectorListService": connListSvc,
		"ConnectorCredentialsLoader": credLoader,
		"OrphanReconciler":           orphanReconciler,
		"JMLService":                 jmlSvc,
		"AccessGrantQueryService":    grantQuerySvc,
	} {
		if svc == nil {
			t.Fatalf("constructor returned nil: %s", name)
		}
	}

	// Step 3 — assemble Dependencies and build the router. This is
	// the same call shape as cmd/ztna-api/main.go.
	deps := handlers.Dependencies{
		PolicyService:              policySvc,
		AccessRequestService:       requestSvc,
		AccessReviewService:        reviewSvc,
		AccessGrantReader:          &handlers.AccessGrantReaderAdapter{Inner: grantQuerySvc},
		ConnectorManagementService: connMgmtSvc,
		ConnectorListReader:        connListSvc,
		OrphanReconciler:           orphanReconciler,
		JMLService:                 jmlSvc,
	}
	router := handlers.Router(deps)

	// Confirm /health stays reachable.
	status, _ := doJSON(t, router, http.MethodGet, "/health", nil)
	if status != http.StatusOK {
		t.Fatalf("GET /health: status=%d", status)
	}

	// Step 4 — seed a connector and drive a minimal request →
	// approve → provision → list → revoke flow through the real
	// services. The MockAccessConnector keeps the upstream call
	// in-process so the test has no external dependencies.
	mock := stubAccessConnector()
	var provisionCalls, revokeCalls int
	mock.FuncProvisionAccess = func(context.Context, map[string]interface{}, map[string]interface{}, access.AccessGrant) error {
		provisionCalls++
		return nil
	}
	mock.FuncRevokeAccess = func(context.Context, map[string]interface{}, map[string]interface{}, access.AccessGrant) error {
		revokeCalls++
		return nil
	}
	access.SwapConnector(t, provider, mock)

	const connectorID = "01HCONN0SMOKEWIRINGCONNCTOR0"
	if err := db.Create(&models.AccessConnector{
		ID:            connectorID,
		WorkspaceID:   workspaceID,
		Provider:      provider,
		ConnectorType: "test",
		Status:        models.StatusConnected,
	}).Error; err != nil {
		t.Fatalf("seed connector: %v", err)
	}

	ctx := context.Background()
	req, err := requestSvc.CreateRequest(ctx, access.CreateAccessRequestInput{
		WorkspaceID:        workspaceID,
		RequesterUserID:    "user-smoke-requester",
		TargetUserID:       "user-smoke-target",
		ConnectorID:        connectorID,
		ResourceExternalID: "resource-smoke",
		Role:               "viewer",
		Justification:      "smoke test",
	})
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	if req.State != models.RequestStateRequested {
		t.Fatalf("expected state=requested, got %q", req.State)
	}

	if err := requestSvc.ApproveRequest(ctx, req.ID, "approver-smoke", "ok"); err != nil {
		t.Fatalf("ApproveRequest: %v", err)
	}

	// Re-fetch so the Provision call sees the approved state.
	approved := &models.AccessRequest{}
	if err := db.WithContext(ctx).First(approved, "id = ?", req.ID).Error; err != nil {
		t.Fatalf("reload request: %v", err)
	}
	if approved.State != models.RequestStateApproved {
		t.Fatalf("expected state=approved, got %q", approved.State)
	}

	if err := provSvc.Provision(ctx, approved, map[string]interface{}{"tenant": "smoke"}, map[string]interface{}{"api_key": "smoke"}); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if provisionCalls != 1 {
		t.Fatalf("expected exactly one ProvisionAccess call, got %d", provisionCalls)
	}

	userID := approved.TargetUserID
	grants, err := grantQuerySvc.ListActiveGrants(ctx, access.GrantQuery{UserID: &userID})
	if err != nil {
		t.Fatalf("ListActiveGrants: %v", err)
	}
	if len(grants) != 1 {
		t.Fatalf("expected exactly one active grant, got %d", len(grants))
	}
	grant := grants[0]
	if grant.ConnectorID != connectorID {
		t.Fatalf("grant.ConnectorID=%q, want %q", grant.ConnectorID, connectorID)
	}

	if err := provSvc.Revoke(ctx, &grant, map[string]interface{}{"tenant": "smoke"}, map[string]interface{}{"api_key": "smoke"}); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if revokeCalls != 1 {
		t.Fatalf("expected exactly one RevokeAccess call, got %d", revokeCalls)
	}

	postRevoke, err := grantQuerySvc.ListActiveGrants(ctx, access.GrantQuery{UserID: &userID})
	if err != nil {
		t.Fatalf("ListActiveGrants after revoke: %v", err)
	}
	if len(postRevoke) != 0 {
		t.Fatalf("expected zero active grants after revoke, got %d", len(postRevoke))
	}

	// The revoked row should still be persisted with a non-nil
	// RevokedAt so the audit trail is preserved.
	var revokedRow models.AccessGrant
	if err := db.WithContext(ctx).First(&revokedRow, "id = ?", grant.ID).Error; err != nil {
		t.Fatalf("reload revoked grant: %v", err)
	}
	if revokedRow.RevokedAt == nil {
		t.Fatalf("expected revoked_at to be set on revoked grant row")
	}
}
