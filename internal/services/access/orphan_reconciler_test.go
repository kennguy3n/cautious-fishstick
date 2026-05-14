package access

import (
	"context"
	"testing"
	"time"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// TestOrphanReconciler_ReconcileWorkspace_DetectsUnknownUsers
// asserts the happy path: connector reports 3 users, IdP knows 1
// of them, so the reconciler stores 2 new orphan rows.
func TestOrphanReconciler_ReconcileWorkspace_DetectsUnknownUsers(t *testing.T) {
	const provider = "mock_orphan_detect"
	db := newJMLTestDB(t)
	if err := db.AutoMigrate(&models.AccessOrphanAccount{}); err != nil {
		t.Fatalf("automigrate orphan: %v", err)
	}
	conn := seedConnectorWithSecrets(t, db, "01HCONN0ORPHANRECON0000001", provider)

	// Known IdP user (mapped via team_members).
	if err := db.Create(&models.TeamMember{
		ID:          "01HTM0ORPHAN000000000000001",
		TeamID:      "01HTEAM0ORPHAN0000000000001",
		UserID:      "01HUSER0ORPHAN0000000000001",
		ExternalID:  "u-known",
		ConnectorID: conn.ID,
	}).Error; err != nil {
		t.Fatalf("seed team_member: %v", err)
	}

	mock := &MockAccessConnector{
		FuncSyncIdentities: func(_ context.Context, _, _ map[string]interface{}, _ string, h func([]*Identity, string) error) error {
			return h([]*Identity{
				{ExternalID: "u-known", Email: "known@example.com"},
				{ExternalID: "u-orphan-1", Email: "ghost1@example.com"},
				{ExternalID: "u-orphan-2", Email: "ghost2@example.com"},
			}, "")
		},
	}
	SwapConnector(t, provider, mock)

	rec := NewOrphanReconciler(db, NewAccessProvisioningService(db), NewConnectorCredentialsLoader(db, PassthroughEncryptor{}))
	got, err := rec.ReconcileWorkspace(context.Background(), "01H000000000000000WORKSPACE")
	if err != nil {
		t.Fatalf("ReconcileWorkspace: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("orphan rows = %d; want 2 (%v)", len(got), got)
	}

	var rows []models.AccessOrphanAccount
	if err := db.Find(&rows).Error; err != nil {
		t.Fatalf("list orphans: %v", err)
	}
	if len(rows) != 2 {
		t.Errorf("persisted orphans = %d; want 2", len(rows))
	}
	for _, r := range rows {
		if r.Status != models.OrphanStatusDetected {
			t.Errorf("orphan %s status = %q; want %q", r.UserExternalID, r.Status, models.OrphanStatusDetected)
		}
		if r.WorkspaceID != "01H000000000000000WORKSPACE" {
			t.Errorf("orphan %s workspace_id = %q; want workspace id", r.UserExternalID, r.WorkspaceID)
		}
	}
}

// TestOrphanReconciler_ReconcileWorkspace_IsIdempotent asserts a
// second reconciliation pass does not create duplicate rows; it
// just refreshes detected_at.
func TestOrphanReconciler_ReconcileWorkspace_IsIdempotent(t *testing.T) {
	const provider = "mock_orphan_idem"
	db := newJMLTestDB(t)
	if err := db.AutoMigrate(&models.AccessOrphanAccount{}); err != nil {
		t.Fatalf("automigrate orphan: %v", err)
	}
	conn := seedConnectorWithSecrets(t, db, "01HCONN0ORPHANIDEM00000001", provider)
	_ = conn

	mock := &MockAccessConnector{
		FuncSyncIdentities: func(_ context.Context, _, _ map[string]interface{}, _ string, h func([]*Identity, string) error) error {
			return h([]*Identity{{ExternalID: "u-orphan", Email: "g@example.com"}}, "")
		},
	}
	SwapConnector(t, provider, mock)

	rec := NewOrphanReconciler(db, NewAccessProvisioningService(db), NewConnectorCredentialsLoader(db, PassthroughEncryptor{}))
	if _, err := rec.ReconcileWorkspace(context.Background(), "01H000000000000000WORKSPACE"); err != nil {
		t.Fatalf("pass 1: %v", err)
	}
	if _, err := rec.ReconcileWorkspace(context.Background(), "01H000000000000000WORKSPACE"); err != nil {
		t.Fatalf("pass 2: %v", err)
	}
	var rows []models.AccessOrphanAccount
	if err := db.Find(&rows).Error; err != nil {
		t.Fatalf("list orphans: %v", err)
	}
	if len(rows) != 1 {
		t.Errorf("persisted orphans = %d after re-reconcile; want 1", len(rows))
	}
}

// TestOrphanReconciler_RevokeOrphan_CallsConnectorAndMarksRow
// asserts that RevokeOrphan calls the connector's RevokeAccess and
// transitions the row to auto_revoked.
func TestOrphanReconciler_RevokeOrphan_CallsConnectorAndMarksRow(t *testing.T) {
	const provider = "mock_orphan_revoke"
	db := newJMLTestDB(t)
	if err := db.AutoMigrate(&models.AccessOrphanAccount{}); err != nil {
		t.Fatalf("automigrate orphan: %v", err)
	}
	conn := seedConnectorWithSecrets(t, db, "01HCONN0ORPHANREVK00000001", provider)

	mock := &MockAccessConnector{
		FuncSyncIdentities: func(_ context.Context, _, _ map[string]interface{}, _ string, h func([]*Identity, string) error) error {
			return h([]*Identity{{ExternalID: "u-ghost", Email: "ghost@example.com"}}, "")
		},
	}
	SwapConnector(t, provider, mock)

	rec := NewOrphanReconciler(db, NewAccessProvisioningService(db), NewConnectorCredentialsLoader(db, PassthroughEncryptor{}))
	rec.SetClock(func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) })
	got, err := rec.ReconcileWorkspace(context.Background(), "01H000000000000000WORKSPACE")
	if err != nil {
		t.Fatalf("ReconcileWorkspace: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("orphan rows = %d; want 1", len(got))
	}

	if err := rec.RevokeOrphan(context.Background(), got[0].ID); err != nil {
		t.Fatalf("RevokeOrphan: %v", err)
	}
	if mock.RevokeAccessCalls != 1 {
		t.Errorf("connector RevokeAccess calls = %d; want 1", mock.RevokeAccessCalls)
	}

	var after models.AccessOrphanAccount
	if err := db.Where("id = ?", got[0].ID).First(&after).Error; err != nil {
		t.Fatalf("reload orphan: %v", err)
	}
	if after.Status != models.OrphanStatusAutoRevoked {
		t.Errorf("orphan status = %q; want %q", after.Status, models.OrphanStatusAutoRevoked)
	}
	if after.ResolvedAt == nil {
		t.Error("ResolvedAt = nil; want set after revoke")
	}
	_ = conn
}

// TestOrphanReconciler_DismissOrphan_MarksRow asserts DismissOrphan
// transitions the row to dismissed.
func TestOrphanReconciler_DismissOrphan_MarksRow(t *testing.T) {
	db := newJMLTestDB(t)
	if err := db.AutoMigrate(&models.AccessOrphanAccount{}); err != nil {
		t.Fatalf("automigrate orphan: %v", err)
	}
	row := models.AccessOrphanAccount{
		ID:             "01HORPHAN00000000000DISMISS",
		WorkspaceID:    "01H000000000000000WORKSPACE",
		ConnectorID:    "01HCONN0ORPHANDISMS00000001",
		UserExternalID: "u-ghost",
		Status:         models.OrphanStatusDetected,
		DetectedAt:     time.Now(),
	}
	if err := db.Create(&row).Error; err != nil {
		t.Fatalf("seed orphan: %v", err)
	}

	rec := NewOrphanReconciler(db, NewAccessProvisioningService(db), NewConnectorCredentialsLoader(db, PassthroughEncryptor{}))
	if err := rec.DismissOrphan(context.Background(), row.ID); err != nil {
		t.Fatalf("DismissOrphan: %v", err)
	}
	var after models.AccessOrphanAccount
	if err := db.Where("id = ?", row.ID).First(&after).Error; err != nil {
		t.Fatalf("reload: %v", err)
	}
	if after.Status != models.OrphanStatusDismissed {
		t.Errorf("status = %q; want %q", after.Status, models.OrphanStatusDismissed)
	}
}

// TestOrphanReconciler_ListOrphans_FiltersByStatus asserts the read
// API filters correctly.
func TestOrphanReconciler_ListOrphans_FiltersByStatus(t *testing.T) {
	db := newJMLTestDB(t)
	if err := db.AutoMigrate(&models.AccessOrphanAccount{}); err != nil {
		t.Fatalf("automigrate orphan: %v", err)
	}
	now := time.Now()
	rows := []models.AccessOrphanAccount{
		{ID: "01HORPHAN0000000000000A001", WorkspaceID: "ws1", ConnectorID: "c1", UserExternalID: "u1", Status: models.OrphanStatusDetected, DetectedAt: now},
		{ID: "01HORPHAN0000000000000A002", WorkspaceID: "ws1", ConnectorID: "c1", UserExternalID: "u2", Status: models.OrphanStatusDismissed, DetectedAt: now},
		{ID: "01HORPHAN0000000000000A003", WorkspaceID: "ws2", ConnectorID: "c2", UserExternalID: "u3", Status: models.OrphanStatusDetected, DetectedAt: now},
	}
	for i := range rows {
		if err := db.Create(&rows[i]).Error; err != nil {
			t.Fatalf("seed orphan: %v", err)
		}
	}

	rec := NewOrphanReconciler(db, NewAccessProvisioningService(db), NewConnectorCredentialsLoader(db, PassthroughEncryptor{}))
	got, err := rec.ListOrphans(context.Background(), "ws1", "")
	if err != nil {
		t.Fatalf("ListOrphans ws1: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("ws1 orphans = %d; want 2", len(got))
	}
	got, err = rec.ListOrphans(context.Background(), "ws1", models.OrphanStatusDetected)
	if err != nil {
		t.Fatalf("ListOrphans ws1 detected: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("ws1 detected orphans = %d; want 1", len(got))
	}
}
