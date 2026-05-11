package access

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

func newConnectorListDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(
		&models.AccessConnector{},
		&models.AccessSyncState{},
	); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}
	return db
}

// TestAccessConnectorListService_HappyPath seeds two connectors in
// the same workspace, one with a recent identity-sync state, and
// asserts ListConnectors returns both ordered by provider and
// joins the sync state correctly.
func TestAccessConnectorListService_HappyPath(t *testing.T) {
	db := newConnectorListDB(t)
	now := time.Now()
	if err := db.Create(&models.AccessConnector{
		ID:            "01H00000000000000CONN0001",
		WorkspaceID:   "01H000000000000000WORKSPACE",
		Provider:      "okta",
		ConnectorType: "saas",
		Status:        "connected",
		CreatedAt:     now,
		UpdatedAt:     now,
	}).Error; err != nil {
		t.Fatalf("seed conn1: %v", err)
	}
	if err := db.Create(&models.AccessConnector{
		ID:            "01H00000000000000CONN0002",
		WorkspaceID:   "01H000000000000000WORKSPACE",
		Provider:      "github",
		ConnectorType: "saas",
		Status:        "connected",
		CreatedAt:     now,
		UpdatedAt:     now,
	}).Error; err != nil {
		t.Fatalf("seed conn2: %v", err)
	}
	if err := db.Create(&models.AccessSyncState{
		ID:          "01H0000000000000SYNCSTATE01",
		ConnectorID: "01H00000000000000CONN0001",
		Kind:        models.SyncStateKindIdentity,
		DeltaLink:   "cursor-abc",
		CreatedAt:   now,
		UpdatedAt:   now,
	}).Error; err != nil {
		t.Fatalf("seed sync: %v", err)
	}

	svc := NewAccessConnectorListService(db)
	out, err := svc.ListConnectors(context.Background(), ListConnectorsQuery{
		WorkspaceID: "01H000000000000000WORKSPACE",
	})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("len(out) = %d; want 2", len(out))
	}
	// Ordered by provider asc → github before okta.
	if out[0].Provider != "github" {
		t.Fatalf("out[0].Provider = %q; want github", out[0].Provider)
	}
	if out[1].Provider != "okta" {
		t.Fatalf("out[1].Provider = %q; want okta", out[1].Provider)
	}
	if _, ok := out[1].LastSyncTimes[models.SyncStateKindIdentity]; !ok {
		t.Fatal("okta LastSyncTimes missing identity entry")
	}
}

// TestAccessConnectorListService_FiltersByStatus seeds two
// connectors with different statuses and asserts the filter is
// applied server-side.
func TestAccessConnectorListService_FiltersByStatus(t *testing.T) {
	db := newConnectorListDB(t)
	now := time.Now()
	for i, status := range []string{"connected", "error"} {
		if err := db.Create(&models.AccessConnector{
			ID:            "01H00000000000000CONN000" + string(rune('1'+i)),
			WorkspaceID:   "01H000000000000000WORKSPACE",
			Provider:      "okta",
			ConnectorType: "saas",
			Status:        status,
			CreatedAt:     now,
			UpdatedAt:     now,
		}).Error; err != nil {
			t.Fatalf("seed %d: %v", i, err)
		}
	}
	svc := NewAccessConnectorListService(db)
	bad := "error"
	out, err := svc.ListConnectors(context.Background(), ListConnectorsQuery{
		WorkspaceID: "01H000000000000000WORKSPACE",
		Status:      &bad,
	})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("len(out) = %d; want 1", len(out))
	}
	if out[0].Status != "error" {
		t.Fatalf("Status = %q; want error", out[0].Status)
	}
}

// TestAccessConnectorListService_MissingWorkspaceReturnsValidation
// is the failure-path test.
func TestAccessConnectorListService_MissingWorkspaceReturnsValidation(t *testing.T) {
	db := newConnectorListDB(t)
	svc := NewAccessConnectorListService(db)
	_, err := svc.ListConnectors(context.Background(), ListConnectorsQuery{})
	if !errors.Is(err, ErrValidation) {
		t.Fatalf("err = %v; want ErrValidation", err)
	}
}

// TestAccessGrantQueryService_GetGrant covers the new GetGrant
// helper added for the entitlements endpoint.
func TestAccessGrantQueryService_GetGrant(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.AutoMigrate(&models.AccessGrant{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	now := time.Now()
	if err := db.Create(&models.AccessGrant{
		ID:                 "01H00000000000000GRANT0001",
		WorkspaceID:        "01H000000000000000WORKSPACE",
		UserID:             "01H000000000000000USER0001",
		ConnectorID:        "01H00000000000000CONN0001",
		ResourceExternalID: "host-001",
		Role:               "viewer",
		GrantedAt:          now,
		CreatedAt:          now,
		UpdatedAt:          now,
	}).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
	svc := NewAccessGrantQueryService(db)
	got, err := svc.GetGrant(context.Background(), "01H00000000000000GRANT0001")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got == nil || got.ID != "01H00000000000000GRANT0001" {
		t.Fatalf("got = %+v; want grant with ID GRANT0001", got)
	}

	_, err = svc.GetGrant(context.Background(), "01H000000000000000NONEXIST")
	if !errors.Is(err, ErrGrantNotFound) {
		t.Fatalf("err = %v; want ErrGrantNotFound", err)
	}

	_, err = svc.GetGrant(context.Background(), "")
	if !errors.Is(err, ErrValidation) {
		t.Fatalf("err = %v; want ErrValidation", err)
	}
}
