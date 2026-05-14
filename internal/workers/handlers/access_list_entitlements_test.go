package handlers

import (
	"context"
	"testing"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

// TestAccessListEntitlements_PersistsEntitlementsSnapshot verifies
// Task 7: the worker writes the connector's returned Entitlement
// slice into access_grant_entitlements, replacing the prior
// snapshot for (connector_id, user_external_id).
func TestAccessListEntitlements_PersistsEntitlementsSnapshot(t *testing.T) {
	db := newHandlerDB(t)
	const connID = "01HCONN0LISTREAL00000000A"
	const jobID = "01HJOB00LISTREAL00000000A"
	seedTestConnector(t, db, connID, "test_provider")
	payload := listEntitlementsPayload{UserExternalID: "alice@example.com"}
	seedJob(t, db, jobID, connID, models.AccessJobTypeListEntitlements, payload)

	mock := &access.MockAccessConnector{
		FuncListEntitlements: func(_ context.Context, _, _ map[string]interface{}, user string) ([]access.Entitlement, error) {
			return []access.Entitlement{
				{ResourceExternalID: "projects/alpha", Role: "viewer", Source: "direct"},
				{ResourceExternalID: "projects/beta", Role: "editor", Source: "group"},
			}, nil
		},
	}
	if err := AccessListEntitlements(context.Background(), newJC(db, mock), jobID); err != nil {
		t.Fatalf("AccessListEntitlements: %v", err)
	}

	var rows []models.AccessGrantEntitlement
	if err := db.Where("connector_id = ? AND user_external_id = ?", connID, "alice@example.com").Find(&rows).Error; err != nil {
		t.Fatalf("list entitlements: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("got %d entitlements; want 2", len(rows))
	}
}

// TestAccessListEntitlements_ReplacesPreviousSnapshot verifies that
// re-running the handler against the same user wipes prior rows.
func TestAccessListEntitlements_ReplacesPreviousSnapshot(t *testing.T) {
	db := newHandlerDB(t)
	const connID = "01HCONN0LISTREP000000000A"
	const jobID = "01HJOB00LISTREP000000000A"
	seedTestConnector(t, db, connID, "test_provider")
	payload := listEntitlementsPayload{UserExternalID: "bob@example.com"}
	seedJob(t, db, jobID, connID, models.AccessJobTypeListEntitlements, payload)

	// Pre-seed a stale entitlement.
	stale := &models.AccessGrantEntitlement{
		ID:                 "01HENT0STALE00000000000000A",
		ConnectorID:        connID,
		UserExternalID:     "bob@example.com",
		ResourceExternalID: "projects/old",
		Role:               "owner",
	}
	if err := db.Create(stale).Error; err != nil {
		t.Fatalf("seed stale: %v", err)
	}

	mock := &access.MockAccessConnector{
		FuncListEntitlements: func(_ context.Context, _, _ map[string]interface{}, _ string) ([]access.Entitlement, error) {
			return []access.Entitlement{
				{ResourceExternalID: "projects/new", Role: "viewer"},
			}, nil
		},
	}
	if err := AccessListEntitlements(context.Background(), newJC(db, mock), jobID); err != nil {
		t.Fatalf("AccessListEntitlements: %v", err)
	}

	var rows []models.AccessGrantEntitlement
	if err := db.Where("connector_id = ? AND user_external_id = ?", connID, "bob@example.com").Find(&rows).Error; err != nil {
		t.Fatalf("list entitlements: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows; want 1 (stale should have been purged)", len(rows))
	}
	if rows[0].ResourceExternalID != "projects/new" {
		t.Errorf("got resource %q; want projects/new", rows[0].ResourceExternalID)
	}
}
