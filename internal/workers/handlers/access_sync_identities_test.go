package handlers

import (
	"context"
	"errors"
	"testing"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

// TestAccessSyncIdentities_PersistsTeamMembersAndTeams verifies the
// Task 6 upgrade: real Team / TeamMember upserts plus real
// access_sync_state persistence.
func TestAccessSyncIdentities_PersistsTeamMembersAndTeams(t *testing.T) {
	db := newHandlerDB(t)
	const connID = "01HCONN0SYNCREAL000000000A"
	const jobID = "01HJOB00SYNCREAL000000000A"
	seedTestConnector(t, db, connID, "test_provider")
	seedJob(t, db, jobID, connID, models.AccessJobTypeSyncIdentities, nil)

	mock := &access.MockAccessConnector{
		FuncSyncIdentities: func(_ context.Context, _, _ map[string]interface{}, _ string, handler func([]*access.Identity, string) error) error {
			batch := []*access.Identity{
				{ExternalID: "ext-user-1", Type: access.IdentityTypeUser, DisplayName: "Alice", Email: "alice@example.com", Status: "active"},
				{ExternalID: "ext-user-2", Type: access.IdentityTypeUser, DisplayName: "Bob", Email: "bob@example.com", Status: "active", ManagerID: "ext-user-1"},
				{ExternalID: "ext-group-1", Type: access.IdentityTypeGroup, DisplayName: "Engineering"},
			}
			return handler(batch, "checkpoint-final")
		},
	}
	if err := AccessSyncIdentities(context.Background(), newJC(db, mock), jobID); err != nil {
		t.Fatalf("AccessSyncIdentities: %v", err)
	}

	var users []models.TeamMember
	if err := db.Where("connector_id = ?", connID).Find(&users).Error; err != nil {
		t.Fatalf("list team_members: %v", err)
	}
	if len(users) != 2 {
		t.Fatalf("got %d team_members; want 2", len(users))
	}
	byExt := map[string]models.TeamMember{}
	for _, u := range users {
		byExt[u.ExternalID] = u
	}
	if byExt["ext-user-2"].ManagerID != byExt["ext-user-1"].ID {
		t.Fatalf("manager link not resolved: %+v", byExt["ext-user-2"])
	}

	var teams []models.Team
	if err := db.Where("connector_id = ?", connID).Find(&teams).Error; err != nil {
		t.Fatalf("list teams: %v", err)
	}
	if len(teams) != 1 || teams[0].Name != "Engineering" {
		t.Fatalf("got teams %+v; want one named Engineering", teams)
	}

	var state models.AccessSyncState
	if err := db.Where("connector_id = ? AND kind = ?", connID, models.SyncStateKindIdentity).First(&state).Error; err != nil {
		t.Fatalf("load sync_state: %v", err)
	}
	if state.DeltaLink != "checkpoint-final" {
		t.Errorf("DeltaLink = %q; want %q", state.DeltaLink, "checkpoint-final")
	}
	if state.IdentityCount != 3 {
		t.Errorf("IdentityCount = %d; want 3", state.IdentityCount)
	}
}

// TestAccessSyncIdentities_TombstoneSafetyAborts verifies that a
// fresh sync with fewer than 70% of the previously observed
// identity count aborts with ErrTombstoneSafetyThreshold and does
// NOT overwrite the previous access_sync_state row.
func TestAccessSyncIdentities_TombstoneSafetyAborts(t *testing.T) {
	db := newHandlerDB(t)
	const connID = "01HCONN0TOMB000000000000A"
	const jobID = "01HJOB0TOMB000000000000A"
	seedTestConnector(t, db, connID, "test_provider")
	seedJob(t, db, jobID, connID, models.AccessJobTypeSyncIdentities, nil)
	// Seed a previous state with 100 identities so the 70%
	// threshold demands >= 70 new identities.
	prev := &models.AccessSyncState{
		ID:            "01HSYNC0PREVIOUS00000000000",
		ConnectorID:   connID,
		Kind:          models.SyncStateKindIdentity,
		DeltaLink:     "old-checkpoint",
		IdentityCount: 100,
	}
	if err := db.Create(prev).Error; err != nil {
		t.Fatalf("seed prev state: %v", err)
	}

	mock := &access.MockAccessConnector{
		FuncSyncIdentities: func(_ context.Context, _, _ map[string]interface{}, _ string, handler func([]*access.Identity, string) error) error {
			batch := []*access.Identity{
				{ExternalID: "u-1", Type: access.IdentityTypeUser},
				{ExternalID: "u-2", Type: access.IdentityTypeUser},
			}
			return handler(batch, "new-checkpoint")
		},
	}
	err := AccessSyncIdentities(context.Background(), newJC(db, mock), jobID)
	if err == nil {
		t.Fatal("expected tombstone safety to abort sync")
	}
	if !errors.Is(err, ErrTombstoneSafetyThreshold) {
		t.Errorf("err = %v; want ErrTombstoneSafetyThreshold", err)
	}
	// Verify previous state unchanged.
	var got models.AccessSyncState
	if err := db.Where("id = ?", prev.ID).First(&got).Error; err != nil {
		t.Fatalf("load state: %v", err)
	}
	if got.DeltaLink != "old-checkpoint" {
		t.Errorf("DeltaLink = %q; want preserved", got.DeltaLink)
	}
	if got.IdentityCount != 100 {
		t.Errorf("IdentityCount = %d; want 100", got.IdentityCount)
	}
}
