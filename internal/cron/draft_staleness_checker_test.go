package cron

import (
	"context"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

func newPolicyDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&models.Policy{}); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}
	return db
}

func seedDraft(t *testing.T, db *gorm.DB, id string, createdAt time.Time) {
	t.Helper()
	row := &models.Policy{
		ID:          id,
		WorkspaceID: "01HWORKSPACE0000000000000A",
		Name:        "draft-" + id,
		IsDraft:     true,
		IsActive:    true,
		Action:      models.PolicyActionAllow,
	}
	if err := db.Create(row).Error; err != nil {
		t.Fatalf("seed policy: %v", err)
	}
	if err := db.Model(&models.Policy{}).Where("id = ?", id).Update("created_at", createdAt).Error; err != nil {
		t.Fatalf("set created_at: %v", err)
	}
}

func TestDraftPolicyStalenessChecker_FlipsOldDrafts(t *testing.T) {
	db := newPolicyDB(t)
	now := time.Date(2025, 1, 30, 0, 0, 0, 0, time.UTC)
	const old = "01HPOL00OLDDRAFT00000000A"
	const recent = "01HPOL00RECENT0000000000A"
	seedDraft(t, db, old, now.AddDate(0, 0, -20))
	seedDraft(t, db, recent, now.AddDate(0, 0, -2))

	c := NewDraftPolicyStalenessChecker(db, nil, 14*24*time.Hour)
	c.SetClock(func() time.Time { return now })

	flipped, err := c.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if flipped != 1 {
		t.Errorf("flipped = %d; want 1", flipped)
	}

	var oldRow models.Policy
	if err := db.Where("id = ?", old).First(&oldRow).Error; err != nil {
		t.Fatalf("load old: %v", err)
	}
	if !oldRow.Stale {
		t.Error("old draft was not flipped to stale=true")
	}

	var recentRow models.Policy
	if err := db.Where("id = ?", recent).First(&recentRow).Error; err != nil {
		t.Fatalf("load recent: %v", err)
	}
	if recentRow.Stale {
		t.Error("recent draft was incorrectly flipped to stale=true")
	}
}

func TestDraftPolicyStalenessChecker_NotifierCalled(t *testing.T) {
	db := newPolicyDB(t)
	now := time.Date(2025, 1, 30, 0, 0, 0, 0, time.UTC)
	seedDraft(t, db, "01HPOL00DRAFT0NOTIF000000A", now.AddDate(0, 0, -30))

	var calls int
	notifier := draftNotifierFunc(func(_ context.Context, _, _, _ string, _ time.Duration) error {
		calls++
		return nil
	})
	c := NewDraftPolicyStalenessChecker(db, notifier, 14*24*time.Hour)
	c.SetClock(func() time.Time { return now })

	if _, err := c.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if calls != 1 {
		t.Errorf("notifier calls = %d; want 1", calls)
	}
}

type draftNotifierFunc func(ctx context.Context, workspaceID, policyID, policyName string, age time.Duration) error

func (f draftNotifierFunc) NotifyDraftStale(ctx context.Context, workspaceID, policyID, policyName string, age time.Duration) error {
	return f(ctx, workspaceID, policyID, policyName, age)
}
