package cron

import (
	"context"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

func newGrantDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&models.AccessGrant{}, &models.AccessConnector{}); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}
	return db
}

func seedGrant(t *testing.T, db *gorm.DB, id string, expiresAt *time.Time) {
	t.Helper()
	now := time.Now()
	reqID := "01HREQ00000000000000000001"
	row := &models.AccessGrant{
		ID:                 id,
		RequestID:          &reqID,
		WorkspaceID:        "01HWORKSPACE0000000000000A",
		UserID:             "01HUSER00000000000000000A",
		ConnectorID:        "01HCONN00000000000000000A",
		ResourceExternalID: "projects/foo",
		Role:               "viewer",
		GrantedAt:          now,
		ExpiresAt:          expiresAt,
	}
	if err := db.Create(row).Error; err != nil {
		t.Fatalf("seed grant: %v", err)
	}
}

type captureRevoker struct {
	calls []string
	now   func() time.Time
	db    *gorm.DB
}

func (c *captureRevoker) Revoke(ctx context.Context, grant *models.AccessGrant, _ map[string]interface{}, _ map[string]interface{}) error {
	c.calls = append(c.calls, grant.ID)
	if grant.RevokedAt != nil {
		return access.ErrAlreadyRevoked
	}
	now := c.now()
	return c.db.WithContext(ctx).
		Model(&models.AccessGrant{}).
		Where("id = ?", grant.ID).
		Updates(map[string]interface{}{
			"revoked_at": now,
			"updated_at": now,
		}).Error
}

func TestGrantExpiryEnforcer_RevokesExpiredGrants(t *testing.T) {
	db := newGrantDB(t)
	now := time.Date(2025, 2, 1, 0, 0, 0, 0, time.UTC)
	pastT := now.Add(-1 * time.Hour)
	futureT := now.Add(1 * time.Hour)
	seedGrant(t, db, "01HGRANT0EXPIRED000000000A", &pastT)
	seedGrant(t, db, "01HGRANT0LIVE0000000000000A", &futureT)
	seedGrant(t, db, "01HGRANT0NEVER0000000000A", nil) // no expiry

	rev := &captureRevoker{now: func() time.Time { return now }, db: db}
	e := NewGrantExpiryEnforcer(db, rev, 100)
	e.SetClock(func() time.Time { return now })

	revoked, err := e.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if revoked != 1 {
		t.Errorf("revoked = %d; want 1", revoked)
	}
	if len(rev.calls) != 1 || rev.calls[0] != "01HGRANT0EXPIRED000000000A" {
		t.Errorf("calls = %v; want [01HGRANT0EXPIRED000000000A]", rev.calls)
	}

	var expired models.AccessGrant
	if err := db.Where("id = ?", "01HGRANT0EXPIRED000000000A").First(&expired).Error; err != nil {
		t.Fatalf("load expired: %v", err)
	}
	if expired.RevokedAt == nil {
		t.Error("expired grant did not get revoked_at set")
	}
	var live models.AccessGrant
	if err := db.Where("id = ?", "01HGRANT0LIVE0000000000000A").First(&live).Error; err != nil {
		t.Fatalf("load live: %v", err)
	}
	if live.RevokedAt != nil {
		t.Error("live grant was incorrectly revoked")
	}
}

func TestGrantExpiryEnforcer_IdempotentAcrossRuns(t *testing.T) {
	db := newGrantDB(t)
	now := time.Date(2025, 2, 1, 0, 0, 0, 0, time.UTC)
	pastT := now.Add(-1 * time.Hour)
	seedGrant(t, db, "01HGRANT0EXPIRED000000000A", &pastT)

	rev := &captureRevoker{now: func() time.Time { return now }, db: db}
	e := NewGrantExpiryEnforcer(db, rev, 100)
	e.SetClock(func() time.Time { return now })

	if _, err := e.Run(context.Background()); err != nil {
		t.Fatalf("first run: %v", err)
	}
	// Second run should be a no-op — the grant already has revoked_at.
	revoked2, err := e.Run(context.Background())
	if err != nil {
		t.Fatalf("second run: %v", err)
	}
	if revoked2 != 0 {
		t.Errorf("second run revoked = %d; want 0", revoked2)
	}
}
