package cron

import (
	"context"
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

// GrantRevoker is the narrow contract GrantExpiryEnforcer uses to
// revoke an expired access_grants row. The production
// implementation is *access.AccessProvisioningService; tests
// substitute a stub that captures every call.
type GrantRevoker interface {
	Revoke(ctx context.Context, grant *models.AccessGrant, config, secrets map[string]interface{}) error
}

// GrantExpiryEnforcer is the Phase 6 background cron job that
// scans access_grants for rows whose expires_at has passed and
// revokes each one through the supplied GrantRevoker. Runs on the
// same external ticker pattern as IdentitySyncScheduler.
//
// Real-world behaviour: the revoker pushes the revoke out to the
// upstream provider via the AccessConnector contract before
// updating the DB. The enforcer is therefore best-effort — a
// connector failure leaves the grant in an "expires_at past,
// revoked_at nil" state, which the next tick retries.
type GrantExpiryEnforcer struct {
	db       *gorm.DB
	revoker  GrantRevoker
	batchSize int
	now      func() time.Time
}

// NewGrantExpiryEnforcer returns an enforcer bound to db that
// revokes grants via revoker. revoker must not be nil; batchSize
// caps the number of grants processed per tick (zero / negative
// falls back to 100 — sized to keep a single tick under the SLA
// budget at the SN360 connector scale).
func NewGrantExpiryEnforcer(db *gorm.DB, revoker GrantRevoker, batchSize int) *GrantExpiryEnforcer {
	if batchSize <= 0 {
		batchSize = 100
	}
	return &GrantExpiryEnforcer{
		db:        db,
		revoker:   revoker,
		batchSize: batchSize,
		now:       time.Now,
	}
}

// SetClock overrides time.Now. Tests use this to pin expiry
// comparisons to a deterministic timestamp.
func (e *GrantExpiryEnforcer) SetClock(now func() time.Time) {
	if now != nil {
		e.now = now
	}
}

// Run scans the access_grants table for unrevoked rows with
// expires_at <= now and calls revoker.Revoke on each. Returns the
// count of grants successfully revoked. A non-nil err carries the
// last per-grant error so callers can log it; individual failures
// do NOT abort the loop.
func (e *GrantExpiryEnforcer) Run(ctx context.Context) (int, error) {
	if e.db == nil {
		return 0, errors.New("cron: grant_expiry_enforcer missing db")
	}
	if e.revoker == nil {
		return 0, errors.New("cron: grant_expiry_enforcer missing revoker")
	}
	now := e.now()

	var grants []models.AccessGrant
	if err := e.db.WithContext(ctx).
		Where("revoked_at IS NULL AND expires_at IS NOT NULL AND expires_at <= ?", now).
		Limit(e.batchSize).
		Find(&grants).Error; err != nil {
		return 0, fmt.Errorf("cron: list expired grants: %w", err)
	}

	var (
		revoked int
		lastErr error
	)
	for i := range grants {
		grant := &grants[i]
		if err := e.revoker.Revoke(ctx, grant, nil, nil); err != nil {
			// Treat ErrAlreadyRevoked as idempotent success.
			if errors.Is(err, access.ErrAlreadyRevoked) {
				continue
			}
			lastErr = fmt.Errorf("cron: revoke grant %s: %w", grant.ID, err)
			continue
		}
		revoked++
	}
	return revoked, lastErr
}
