package cron

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"github.com/oklog/ulid/v2"
	"gorm.io/datatypes"
	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// IdentitySyncScheduler is the Phase 6 background cron job that
// scans the access_connectors table and enqueues a fresh
// sync_identities access_jobs row for every connector whose last
// successful identity sync is older than fullResyncInterval.
//
// The scheduler is driven by an external ticker (the
// access-connector-worker binary calls Run once per tick). It is
// idempotent across runs: re-running before the previous sync
// completes still enqueues a fresh row, but the connector handler
// uses the latest checkpoint so duplicate work converges quickly.
type IdentitySyncScheduler struct {
	db                  *gorm.DB
	fullResyncInterval  time.Duration
	now                 func() time.Time
	newID               func() string
}

// NewIdentitySyncScheduler returns a scheduler bound to db that
// considers a connector "stale" when its latest
// access_sync_state.updated_at is older than fullResyncInterval.
// fullResyncInterval must be positive; zero or negative falls back
// to 24h so a misconfigured cron job still surfaces stale
// connectors.
func NewIdentitySyncScheduler(db *gorm.DB, fullResyncInterval time.Duration) *IdentitySyncScheduler {
	if fullResyncInterval <= 0 {
		fullResyncInterval = 24 * time.Hour
	}
	return &IdentitySyncScheduler{
		db:                 db,
		fullResyncInterval: fullResyncInterval,
		now:                time.Now,
		newID:              defaultULID,
	}
}

// SetClock overrides time.Now. Tests use this to pin staleness
// comparisons to a deterministic timestamp.
func (s *IdentitySyncScheduler) SetClock(now func() time.Time) {
	if now != nil {
		s.now = now
	}
}

// SetIDFactory overrides the ULID generator. Tests pin this so
// assertions can predict the freshly-inserted access_jobs row ID.
func (s *IdentitySyncScheduler) SetIDFactory(fn func() string) {
	if fn != nil {
		s.newID = fn
	}
}

// Run scans every non-deleted access_connectors row and INSERTs a
// pending sync_identities access_jobs row for each connector whose
// last identity sync is older than fullResyncInterval. Connectors
// with no prior sync_state (never synced) are also scheduled.
//
// Returns the count of enqueued jobs. A non-nil err carries the
// last per-connector error so callers can log it; individual
// failures do NOT abort the loop.
func (s *IdentitySyncScheduler) Run(ctx context.Context) (int, error) {
	if s.db == nil {
		return 0, errors.New("cron: identity_sync_scheduler missing db")
	}
	threshold := s.now().Add(-s.fullResyncInterval)

	var connectors []models.AccessConnector
	if err := s.db.WithContext(ctx).Find(&connectors).Error; err != nil {
		return 0, fmt.Errorf("cron: list connectors: %w", err)
	}

	var (
		enqueued int
		lastErr  error
	)
	for _, conn := range connectors {
		var state models.AccessSyncState
		err := s.db.WithContext(ctx).
			Where("connector_id = ? AND kind = ?", conn.ID, models.SyncStateKindIdentity).
			Order("updated_at DESC").
			First(&state).Error
		never := errors.Is(err, gorm.ErrRecordNotFound)
		if err != nil && !never {
			lastErr = fmt.Errorf("cron: load sync_state %s: %w", conn.ID, err)
			continue
		}
		if !never && state.UpdatedAt.After(threshold) {
			continue
		}

		now := s.now()
		job := &models.AccessJob{
			ID:          s.newID(),
			ConnectorID: conn.ID,
			JobType:     models.AccessJobTypeSyncIdentities,
			Status:      models.AccessJobStatusPending,
			Payload:     datatypes.JSON([]byte("{}")),
			CreatedAt:   now,
			UpdatedAt:   now,
		}
		if err := s.db.WithContext(ctx).Create(job).Error; err != nil {
			lastErr = fmt.Errorf("cron: insert job for %s: %w", conn.ID, err)
			continue
		}
		enqueued++
	}
	return enqueued, lastErr
}

// defaultULID is the package-private ULID generator the schedulers
// share. The cron package owns its own generator to avoid an
// import cycle with internal/services/access.
func defaultULID() string {
	return ulid.MustNew(ulid.Now(), rand.Reader).String()
}
