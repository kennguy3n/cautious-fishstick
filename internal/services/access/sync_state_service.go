package access

import (
	"context"
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// SyncStateService is the read / write surface for the
// access_sync_state table per docs/architecture.md §11 and
// docs/architecture.md §3. The access-connector-worker calls Get
// before issuing a delta sync request; if the cursor is missing
// the worker falls back to a full enumeration. After a successful
// batch the worker calls Set to persist the new cursor.
//
// The service is intentionally small — no Delete / List API. The
// cursor lifecycle is fully driven by the worker: cursors are
// created on first sync, refreshed on every subsequent sync, and
// only ever removed when the parent connector is soft-deleted (the
// access-platform sweep handles that elsewhere).
type SyncStateService struct {
	db    *gorm.DB
	now   func() time.Time
	newID func() string
}

// NewSyncStateService returns a service backed by db. db must not be
// nil. now defaults to time.Now and newID defaults to the package
// ULID generator; both are overridable for tests via the SetClock /
// SetIDGenerator hooks.
func NewSyncStateService(db *gorm.DB) *SyncStateService {
	return &SyncStateService{
		db:    db,
		now:   time.Now,
		newID: newULID,
	}
}

// SetClock overrides time.Now. Tests use this to pin UpdatedAt.
func (s *SyncStateService) SetClock(now func() time.Time) {
	if now != nil {
		s.now = now
	}
}

// SetIDGenerator overrides newULID. Tests use this to pin the
// generated ID on a fresh insert.
func (s *SyncStateService) SetIDGenerator(g func() string) {
	if g != nil {
		s.newID = g
	}
}

// validateKind ensures the supplied kind is one of the three
// canonical sync kinds. Surfaces ErrValidation so callers can
// errors.Is against the access-platform validation sentinel.
func validateSyncStateKind(kind string) error {
	switch kind {
	case models.SyncStateKindIdentity, models.SyncStateKindGroup, models.SyncStateKindAudit:
		return nil
	default:
		return fmt.Errorf("%w: kind %q must be one of identity, group, audit", ErrValidation, kind)
	}
}

// Get returns the persisted delta-link cursor for (connectorID, kind)
// or an empty string when no cursor exists yet. A missing row is
// NOT an error — callers treat empty as "no cursor; do a full sync".
//
// connectorID and kind are both required.
func (s *SyncStateService) Get(ctx context.Context, connectorID, kind string) (string, error) {
	if connectorID == "" {
		return "", fmt.Errorf("%w: connector_id is required", ErrValidation)
	}
	if err := validateSyncStateKind(kind); err != nil {
		return "", err
	}

	var row models.AccessSyncState
	err := s.db.WithContext(ctx).
		Where("connector_id = ? AND kind = ?", connectorID, kind).
		First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("sync_state: get: %w", err)
	}
	return row.DeltaLink, nil
}

// Set writes (or upserts) the delta-link cursor for (connectorID,
// kind). Empty deltaLink is allowed — it is the canonical "I've
// completed a full sync but the provider didn't return a cursor"
// sentinel; the next sync will fall back to full again.
//
// The (connector_id, kind) tuple is unique; Set uses ON CONFLICT
// upsert semantics so concurrent workers can't insert duplicate
// cursors.
func (s *SyncStateService) Set(ctx context.Context, connectorID, kind, deltaLink string) error {
	if connectorID == "" {
		return fmt.Errorf("%w: connector_id is required", ErrValidation)
	}
	if err := validateSyncStateKind(kind); err != nil {
		return err
	}

	now := s.now()
	row := models.AccessSyncState{
		ID:          s.newID(),
		ConnectorID: connectorID,
		Kind:        kind,
		DeltaLink:   deltaLink,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	// Upsert keyed on (connector_id, kind) — DoUpdates touches
	// delta_link and updated_at only so the original CreatedAt
	// stays accurate.
	err := s.db.WithContext(ctx).
		Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "connector_id"}, {Name: "kind"}},
			DoUpdates: clause.AssignmentColumns([]string{"delta_link", "updated_at"}),
		}).
		Create(&row).Error
	if err != nil {
		return fmt.Errorf("sync_state: set: %w", err)
	}
	return nil
}
