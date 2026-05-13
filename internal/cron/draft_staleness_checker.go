package cron

import (
	"context"
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// DraftStalenessNotifier is the narrow contract
// DraftPolicyStalenessChecker uses to emit notifications for newly
// marked stale drafts. The production implementation wraps the
// NotificationAdapter from internal/services/access; tests can pass
// nil to skip notifications entirely.
type DraftStalenessNotifier interface {
	NotifyDraftStale(ctx context.Context, workspaceID, policyID, policyName string, age time.Duration) error
}

// DraftPolicyStalenessChecker scans the policies table for draft
// policies whose created_at is older than staleAfter and flips
// their stale column to true. Runs on the same external ticker
// pattern as IdentitySyncScheduler.
//
// Best-effort: a per-row UPDATE failure does NOT abort the loop.
// The last error is surfaced via the returned err for callers that
// want aggregate diagnostics.
type DraftPolicyStalenessChecker struct {
	db         *gorm.DB
	notifier   DraftStalenessNotifier
	staleAfter time.Duration
	now        func() time.Time
}

// NewDraftPolicyStalenessChecker returns a checker bound to db
// that flags drafts older than staleAfter. staleAfter must be
// positive; zero or negative falls back to 14 days (matching
// config.DefaultDraftPolicyStaleAfter).
func NewDraftPolicyStalenessChecker(db *gorm.DB, notifier DraftStalenessNotifier, staleAfter time.Duration) *DraftPolicyStalenessChecker {
	if staleAfter <= 0 {
		staleAfter = 14 * 24 * time.Hour
	}
	return &DraftPolicyStalenessChecker{
		db:         db,
		notifier:   notifier,
		staleAfter: staleAfter,
		now:        time.Now,
	}
}

// SetClock overrides time.Now. Tests use this to pin staleness
// comparisons to a deterministic timestamp.
func (c *DraftPolicyStalenessChecker) SetClock(now func() time.Time) {
	if now != nil {
		c.now = now
	}
}

// Run scans the policies table and marks every draft whose
// created_at is older than staleAfter as stale. Returns the count
// of rows flipped. A non-nil err carries the last per-row error.
func (c *DraftPolicyStalenessChecker) Run(ctx context.Context) (int, error) {
	if c.db == nil {
		return 0, errors.New("cron: draft_staleness_checker missing db")
	}
	now := c.now()
	threshold := now.Add(-c.staleAfter)

	var drafts []models.Policy
	if err := c.db.WithContext(ctx).
		Where("is_draft = ? AND stale = ? AND created_at < ?", true, false, threshold).
		Find(&drafts).Error; err != nil {
		return 0, fmt.Errorf("cron: list stale drafts: %w", err)
	}

	var (
		flipped int
		lastErr error
	)
	for _, p := range drafts {
		if err := c.db.WithContext(ctx).
			Model(&models.Policy{}).
			Where("id = ?", p.ID).
			Updates(map[string]interface{}{
				"stale":      true,
				"updated_at": now,
			}).Error; err != nil {
			lastErr = fmt.Errorf("cron: update policy %s: %w", p.ID, err)
			continue
		}
		flipped++
		if c.notifier != nil {
			age := now.Sub(p.CreatedAt)
			if err := c.notifier.NotifyDraftStale(ctx, p.WorkspaceID, p.ID, p.Name, age); err != nil {
				lastErr = fmt.Errorf("cron: notify stale policy %s: %w", p.ID, err)
			}
		}
	}
	return flipped, lastErr
}
