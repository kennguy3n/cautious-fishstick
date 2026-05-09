// Package cron contains background workers that drive periodic
// access-platform behaviour. The Phase 5 entry point is
// CampaignScheduler, which scans access_campaign_schedules for due
// rows and starts a fresh AccessReview campaign for each.
//
// The package exposes one type per worker; cmd/ztna-api wires them
// in and calls Run on a goroutine. Workers are designed to be
// idempotent and crash-safe — re-running Run after a partial failure
// must not double-start campaigns.
package cron

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

// CampaignStarter is the narrow interface CampaignScheduler uses to
// trigger a fresh AccessReview inside an externally-managed
// transaction. The production implementation is
// *access.AccessReviewService.StartCampaignTx; tests substitute a
// stub. The scheduler always invokes the starter inside a tx that
// also bumps access_campaign_schedules.NextRunAt so the two writes
// are atomic — either both commit or both roll back, never one.
type CampaignStarter interface {
	StartCampaignTx(ctx context.Context, tx *gorm.DB, in access.StartCampaignInput) (*models.AccessReview, []models.AccessReviewDecision, error)
}

// CampaignScheduler is the Phase 5 background worker that drives the
// access_campaign_schedules table. On each call to Run it scans for
// schedules whose NextRunAt has elapsed, starts a fresh AccessReview
// for each, and bumps NextRunAt by FrequencyDays. Soft-deleted /
// inactive schedules are skipped.
//
// CampaignScheduler is intentionally not a long-lived goroutine; it
// expects an external ticker (or test loop) to drive Run. This makes
// it trivial to unit-test with a synthetic clock.
type CampaignScheduler struct {
	db        *gorm.DB
	starter   CampaignStarter
	now       func() time.Time
	defaultDue time.Duration
}

// NewCampaignScheduler returns a scheduler bound to db and starter.
// db and starter must both be non-nil; starter is the
// AccessReviewService that StartCampaign-s the new review.
func NewCampaignScheduler(db *gorm.DB, starter CampaignStarter) *CampaignScheduler {
	return &CampaignScheduler{
		db:        db,
		starter:   starter,
		now:       time.Now,
		defaultDue: 14 * 24 * time.Hour,
	}
}

// SetClock overrides time.Now. Tests use this to pin NextRunAt
// comparisons to a deterministic timestamp.
func (s *CampaignScheduler) SetClock(now func() time.Time) {
	s.now = now
}

// SetDefaultDueWindow overrides the default DueAt window the
// scheduler stamps onto the new AccessReview. Defaults to 14 days
// from time.Now(). Tests use this to pin DueAt assertions.
func (s *CampaignScheduler) SetDefaultDueWindow(d time.Duration) {
	if d > 0 {
		s.defaultDue = d
	}
}

// Run scans access_campaign_schedules for active rows whose
// NextRunAt is at or before time.Now() and starts a new AccessReview
// for each. The scheduler updates NextRunAt as part of the same
// per-row transaction as the new AccessReview so a transient panic
// mid-loop or a DB error between the two writes can never leave the
// schedule "due" with a fresh campaign already inserted. Either both
// happen or neither does.
//
// Run is safe to call repeatedly. The unit of work is one schedule
// row; a failure on one row does not abort the loop, but the error
// is logged and surfaced in the returned err (the LAST seen error
// — callers needing per-row errors should add a per-row hook).
//
// Run never blocks indefinitely; the only sleeping it does is the
// underlying DB query, which respects ctx.
func (s *CampaignScheduler) Run(ctx context.Context) error {
	if s == nil || s.db == nil || s.starter == nil {
		return errors.New("cron: scheduler is not fully wired")
	}
	now := s.now()

	var due []models.AccessCampaignSchedule
	if err := s.db.WithContext(ctx).
		Where("is_active = ?", true).
		Where("next_run_at <= ?", now).
		Find(&due).Error; err != nil {
		return fmt.Errorf("cron: list due schedules: %w", err)
	}

	var lastErr error
	for i := range due {
		sched := &due[i]
		if err := s.runOne(ctx, sched, now); err != nil {
			log.Printf("cron: campaign_scheduler: schedule_id=%s name=%q: %v", sched.ID, sched.Name, err)
			lastErr = err
			continue
		}
	}
	return lastErr
}

// runOne starts a single campaign for the supplied schedule and
// bumps NextRunAt. Both writes happen in a single transaction so a
// failure between StartCampaign and the NextRunAt UPDATE rolls the
// new AccessReview back — the next Run will see the row as still
// due and retry from a clean state. The DueAt stamped onto the new
// review is now + defaultDue.
func (s *CampaignScheduler) runOne(ctx context.Context, sched *models.AccessCampaignSchedule, now time.Time) error {
	in := access.StartCampaignInput{
		WorkspaceID: sched.WorkspaceID,
		Name:        sched.Name,
		DueAt:       now.Add(s.defaultDue),
	}
	if len(sched.ScopeFilter) > 0 {
		in.ScopeFilter = json.RawMessage(sched.ScopeFilter)
	}

	freq := sched.FrequencyDays
	if freq <= 0 {
		freq = 90 // PROPOSAL §9 default
	}
	next := now.Add(time.Duration(freq) * 24 * time.Hour)

	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if _, _, err := s.starter.StartCampaignTx(ctx, tx, in); err != nil {
			return fmt.Errorf("cron: start campaign for schedule_id=%s: %w", sched.ID, err)
		}
		if err := tx.
			Model(&models.AccessCampaignSchedule{}).
			Where("id = ?", sched.ID).
			Updates(map[string]interface{}{
				"next_run_at": next,
				"updated_at":  now,
			}).Error; err != nil {
			return fmt.Errorf("cron: bump next_run_at for schedule_id=%s: %w", sched.ID, err)
		}
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}
