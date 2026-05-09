package cron

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

// stubStarter is a tiny CampaignStarter test double that records
// each StartCampaignTx call. The optional onTx hook lets a test
// observe (or write through) the same *gorm.DB the scheduler is
// using — this is what we use to prove the bump UPDATE is rolled
// back when StartCampaignTx returns an error.
type stubStarter struct {
	calls []access.StartCampaignInput
	err   error
	onTx  func(tx *gorm.DB)
}

func (s *stubStarter) StartCampaignTx(_ context.Context, tx *gorm.DB, in access.StartCampaignInput) (*models.AccessReview, []models.AccessReviewDecision, error) {
	s.calls = append(s.calls, in)
	if s.onTx != nil {
		s.onTx(tx)
	}
	if s.err != nil {
		return nil, nil, s.err
	}
	return &models.AccessReview{ID: "01H00000000000000REVIEW0001", WorkspaceID: in.WorkspaceID, Name: in.Name}, nil, nil
}

func newSchedDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&models.AccessCampaignSchedule{}); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}
	return db
}

func seedSchedule(t *testing.T, db *gorm.DB, id string, nextRunAt time.Time, active bool, freq int) {
	t.Helper()
	row := &models.AccessCampaignSchedule{
		ID:            id,
		WorkspaceID:   "01H000000000000000WORKSPACE",
		Name:          "Q4 access check-up",
		FrequencyDays: freq,
		NextRunAt:     nextRunAt,
		IsActive:      active,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
	if err := db.Create(row).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
	// GORM's `default:true` tag overrides an explicit `false` on
	// Create (it treats false as the zero-value for bool). Force the
	// row to the desired value via an explicit UPDATE so the
	// is_active=false case actually exercises the inactive path.
	if !active {
		if err := db.Model(&models.AccessCampaignSchedule{}).
			Where("id = ?", id).
			Update("is_active", false).Error; err != nil {
			t.Fatalf("seed inactive: %v", err)
		}
	}
}

func TestRun_StartsDueSchedules(t *testing.T) {
	db := newSchedDB(t)
	starter := &stubStarter{}
	now := time.Date(2025, 12, 1, 12, 0, 0, 0, time.UTC)

	seedSchedule(t, db, "01H00000000000000SCHED0001", now.Add(-1*time.Hour), true, 90)
	seedSchedule(t, db, "01H00000000000000SCHED0002", now.Add(1*time.Hour), true, 90) // future
	seedSchedule(t, db, "01H00000000000000SCHED0003", now.Add(-1*time.Hour), false, 90) // inactive

	s := NewCampaignScheduler(db, starter)
	s.SetClock(func() time.Time { return now })
	if err := s.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(starter.calls) != 1 {
		t.Fatalf("StartCampaign calls = %d; want 1", len(starter.calls))
	}
	if starter.calls[0].Name != "Q4 access check-up" {
		t.Fatalf("Name = %q", starter.calls[0].Name)
	}

	// And the bumped NextRunAt is +90 days from now.
	var got models.AccessCampaignSchedule
	if err := db.Where("id = ?", "01H00000000000000SCHED0001").First(&got).Error; err != nil {
		t.Fatalf("read-back: %v", err)
	}
	want := now.Add(90 * 24 * time.Hour)
	if !got.NextRunAt.Equal(want) {
		t.Fatalf("NextRunAt = %v; want %v", got.NextRunAt, want)
	}
}

func TestRun_StartCampaignErrorPreservesNextRunAt(t *testing.T) {
	db := newSchedDB(t)
	starter := &stubStarter{err: errors.New("boom")}
	now := time.Date(2025, 12, 1, 12, 0, 0, 0, time.UTC)
	originalNext := now.Add(-1 * time.Hour)
	seedSchedule(t, db, "01H00000000000000SCHED0001", originalNext, true, 90)

	s := NewCampaignScheduler(db, starter)
	s.SetClock(func() time.Time { return now })
	err := s.Run(context.Background())
	if err == nil {
		t.Fatal("Run returned nil; want non-nil")
	}

	var got models.AccessCampaignSchedule
	if err := db.Where("id = ?", "01H00000000000000SCHED0001").First(&got).Error; err != nil {
		t.Fatalf("read-back: %v", err)
	}
	if !got.NextRunAt.Equal(originalNext) {
		t.Fatalf("NextRunAt = %v; want unchanged %v (so retry on next Run)", got.NextRunAt, originalNext)
	}
}

// TestRun_AtomicityOnStartCampaignFailure proves the scheduler's
// commit invariant: if StartCampaignTx writes anything to the shared
// transaction and then returns an error, the entire unit of work
// (including the NextRunAt bump) MUST roll back. Concretely, we
// pre-create a sibling AccessCampaignSchedule row inside the
// scheduler's tx via the starter's onTx hook — because the starter
// then errors, the sibling insert and the NextRunAt update must
// both be absent after Run returns.
func TestRun_AtomicityOnStartCampaignFailure(t *testing.T) {
	db := newSchedDB(t)
	now := time.Date(2025, 12, 1, 12, 0, 0, 0, time.UTC)
	originalNext := now.Add(-1 * time.Hour)
	seedSchedule(t, db, "01H00000000000000SCHED0001", originalNext, true, 90)

	starter := &stubStarter{
		err: errors.New("boom"),
		onTx: func(tx *gorm.DB) {
			// Write a sibling row *inside* the scheduler's tx.
			// If the tx commits, this row will exist; if it
			// rolls back (the correct behaviour), it won't.
			sibling := &models.AccessCampaignSchedule{
				ID:            "01H00000000000000SCHEDSIB01",
				WorkspaceID:   "01H000000000000000WORKSPACE",
				Name:          "sibling",
				FrequencyDays: 90,
				NextRunAt:     now,
				IsActive:      true,
				CreatedAt:     now,
				UpdatedAt:     now,
			}
			_ = tx.Create(sibling).Error
		},
	}

	s := NewCampaignScheduler(db, starter)
	s.SetClock(func() time.Time { return now })
	if err := s.Run(context.Background()); err == nil {
		t.Fatal("Run returned nil; want non-nil")
	}

	// 1. NextRunAt must be unchanged — same invariant as the
	//    "preserves NextRunAt" test, but the point here is that
	//    it holds even though StartCampaignTx wrote through tx.
	var got models.AccessCampaignSchedule
	if err := db.Where("id = ?", "01H00000000000000SCHED0001").First(&got).Error; err != nil {
		t.Fatalf("read-back: %v", err)
	}
	if !got.NextRunAt.Equal(originalNext) {
		t.Fatalf("NextRunAt = %v; want unchanged %v (rollback failed)", got.NextRunAt, originalNext)
	}

	// 2. The sibling insert StartCampaignTx made through the
	//    shared tx must NOT be present — if it is, the bump and
	//    the campaign insert would have committed together and
	//    we'd double-fire on the next Run.
	var sibling models.AccessCampaignSchedule
	err := db.Where("id = ?", "01H00000000000000SCHEDSIB01").First(&sibling).Error
	if err == nil {
		t.Fatal("sibling row was committed; tx did not roll back")
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("unexpected error reading sibling: %v", err)
	}
}

func TestRun_DefaultFrequencyWhenZero(t *testing.T) {
	db := newSchedDB(t)
	starter := &stubStarter{}
	now := time.Date(2025, 12, 1, 12, 0, 0, 0, time.UTC)
	seedSchedule(t, db, "01H00000000000000SCHED0001", now.Add(-1*time.Hour), true, 0)

	s := NewCampaignScheduler(db, starter)
	s.SetClock(func() time.Time { return now })
	if err := s.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	var got models.AccessCampaignSchedule
	if err := db.Where("id = ?", "01H00000000000000SCHED0001").First(&got).Error; err != nil {
		t.Fatalf("read-back: %v", err)
	}
	want := now.Add(90 * 24 * time.Hour)
	if !got.NextRunAt.Equal(want) {
		t.Fatalf("NextRunAt = %v; want %v (default 90d frequency)", got.NextRunAt, want)
	}
}

func TestRun_NoDueRowsReturnsNil(t *testing.T) {
	db := newSchedDB(t)
	starter := &stubStarter{}
	now := time.Date(2025, 12, 1, 12, 0, 0, 0, time.UTC)
	// Future row only.
	seedSchedule(t, db, "01H00000000000000SCHED0001", now.Add(1*time.Hour), true, 90)
	s := NewCampaignScheduler(db, starter)
	s.SetClock(func() time.Time { return now })
	if err := s.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(starter.calls) != 0 {
		t.Fatalf("StartCampaign calls = %d; want 0", len(starter.calls))
	}
}

func TestRun_NilFieldsReturnError(t *testing.T) {
	var s *CampaignScheduler
	if err := s.Run(context.Background()); err == nil {
		t.Fatal("nil scheduler did not error")
	}
	s2 := &CampaignScheduler{}
	if err := s2.Run(context.Background()); err == nil {
		t.Fatal("partially wired scheduler did not error")
	}
}

func TestSetDefaultDueWindow_IgnoresZero(t *testing.T) {
	s := NewCampaignScheduler(newSchedDB(t), &stubStarter{})
	original := s.defaultDue
	s.SetDefaultDueWindow(0)
	if s.defaultDue != original {
		t.Fatalf("defaultDue changed to %v; want unchanged %v", s.defaultDue, original)
	}
	s.SetDefaultDueWindow(7 * 24 * time.Hour)
	if s.defaultDue != 7*24*time.Hour {
		t.Fatalf("defaultDue = %v; want 7d", s.defaultDue)
	}
}
