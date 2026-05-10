package cron

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

// testJSONMarshal is the internal helper that the skip-date tests
// use to materialise SkipDates payloads. Defined as a top-level alias
// so the test file's helper indirection stays trivial.
func testJSONMarshal(v interface{}) ([]byte, error) {
	return json.Marshal(v)
}

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
	seedSchedule(t, db, "01H00000000000000SCHED0002", now.Add(1*time.Hour), true, 90)   // future
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

// seedScheduleWithSkipDates is like seedSchedule but also sets the
// SkipDates JSON column. Used by the Phase 5 skip-date tests.
func seedScheduleWithSkipDates(t *testing.T, db *gorm.DB, id string, nextRunAt time.Time, skipDates []string) {
	t.Helper()
	raw, err := jsonMarshal(skipDates)
	if err != nil {
		t.Fatalf("marshal skip_dates: %v", err)
	}
	row := &models.AccessCampaignSchedule{
		ID:            id,
		WorkspaceID:   "01H000000000000000WORKSPACE",
		Name:          "Q4 access check-up",
		FrequencyDays: 90,
		NextRunAt:     nextRunAt,
		IsActive:      true,
		SkipDates:     raw,
	}
	if err := db.Create(row).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
}

// jsonMarshal is a thin wrapper around encoding/json.Marshal used by
// the skip-date tests below. We import encoding/json at the top of
// the file (added alongside the new tests).
func jsonMarshal(v interface{}) ([]byte, error) {
	return testJSONMarshal(v)
}

// TestRun_SkipsCampaignOnSkipDate validates that a schedule whose
// SkipDates list contains today bumps NextRunAt without starting a
// campaign.
func TestRun_SkipsCampaignOnSkipDate(t *testing.T) {
	db := newSchedDB(t)
	starter := &stubStarter{}
	now := time.Date(2026, 12, 25, 8, 0, 0, 0, time.UTC) // Christmas
	originalNext := now.Add(-1 * time.Hour)
	seedScheduleWithSkipDates(t, db, "01HSCHED0000000000SKIP1", originalNext, []string{"2026-12-25"})

	s := NewCampaignScheduler(db, starter)
	s.SetClock(func() time.Time { return now })
	if err := s.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(starter.calls) != 0 {
		t.Errorf("StartCampaign calls = %d; want 0 (today is a skip date)", len(starter.calls))
	}
	var got models.AccessCampaignSchedule
	if err := db.Where("id = ?", "01HSCHED0000000000SKIP1").First(&got).Error; err != nil {
		t.Fatalf("read-back: %v", err)
	}
	want := now.Add(90 * 24 * time.Hour)
	if !got.NextRunAt.Equal(want) {
		t.Errorf("NextRunAt = %v; want bumped to %v", got.NextRunAt, want)
	}
}

// TestRun_SkipDatesNotMatchingTodayRunsNormally exercises the
// non-skip path: schedules with a SkipDates list that does NOT
// contain today still start a campaign.
func TestRun_SkipDatesNotMatchingTodayRunsNormally(t *testing.T) {
	db := newSchedDB(t)
	starter := &stubStarter{}
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	originalNext := now.Add(-1 * time.Hour)
	seedScheduleWithSkipDates(t, db, "01HSCHED0000000000SKIP2", originalNext, []string{"2026-12-25", "2027-01-01"})

	s := NewCampaignScheduler(db, starter)
	s.SetClock(func() time.Time { return now })
	if err := s.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(starter.calls) != 1 {
		t.Errorf("StartCampaign calls = %d; want 1", len(starter.calls))
	}
}

// TestRun_EmptySkipDatesAlwaysRuns covers the boundary case of a
// JSON-null / empty SkipDates column — never skip.
func TestRun_EmptySkipDatesAlwaysRuns(t *testing.T) {
	db := newSchedDB(t)
	starter := &stubStarter{}
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	seedSchedule(t, db, "01HSCHED0000000000SKIP3", now.Add(-1*time.Hour), true, 90)
	s := NewCampaignScheduler(db, starter)
	s.SetClock(func() time.Time { return now })
	if err := s.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(starter.calls) != 1 {
		t.Errorf("StartCampaign calls = %d; want 1", len(starter.calls))
	}
}

// TestRun_SkipDateThenRunSequence is the Phase 5 e2e exercise that
// drives the scheduler across two ticks for the same schedule:
//   - tick 1 lands on a configured skip date → no campaign starts,
//     NextRunAt advances by FrequencyDays.
//   - tick 2 lands on a non-skip date but past the (newly bumped)
//     NextRunAt → a campaign IS started, NextRunAt advances again.
//
// This covers the back-pressure invariant that a skipped tick leaves
// the schedule in a state where the *next* fire-time is correct, not
// the current one.
func TestRun_SkipDateThenRunSequence(t *testing.T) {
	db := newSchedDB(t)
	starter := &stubStarter{}

	// Tick 1: 2026-12-25 (Christmas, configured skip date).
	tick1 := time.Date(2026, 12, 25, 8, 0, 0, 0, time.UTC)
	originalNext := tick1.Add(-1 * time.Hour)
	seedScheduleWithSkipDates(t, db, "01HSEQ0000000000SKIPRUN1", originalNext, []string{"2026-12-25"})

	s := NewCampaignScheduler(db, starter)
	s.SetClock(func() time.Time { return tick1 })
	if err := s.Run(context.Background()); err != nil {
		t.Fatalf("Run tick1: %v", err)
	}
	if len(starter.calls) != 0 {
		t.Fatalf("tick1 StartCampaign calls = %d; want 0 (today is skip date)", len(starter.calls))
	}

	// Confirm NextRunAt advanced by FrequencyDays (90).
	var afterSkip models.AccessCampaignSchedule
	if err := db.Where("id = ?", "01HSEQ0000000000SKIPRUN1").First(&afterSkip).Error; err != nil {
		t.Fatalf("read-back after skip: %v", err)
	}
	expectedNext := tick1.Add(90 * 24 * time.Hour)
	if !afterSkip.NextRunAt.Equal(expectedNext) {
		t.Fatalf("NextRunAt after skip = %v; want %v", afterSkip.NextRunAt, expectedNext)
	}

	// Tick 2: a date past the bumped NextRunAt that is NOT a skip
	// date. The scheduler must start a campaign and bump NextRunAt
	// again.
	tick2 := expectedNext.Add(2 * time.Hour) // 2 hours past the new NextRunAt
	s.SetClock(func() time.Time { return tick2 })
	if err := s.Run(context.Background()); err != nil {
		t.Fatalf("Run tick2: %v", err)
	}
	if len(starter.calls) != 1 {
		t.Fatalf("tick2 StartCampaign calls = %d; want 1 (non-skip date past NextRunAt)", len(starter.calls))
	}
	var afterRun models.AccessCampaignSchedule
	if err := db.Where("id = ?", "01HSEQ0000000000SKIPRUN1").First(&afterRun).Error; err != nil {
		t.Fatalf("read-back after run: %v", err)
	}
	expectedNext2 := tick2.Add(90 * 24 * time.Hour)
	if !afterRun.NextRunAt.Equal(expectedNext2) {
		t.Fatalf("NextRunAt after run = %v; want %v", afterRun.NextRunAt, expectedNext2)
	}
}

// TestRun_MalformedSkipDatesProceedsAsRun covers the operator-error
// path: a corrupt SkipDates JSON should NOT strand the campaign — we
// log the decode error and continue with a normal run.
func TestRun_MalformedSkipDatesProceedsAsRun(t *testing.T) {
	db := newSchedDB(t)
	starter := &stubStarter{}
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	row := &models.AccessCampaignSchedule{
		ID:            "01HSCHED0000000000SKIP4",
		WorkspaceID:   "01H000000000000000WORKSPACE",
		Name:          "Q4 access check-up",
		FrequencyDays: 90,
		NextRunAt:     now.Add(-1 * time.Hour),
		IsActive:      true,
		SkipDates:     []byte("not-json"),
	}
	if err := db.Create(row).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	s := NewCampaignScheduler(db, starter)
	s.SetClock(func() time.Time { return now })
	if err := s.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(starter.calls) != 1 {
		t.Errorf("StartCampaign calls = %d; want 1 (malformed skip dates → run normally)", len(starter.calls))
	}
}
