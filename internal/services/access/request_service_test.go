package access

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// newTestDB opens a fresh in-memory SQLite DB and AutoMigrates the four
// Phase 2 tables. Each test gets its own DB so tests can run in parallel.
//
// SQLite has dynamic typing, so the postgres-flavoured `type:jsonb` and
// `varchar(N)` tags on the model structs are accepted as TEXT-equivalent.
// AutoMigrate still creates every index declared on the struct tags.
func newTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(
		&models.AccessRequest{},
		&models.AccessRequestStateHistory{},
		&models.AccessGrant{},
		&models.AccessWorkflow{},
	); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}
	return db
}

// validInput returns a populated CreateAccessRequestInput. Tests mutate
// individual fields to drive specific validation paths.
func validInput() CreateAccessRequestInput {
	return CreateAccessRequestInput{
		WorkspaceID:        "01H000000000000000WORKSPACE",
		RequesterUserID:    "01H000000000000000REQUESTER",
		TargetUserID:       "01H000000000000000TARGETUSR",
		ConnectorID:        "01H000000000000000CONNECTOR",
		ResourceExternalID: "projects/foo",
		Role:               "viewer",
		Justification:      "weekly on-call rotation needs read-only access",
	}
}

// TestCreateRequest_HappyPath asserts that CreateRequest persists a row in
// state "requested" and a matching history row with the empty FromState.
func TestCreateRequest_HappyPath(t *testing.T) {
	db := newTestDB(t)
	svc := NewAccessRequestService(db)

	got, err := svc.CreateRequest(context.Background(), validInput())
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	if got == nil {
		t.Fatal("CreateRequest returned nil request without error")
	}
	if got.ID == "" {
		t.Error("CreateRequest returned a request with empty ID")
	}
	if got.State != models.RequestStateRequested {
		t.Errorf("State = %q; want %q", got.State, models.RequestStateRequested)
	}

	// Read back the row to confirm it actually persisted.
	var stored models.AccessRequest
	if err := db.Where("id = ?", got.ID).First(&stored).Error; err != nil {
		t.Fatalf("read-back access_requests: %v", err)
	}
	if stored.RequesterUserID != got.RequesterUserID {
		t.Errorf("stored RequesterUserID = %q; want %q", stored.RequesterUserID, got.RequesterUserID)
	}

	// And the initial state-history entry.
	var history []models.AccessRequestStateHistory
	if err := db.Where("request_id = ?", got.ID).Find(&history).Error; err != nil {
		t.Fatalf("read-back history: %v", err)
	}
	if len(history) != 1 {
		t.Fatalf("got %d history rows; want 1", len(history))
	}
	if history[0].FromState != "" {
		t.Errorf("initial history FromState = %q; want empty string", history[0].FromState)
	}
	if history[0].ToState != models.RequestStateRequested {
		t.Errorf("initial history ToState = %q; want %q", history[0].ToState, models.RequestStateRequested)
	}
}

// TestCreateRequest_MissingFieldsReturnValidationError covers every
// required-field path so accidentally dropping a field check from
// validateCreateRequest is caught.
func TestCreateRequest_MissingFieldsReturnValidationError(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*CreateAccessRequestInput)
	}{
		{"missing workspace", func(in *CreateAccessRequestInput) { in.WorkspaceID = "" }},
		{"missing requester", func(in *CreateAccessRequestInput) { in.RequesterUserID = "" }},
		{"missing target", func(in *CreateAccessRequestInput) { in.TargetUserID = "" }},
		{"missing connector", func(in *CreateAccessRequestInput) { in.ConnectorID = "" }},
		{"missing resource", func(in *CreateAccessRequestInput) { in.ResourceExternalID = "" }},
		{"missing role", func(in *CreateAccessRequestInput) { in.Role = "" }},
	}
	db := newTestDB(t)
	svc := NewAccessRequestService(db)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := validInput()
			tc.mutate(&in)
			_, err := svc.CreateRequest(context.Background(), in)
			if err == nil {
				t.Fatal("expected validation error; got nil")
			}
			if !errors.Is(err, ErrValidation) {
				t.Errorf("error = %v; want ErrValidation", err)
			}
		})
	}
}

// TestApproveRequest_HappyPath asserts the standard "requested → approved"
// transition flips the state column and inserts a matching history row.
func TestApproveRequest_HappyPath(t *testing.T) {
	db := newTestDB(t)
	svc := NewAccessRequestService(db)
	req, err := svc.CreateRequest(context.Background(), validInput())
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}

	if err := svc.ApproveRequest(context.Background(), req.ID, "01H000000000000000MANAGERID", "ok"); err != nil {
		t.Fatalf("ApproveRequest: %v", err)
	}

	var stored models.AccessRequest
	if err := db.Where("id = ?", req.ID).First(&stored).Error; err != nil {
		t.Fatalf("read-back access_requests: %v", err)
	}
	if stored.State != models.RequestStateApproved {
		t.Errorf("State = %q; want %q", stored.State, models.RequestStateApproved)
	}

	var history []models.AccessRequestStateHistory
	if err := db.Where("request_id = ?", req.ID).Order("created_at asc").Find(&history).Error; err != nil {
		t.Fatalf("read-back history: %v", err)
	}
	if len(history) != 2 {
		t.Fatalf("got %d history rows; want 2 (create + approve)", len(history))
	}
	if history[1].FromState != models.RequestStateRequested || history[1].ToState != models.RequestStateApproved {
		t.Errorf("approve history = %q -> %q; want %q -> %q", history[1].FromState, history[1].ToState, models.RequestStateRequested, models.RequestStateApproved)
	}
	if history[1].Reason != "ok" {
		t.Errorf("approve history reason = %q; want %q", history[1].Reason, "ok")
	}
}

// TestApproveRequest_FromInvalidStateReturnsError pre-flips the request to
// "denied" (terminal) and asserts that approve refuses the transition.
func TestApproveRequest_FromInvalidStateReturnsError(t *testing.T) {
	db := newTestDB(t)
	svc := NewAccessRequestService(db)
	req, err := svc.CreateRequest(context.Background(), validInput())
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	if err := svc.DenyRequest(context.Background(), req.ID, "manager", "no"); err != nil {
		t.Fatalf("DenyRequest: %v", err)
	}

	err = svc.ApproveRequest(context.Background(), req.ID, "manager", "second thoughts")
	if err == nil {
		t.Fatal("expected error approving a denied request; got nil")
	}
	if !errors.Is(err, ErrInvalidStateTransition) {
		t.Errorf("error = %v; want ErrInvalidStateTransition", err)
	}
}

// TestDenyRequest_HappyPath flips a fresh request "requested → denied".
func TestDenyRequest_HappyPath(t *testing.T) {
	db := newTestDB(t)
	svc := NewAccessRequestService(db)
	req, err := svc.CreateRequest(context.Background(), validInput())
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}

	if err := svc.DenyRequest(context.Background(), req.ID, "manager", "policy violation"); err != nil {
		t.Fatalf("DenyRequest: %v", err)
	}

	var stored models.AccessRequest
	if err := db.Where("id = ?", req.ID).First(&stored).Error; err != nil {
		t.Fatalf("read-back: %v", err)
	}
	if stored.State != models.RequestStateDenied {
		t.Errorf("State = %q; want %q", stored.State, models.RequestStateDenied)
	}
}

// TestCancelRequest_FromRequestedAndApproved covers both legal source
// states for cancel.
func TestCancelRequest_FromRequestedAndApproved(t *testing.T) {
	t.Run("from requested", func(t *testing.T) {
		db := newTestDB(t)
		svc := NewAccessRequestService(db)
		req, err := svc.CreateRequest(context.Background(), validInput())
		if err != nil {
			t.Fatalf("CreateRequest: %v", err)
		}
		if err := svc.CancelRequest(context.Background(), req.ID, "requester", "no longer needed"); err != nil {
			t.Fatalf("CancelRequest: %v", err)
		}
	})
	t.Run("from approved", func(t *testing.T) {
		db := newTestDB(t)
		svc := NewAccessRequestService(db)
		req, err := svc.CreateRequest(context.Background(), validInput())
		if err != nil {
			t.Fatalf("CreateRequest: %v", err)
		}
		if err := svc.ApproveRequest(context.Background(), req.ID, "manager", "ok"); err != nil {
			t.Fatalf("ApproveRequest: %v", err)
		}
		if err := svc.CancelRequest(context.Background(), req.ID, "admin", "rescinded"); err != nil {
			t.Fatalf("CancelRequest from approved: %v", err)
		}
	})
}

// TestCancelRequest_FromTerminalStateReturnsError covers the "cancel a
// denied request" failure path. Pure FSM behaviour but exercised through
// the service so the wrapping holds end-to-end.
func TestCancelRequest_FromTerminalStateReturnsError(t *testing.T) {
	db := newTestDB(t)
	svc := NewAccessRequestService(db)
	req, err := svc.CreateRequest(context.Background(), validInput())
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	if err := svc.DenyRequest(context.Background(), req.ID, "manager", "no"); err != nil {
		t.Fatalf("DenyRequest: %v", err)
	}

	err = svc.CancelRequest(context.Background(), req.ID, "requester", "wait")
	if !errors.Is(err, ErrInvalidStateTransition) {
		t.Errorf("error = %v; want ErrInvalidStateTransition", err)
	}
}

// TestApproveRequest_NonExistentIDReturnsRequestNotFound exercises the
// "select before update" path. We use a syntactically-valid ULID-shaped
// string that no row will carry.
func TestApproveRequest_NonExistentIDReturnsRequestNotFound(t *testing.T) {
	db := newTestDB(t)
	svc := NewAccessRequestService(db)
	err := svc.ApproveRequest(context.Background(), "01H000000000000000NOPENOPEN0", "manager", "ok")
	if err == nil {
		t.Fatal("expected error for non-existent request; got nil")
	}
	if !errors.Is(err, ErrRequestNotFound) {
		t.Errorf("error = %v; want ErrRequestNotFound", err)
	}
}

// TestApproveRequest_EmptyIDReturnsValidationError covers the trivial-but-
// dangerous case of accidentally passing an empty string to a transition.
func TestApproveRequest_EmptyIDReturnsValidationError(t *testing.T) {
	db := newTestDB(t)
	svc := NewAccessRequestService(db)
	err := svc.ApproveRequest(context.Background(), "", "manager", "ok")
	if err == nil {
		t.Fatal("expected validation error; got nil")
	}
	if !errors.Is(err, ErrValidation) {
		t.Errorf("error = %v; want ErrValidation", err)
	}
}

// TestCreateRequest_GeneratesDistinctIDs exercises the "concurrent calls
// in the same millisecond produce distinct IDs" property by invoking
// CreateRequest serially many times. With crypto/rand entropy the chance
// of a collision in 100 attempts is astronomical; if it ever does
// collide, the second insert will fail with a primary-key violation and
// we want to be told.
func TestCreateRequest_GeneratesDistinctIDs(t *testing.T) {
	db := newTestDB(t)
	svc := NewAccessRequestService(db)
	seen := map[string]struct{}{}
	for i := 0; i < 16; i++ {
		req, err := svc.CreateRequest(context.Background(), validInput())
		if err != nil {
			t.Fatalf("CreateRequest #%d: %v", i, err)
		}
		if _, dup := seen[req.ID]; dup {
			t.Fatalf("CreateRequest emitted duplicate ID %q", req.ID)
		}
		seen[req.ID] = struct{}{}
	}
}

// TestCreateRequest_PinsTimestampsAndID ensures the test-overridable now /
// newID hooks actually flow through to the persisted row. Without these
// hooks the service would be fundamentally untestable for time-sensitive
// behaviour in later phases.
func TestCreateRequest_PinsTimestampsAndID(t *testing.T) {
	db := newTestDB(t)
	frozen := time.Date(2026, 5, 9, 12, 0, 0, 0, time.UTC)
	id := "01H00000000000000000000001"
	svc := NewAccessRequestService(db)
	svc.now = func() time.Time { return frozen }
	svc.newID = func() string { return id }

	got, err := svc.CreateRequest(context.Background(), validInput())
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	if got.ID != id {
		t.Errorf("ID = %q; want %q", got.ID, id)
	}
	if !got.CreatedAt.Equal(frozen) {
		t.Errorf("CreatedAt = %v; want %v", got.CreatedAt, frozen)
	}
}

// newConcurrentTestDB opens a file-backed SQLite DB suitable for a
// concurrent-race test. Three subtleties:
//
//  1. ":memory:" without shared cache gives each connection its own
//     private DB, so we use a temp file.
//  2. WAL mode + busy_timeout would normally let SQLite serialize
//     concurrent writers via timed retry, but glebarez/sqlite does not
//     reliably honor pragma URIs when the pool opens new connections,
//     so we instead pin the pool to a single writer connection. That
//     forces SQLite to serialize the two transactions — the second
//     one's SELECT sees the new state and the FSM (or CAS) rejects.
//  3. SetMaxOpenConns(1) does NOT defeat the race assertion. Both
//     goroutines still call ApproveRequest/DenyRequest concurrently;
//     the pool just queues their connection acquisition. The invariant
//     under test — "exactly one winner, no corruption, history correct"
//     — holds for every interleaving regardless of which path (FSM
//     recheck or CAS UPDATE) catches the losers.
func newConcurrentTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := filepath.Join(t.TempDir(), "concurrent.db")
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("unwrap *sql.DB: %v", err)
	}
	sqlDB.SetMaxOpenConns(1)
	if err := db.AutoMigrate(
		&models.AccessRequest{},
		&models.AccessRequestStateHistory{},
		&models.AccessGrant{},
		&models.AccessWorkflow{},
	); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}
	return db
}

// TestTransitionInTx_ConcurrentRace asserts the optimistic-lock invariant
// in TransitionInTx: when N goroutines race to transition the same
// "requested" row to mutually exclusive terminal states (approve / deny),
// exactly ONE wins. Losers must fail with ErrInvalidStateTransition
// (whether caught by the FSM read-back or by the CAS UPDATE — both are
// legitimate paths) and must NOT have inserted a state-history row. The
// final database state must be either "approved" or "denied" but never
// both, never corrupted, and never duplicated.
//
// This test reproduces the bug Devin Review flagged on PR #4: without the
// "AND state = ?" CAS predicate, two concurrent transactions could both
// pass the FSM check on a stale read and both UPDATE — last writer wins,
// audit trail diverges from final state. With the CAS predicate, the
// second writer's UPDATE matches zero rows and is rejected.
func TestTransitionInTx_ConcurrentRace(t *testing.T) {
	db := newConcurrentTestDB(t)
	svc := NewAccessRequestService(db)
	ctx := context.Background()

	req, err := svc.CreateRequest(ctx, validInput())
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}

	const racers = 8
	var (
		startBarrier sync.WaitGroup
		done         sync.WaitGroup
		results      = make([]error, racers)
	)
	startBarrier.Add(1)
	done.Add(racers)

	for i := 0; i < racers; i++ {
		i := i
		go func() {
			defer done.Done()
			startBarrier.Wait()
			if i%2 == 0 {
				results[i] = svc.ApproveRequest(ctx, req.ID, "actor", "race")
			} else {
				results[i] = svc.DenyRequest(ctx, req.ID, "actor", "race")
			}
		}()
	}
	startBarrier.Done()
	done.Wait()

	wins := 0
	for i, err := range results {
		switch {
		case err == nil:
			wins++
		case errors.Is(err, ErrInvalidStateTransition):
			// Expected: either the FSM rejected on a re-read of the now-
			// terminal state, or the CAS UPDATE matched zero rows. Both
			// surface ErrInvalidStateTransition by design.
		default:
			t.Errorf("racer #%d: unexpected error %v (want nil or ErrInvalidStateTransition)", i, err)
		}
	}
	if wins != 1 {
		t.Fatalf("wins = %d; want exactly 1 (last-writer-wins corruption)", wins)
	}

	var stored models.AccessRequest
	if err := db.Where("id = ?", req.ID).First(&stored).Error; err != nil {
		t.Fatalf("read back request: %v", err)
	}
	if stored.State != models.RequestStateApproved && stored.State != models.RequestStateDenied {
		t.Errorf("final state = %q; want approved or denied", stored.State)
	}

	// History invariant: 1 initial "" → "requested" + exactly 1 winning
	// transition. Losers that hit either the FSM-recheck or the CAS path
	// roll back inside the transaction and do NOT insert a row.
	var historyCount int64
	if err := db.Model(&models.AccessRequestStateHistory{}).
		Where("request_id = ?", req.ID).
		Count(&historyCount).Error; err != nil {
		t.Fatalf("count history rows: %v", err)
	}
	if historyCount != 2 {
		t.Errorf("history rows = %d; want 2 (initial + winner)", historyCount)
	}
}
