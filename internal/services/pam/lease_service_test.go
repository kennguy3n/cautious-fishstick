package pam

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

// fakeAccessRequestCreator is a test stub for AccessRequestCreator
// that returns a deterministic AccessRequest with a fixed ID so the
// PAMLeaseService.RequestLease wiring can be asserted end-to-end
// without standing up the full AccessRequestService.
type fakeAccessRequestCreator struct {
	calls    int
	lastIn   access.CreateAccessRequestInput
	returnID string
	err      error
}

func (f *fakeAccessRequestCreator) CreateRequest(_ context.Context, in access.CreateAccessRequestInput) (*models.AccessRequest, error) {
	f.calls++
	f.lastIn = in
	if f.err != nil {
		return nil, f.err
	}
	id := f.returnID
	if id == "" {
		id = "req-stub"
	}
	return &models.AccessRequest{ID: id, WorkspaceID: in.WorkspaceID}, nil
}

// fakeLeaseNotifier captures the per-event notify calls so the
// lease service tests can verify the hook fired without requiring
// a real notification service.
type fakeLeaseNotifier struct {
	approvedCount int
	revokedCount  int
	expiredCount  int
	lastReason    string
}

func (f *fakeLeaseNotifier) NotifyLeaseApproved(_ context.Context, _ *models.PAMLease) error {
	f.approvedCount++
	return nil
}

func (f *fakeLeaseNotifier) NotifyLeaseRevoked(_ context.Context, _ *models.PAMLease, reason string) error {
	f.revokedCount++
	f.lastReason = reason
	return nil
}

func (f *fakeLeaseNotifier) NotifyLeaseExpired(_ context.Context, _ *models.PAMLease) error {
	f.expiredCount++
	return nil
}

func TestPAMLeaseService_RequestLease_HappyPath(t *testing.T) {
	creator := &fakeAccessRequestCreator{returnID: "req-001"}
	svc := NewPAMLeaseService(newPAMDB(t), creator, nil)
	lease, err := svc.RequestLease(context.Background(), "ws-1", RequestLeaseInput{
		UserID:          "user-1",
		AssetID:         "asset-1",
		AccountID:       "acct-1",
		Reason:          "deploy",
		DurationMinutes: 30,
	})
	if err != nil {
		t.Fatalf("RequestLease: %v", err)
	}
	if lease.GrantedAt != nil {
		t.Fatalf("granted_at should be nil for newly requested lease")
	}
	if lease.RequestID != "req-001" {
		t.Fatalf("request id = %q; want req-001", lease.RequestID)
	}
	if creator.calls != 1 {
		t.Fatalf("creator calls = %d", creator.calls)
	}
	if creator.lastIn.Role != "pam_session" {
		t.Fatalf("role = %q; want pam_session", creator.lastIn.Role)
	}
}

func TestPAMLeaseService_RequestLease_Validation(t *testing.T) {
	svc := NewPAMLeaseService(newPAMDB(t), nil, nil)
	cases := []struct {
		name string
		ws   string
		in   RequestLeaseInput
	}{
		{"missing workspace", "", RequestLeaseInput{UserID: "u", AssetID: "a", AccountID: "c", DurationMinutes: 1}},
		{"missing user", "ws", RequestLeaseInput{AssetID: "a", AccountID: "c", DurationMinutes: 1}},
		{"missing asset", "ws", RequestLeaseInput{UserID: "u", AccountID: "c", DurationMinutes: 1}},
		{"missing account", "ws", RequestLeaseInput{UserID: "u", AssetID: "a", DurationMinutes: 1}},
		{"zero duration", "ws", RequestLeaseInput{UserID: "u", AssetID: "a", AccountID: "c"}},
		{"too long", "ws", RequestLeaseInput{UserID: "u", AssetID: "a", AccountID: "c", DurationMinutes: 24*60 + 1}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := svc.RequestLease(context.Background(), tc.ws, tc.in)
			if !errors.Is(err, ErrValidation) {
				t.Fatalf("err = %v; want ErrValidation", err)
			}
		})
	}
}

func TestPAMLeaseService_RequestLease_NilCreator(t *testing.T) {
	svc := NewPAMLeaseService(newPAMDB(t), nil, nil)
	lease, err := svc.RequestLease(context.Background(), "ws-1", RequestLeaseInput{
		UserID:          "u",
		AssetID:         "a",
		AccountID:       "c",
		DurationMinutes: 30,
	})
	if err != nil {
		t.Fatalf("RequestLease: %v", err)
	}
	if lease.RequestID != "" {
		t.Fatalf("request_id = %q; want empty when creator is nil", lease.RequestID)
	}
}

func TestPAMLeaseService_ApproveLease_SetsGrantedAndExpires(t *testing.T) {
	notif := &fakeLeaseNotifier{}
	svc := NewPAMLeaseService(newPAMDB(t), &fakeAccessRequestCreator{}, notif)
	lease, err := svc.RequestLease(context.Background(), "ws-1", RequestLeaseInput{
		UserID: "u", AssetID: "a", AccountID: "c", DurationMinutes: 30,
	})
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	approved, err := svc.ApproveLease(context.Background(), lease.ID, "approver-1", 30)
	if err != nil {
		t.Fatalf("ApproveLease: %v", err)
	}
	if approved.GrantedAt == nil {
		t.Fatalf("granted_at not set")
	}
	if approved.ExpiresAt == nil {
		t.Fatalf("expires_at not set")
	}
	if approved.ApprovedBy != "approver-1" {
		t.Fatalf("approved_by = %q", approved.ApprovedBy)
	}
	if notif.approvedCount != 1 {
		t.Fatalf("approved notifications = %d", notif.approvedCount)
	}
}

func TestPAMLeaseService_ApproveLease_IdempotentOnSecondCall(t *testing.T) {
	svc := NewPAMLeaseService(newPAMDB(t), &fakeAccessRequestCreator{}, nil)
	lease, err := svc.RequestLease(context.Background(), "ws-1", RequestLeaseInput{
		UserID: "u", AssetID: "a", AccountID: "c", DurationMinutes: 30,
	})
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	first, err := svc.ApproveLease(context.Background(), lease.ID, "approver-1", 30)
	if err != nil {
		t.Fatalf("first approve: %v", err)
	}
	second, err := svc.ApproveLease(context.Background(), lease.ID, "approver-2", 30)
	if err != nil {
		t.Fatalf("second approve: %v", err)
	}
	if !first.GrantedAt.Equal(*second.GrantedAt) {
		t.Fatalf("second approve mutated granted_at")
	}
}

func TestPAMLeaseService_ApproveLease_RejectsRevoked(t *testing.T) {
	svc := NewPAMLeaseService(newPAMDB(t), &fakeAccessRequestCreator{}, nil)
	lease, err := svc.RequestLease(context.Background(), "ws-1", RequestLeaseInput{
		UserID: "u", AssetID: "a", AccountID: "c", DurationMinutes: 30,
	})
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	if _, err := svc.RevokeLease(context.Background(), lease.ID, "test"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	_, err = svc.ApproveLease(context.Background(), lease.ID, "approver", 30)
	if !errors.Is(err, ErrLeaseAlreadyTerminal) {
		t.Fatalf("err = %v; want ErrLeaseAlreadyTerminal", err)
	}
}

func TestPAMLeaseService_ApproveLease_NotFound(t *testing.T) {
	svc := NewPAMLeaseService(newPAMDB(t), nil, nil)
	_, err := svc.ApproveLease(context.Background(), "nope", "approver", 30)
	if !errors.Is(err, ErrLeaseNotFound) {
		t.Fatalf("err = %v; want ErrLeaseNotFound", err)
	}
}

func TestPAMLeaseService_RevokeLease_SetsRevoked(t *testing.T) {
	notif := &fakeLeaseNotifier{}
	svc := NewPAMLeaseService(newPAMDB(t), &fakeAccessRequestCreator{}, notif)
	lease, err := svc.RequestLease(context.Background(), "ws-1", RequestLeaseInput{
		UserID: "u", AssetID: "a", AccountID: "c", DurationMinutes: 30,
	})
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	revoked, err := svc.RevokeLease(context.Background(), lease.ID, "policy violation")
	if err != nil {
		t.Fatalf("RevokeLease: %v", err)
	}
	if revoked.RevokedAt == nil {
		t.Fatalf("revoked_at not set")
	}
	if notif.revokedCount != 1 || notif.lastReason != "policy violation" {
		t.Fatalf("revoke notify: count=%d reason=%q", notif.revokedCount, notif.lastReason)
	}
}

func TestPAMLeaseService_RevokeLease_Idempotent(t *testing.T) {
	svc := NewPAMLeaseService(newPAMDB(t), &fakeAccessRequestCreator{}, nil)
	lease, err := svc.RequestLease(context.Background(), "ws-1", RequestLeaseInput{
		UserID: "u", AssetID: "a", AccountID: "c", DurationMinutes: 30,
	})
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	first, err := svc.RevokeLease(context.Background(), lease.ID, "r1")
	if err != nil {
		t.Fatalf("first revoke: %v", err)
	}
	second, err := svc.RevokeLease(context.Background(), lease.ID, "r2")
	if err != nil {
		t.Fatalf("second revoke: %v", err)
	}
	if !first.RevokedAt.Equal(*second.RevokedAt) {
		t.Fatalf("revoked_at mutated on second revoke")
	}
}

func TestPAMLeaseService_GetLease_ScopedByWorkspace(t *testing.T) {
	svc := NewPAMLeaseService(newPAMDB(t), &fakeAccessRequestCreator{}, nil)
	lease, err := svc.RequestLease(context.Background(), "ws-1", RequestLeaseInput{
		UserID: "u", AssetID: "a", AccountID: "c", DurationMinutes: 30,
	})
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	if _, err := svc.GetLease(context.Background(), "ws-1", lease.ID); err != nil {
		t.Fatalf("GetLease ws-1: %v", err)
	}
	_, err = svc.GetLease(context.Background(), "ws-other", lease.ID)
	if !errors.Is(err, ErrLeaseNotFound) {
		t.Fatalf("cross-workspace = %v; want ErrLeaseNotFound", err)
	}
}

func TestPAMLeaseService_ListActiveLeases_FiltersCorrectly(t *testing.T) {
	now := time.Now().UTC()
	svc := NewPAMLeaseService(newPAMDB(t), &fakeAccessRequestCreator{}, nil)
	svc.now = func() time.Time { return now }

	// Seed three leases manually with various states.
	past := now.Add(-1 * time.Hour)
	future := now.Add(1 * time.Hour)
	rows := []*models.PAMLease{
		{ID: NewULID(), WorkspaceID: "ws-1", UserID: "u", AssetID: "a", AccountID: "c", GrantedAt: &past, ExpiresAt: &future, CreatedAt: now, UpdatedAt: now}, // active
		{ID: NewULID(), WorkspaceID: "ws-1", UserID: "u", AssetID: "a", AccountID: "c", GrantedAt: &past, ExpiresAt: &past, CreatedAt: now, UpdatedAt: now},   // expired (no revoked_at)
		{ID: NewULID(), WorkspaceID: "ws-1", UserID: "u", AssetID: "a", AccountID: "c", GrantedAt: &past, ExpiresAt: &future, RevokedAt: &now, CreatedAt: now, UpdatedAt: now}, // revoked
		{ID: NewULID(), WorkspaceID: "ws-1", UserID: "u", AssetID: "a", AccountID: "c", CreatedAt: now, UpdatedAt: now}, // requested only
	}
	for _, r := range rows {
		if err := svc.db.Create(r).Error; err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	active, err := svc.ListActiveLeases(context.Background(), "ws-1")
	if err != nil {
		t.Fatalf("ListActiveLeases: %v", err)
	}
	if len(active) != 1 {
		t.Fatalf("active = %d; want 1", len(active))
	}
	if active[0].ID != rows[0].ID {
		t.Fatalf("active id = %q; want %q", active[0].ID, rows[0].ID)
	}
}

func TestPAMLeaseService_ListLeases_FiltersByUserAndAsset(t *testing.T) {
	now := time.Now().UTC()
	svc := NewPAMLeaseService(newPAMDB(t), &fakeAccessRequestCreator{}, nil)
	mk := func(user, asset string) {
		if err := svc.db.Create(&models.PAMLease{
			ID: NewULID(), WorkspaceID: "ws-1", UserID: user, AssetID: asset, AccountID: "c",
			CreatedAt: now, UpdatedAt: now,
		}).Error; err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	mk("u1", "a1")
	mk("u1", "a2")
	mk("u2", "a1")

	out, err := svc.ListLeases(context.Background(), "ws-1", ListLeasesFilters{UserID: "u1"})
	if err != nil {
		t.Fatalf("ListLeases user filter: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("u1 leases = %d; want 2", len(out))
	}
	out, err = svc.ListLeases(context.Background(), "ws-1", ListLeasesFilters{AssetID: "a1"})
	if err != nil {
		t.Fatalf("ListLeases asset filter: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("a1 leases = %d; want 2", len(out))
	}
}

func TestPAMLeaseService_ExpireLeases_BulkExpiry(t *testing.T) {
	now := time.Now().UTC()
	svc := NewPAMLeaseService(newPAMDB(t), &fakeAccessRequestCreator{}, nil)
	svc.now = func() time.Time { return now }

	past := now.Add(-1 * time.Hour)
	future := now.Add(1 * time.Hour)
	for i := 0; i < 3; i++ {
		if err := svc.db.Create(&models.PAMLease{
			ID: NewULID(), WorkspaceID: "ws", UserID: "u", AssetID: "a", AccountID: "c",
			GrantedAt: &past, ExpiresAt: &past, CreatedAt: now, UpdatedAt: now,
		}).Error; err != nil {
			t.Fatalf("seed expired %d: %v", i, err)
		}
	}
	// Active leases must NOT be swept.
	for i := 0; i < 2; i++ {
		if err := svc.db.Create(&models.PAMLease{
			ID: NewULID(), WorkspaceID: "ws", UserID: "u", AssetID: "a", AccountID: "c",
			GrantedAt: &past, ExpiresAt: &future, CreatedAt: now, UpdatedAt: now,
		}).Error; err != nil {
			t.Fatalf("seed active %d: %v", i, err)
		}
	}
	count, err := svc.ExpireLeases(context.Background())
	if err != nil {
		t.Fatalf("ExpireLeases: %v", err)
	}
	if count != 3 {
		t.Fatalf("expired = %d; want 3", count)
	}
	// Active leases should still be unrevoked.
	var active int64
	svc.db.Model(&models.PAMLease{}).Where("revoked_at IS NULL").Count(&active)
	if active != 2 {
		t.Fatalf("active remaining = %d; want 2", active)
	}
}

func TestPAMLeaseService_ExpireLeases_EmptyTable(t *testing.T) {
	svc := NewPAMLeaseService(newPAMDB(t), nil, nil)
	count, err := svc.ExpireLeases(context.Background())
	if err != nil {
		t.Fatalf("ExpireLeases empty: %v", err)
	}
	if count != 0 {
		t.Fatalf("empty = %d; want 0", count)
	}
}

func TestPAMLeaseService_ExpiredLeases_ListsOverdueOnly(t *testing.T) {
	now := time.Now().UTC()
	svc := NewPAMLeaseService(newPAMDB(t), nil, nil)
	svc.now = func() time.Time { return now }
	past := now.Add(-1 * time.Hour)
	future := now.Add(1 * time.Hour)
	if err := svc.db.Create(&models.PAMLease{
		ID: NewULID(), WorkspaceID: "ws", UserID: "u", AssetID: "a", AccountID: "c",
		GrantedAt: &past, ExpiresAt: &past, CreatedAt: now, UpdatedAt: now,
	}).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := svc.db.Create(&models.PAMLease{
		ID: NewULID(), WorkspaceID: "ws", UserID: "u", AssetID: "a", AccountID: "c",
		GrantedAt: &past, ExpiresAt: &future, CreatedAt: now, UpdatedAt: now,
	}).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
	out, err := svc.ExpiredLeases(context.Background(), 100)
	if err != nil {
		t.Fatalf("ExpiredLeases: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("overdue = %d; want 1", len(out))
	}
}

func TestPAMLeaseService_NotifyExpired_NoopWhenNotifierNil(t *testing.T) {
	svc := NewPAMLeaseService(newPAMDB(t), nil, nil)
	svc.NotifyExpired(context.Background(), []models.PAMLease{{ID: "x"}})
}

func TestPAMLeaseService_NotifyExpired_FiresOnceForEach(t *testing.T) {
	notif := &fakeLeaseNotifier{}
	svc := NewPAMLeaseService(newPAMDB(t), nil, notif)
	svc.NotifyExpired(context.Background(), []models.PAMLease{{ID: "1"}, {ID: "2"}, {ID: "3"}})
	if notif.expiredCount != 3 {
		t.Fatalf("expired notifications = %d; want 3", notif.expiredCount)
	}
}
