package access

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// TestAccessRequestService_GetRequest_HappyPath: create a request,
// approve it, then fetch the detail. Assert both the row and the
// state-history rows come back ordered oldest-first.
func TestAccessRequestService_GetRequest_HappyPath(t *testing.T) {
	db := newTestDB(t)
	svc := NewAccessRequestService(db)
	ctx := context.Background()

	created, err := svc.CreateRequest(ctx, validInput())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := svc.ApproveRequest(ctx, created.ID, "01H000000000000000ACTORUSRID", "manager approved"); err != nil {
		t.Fatalf("approve: %v", err)
	}

	got, err := svc.GetRequest(ctx, created.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got == nil {
		t.Fatal("got = nil")
	}
	if got.Request.ID != created.ID {
		t.Fatalf("Request.ID = %q; want %q", got.Request.ID, created.ID)
	}
	if len(got.History) < 2 {
		t.Fatalf("len(History) = %d; want >= 2 (created + approve)", len(got.History))
	}
	// Verify ordering is oldest-first so the UI does not have to
	// re-sort client-side. CreatedAt of [0] must be <= CreatedAt of
	// [len-1].
	if got.History[0].CreatedAt.After(got.History[len(got.History)-1].CreatedAt) {
		t.Fatal("history is not oldest-first")
	}
}

// TestAccessRequestService_GetRequest_NotFound asserts the
// ErrRequestNotFound sentinel is wrapped (so errors.Is recognises
// it) when the row does not exist.
func TestAccessRequestService_GetRequest_NotFound(t *testing.T) {
	db := newTestDB(t)
	svc := NewAccessRequestService(db)
	_, err := svc.GetRequest(context.Background(), "01H000000000000000NONEXIST")
	if err == nil {
		t.Fatal("err = nil; want ErrRequestNotFound")
	}
	if !errors.Is(err, ErrRequestNotFound) {
		t.Fatalf("err = %v; want ErrRequestNotFound", err)
	}
}

// TestAccessRequestService_GetRequest_EmptyIDValidation guards the
// pre-check so an empty ID surfaces as a validation error instead
// of a wide-open SELECT.
func TestAccessRequestService_GetRequest_EmptyIDValidation(t *testing.T) {
	db := newTestDB(t)
	svc := NewAccessRequestService(db)
	_, err := svc.GetRequest(context.Background(), "")
	if !errors.Is(err, ErrValidation) {
		t.Fatalf("err = %v; want ErrValidation", err)
	}
}

// TestAccessRequestService_GetRequest_IncludesGrant asserts the
// detail surface returns the access_grants row referencing the
// request when one exists. The Admin UI uses Grant to render
// "active grant: <user> → <resource> until <expires_at>" on the
// triage page without a second round-trip.
//
// The request is forced into RequestStateProvisioned because that
// is the only path on which an access_grants row is ever written
// in production (see provisioning_service.go) — GetRequest reads
// the grant table only when the request has reached such a state.
func TestAccessRequestService_GetRequest_IncludesGrant(t *testing.T) {
	db := newTestDB(t)
	svc := NewAccessRequestService(db)
	ctx := context.Background()

	created, err := svc.CreateRequest(ctx, validInput())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	// Bypass the FSM for test setup — provisioning_service.go is
	// the production path that writes both the state and the grant
	// transactionally; tests that exercise the read API only need
	// the post-conditions, not the workflow.
	if err := db.Model(&models.AccessRequest{}).
		Where("id = ?", created.ID).
		Update("state", models.RequestStateProvisioned).Error; err != nil {
		t.Fatalf("force state to provisioned: %v", err)
	}

	requestID := created.ID
	expiresAt := time.Now().Add(7 * 24 * time.Hour).UTC()
	seedGrant := &models.AccessGrant{
		ID:                 "01H00000000000000GRANT001",
		RequestID:          &requestID,
		WorkspaceID:        created.WorkspaceID,
		UserID:             created.TargetUserID,
		ConnectorID:        created.ConnectorID,
		ResourceExternalID: created.ResourceExternalID,
		Role:               created.Role,
		GrantedAt:          time.Now().UTC(),
		ExpiresAt:          &expiresAt,
		CreatedAt:          time.Now().UTC(),
		UpdatedAt:          time.Now().UTC(),
	}
	if err := db.Create(seedGrant).Error; err != nil {
		t.Fatalf("seed grant: %v", err)
	}

	got, err := svc.GetRequest(ctx, created.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Grant == nil {
		t.Fatal("Grant = nil; want non-nil after seeding access_grants row")
	}
	if got.Grant.ID != seedGrant.ID {
		t.Fatalf("Grant.ID = %q; want %q", got.Grant.ID, seedGrant.ID)
	}
}

// TestAccessRequestService_GetRequest_SkipsGrantLookupForNonProvisioned
// pins the optimisation that GetRequest does NOT issue a grant SELECT
// when the request never reached a state that could have written one.
// This is the common path for pending / denied / cancelled requests
// on the Admin UI triage page — the wasted indexed SELECT used to add
// a round-trip per render. The assertion uses a stale grant row that
// SHOULD NOT surface in the detail because the request is still in
// RequestStateRequested.
func TestAccessRequestService_GetRequest_SkipsGrantLookupForNonProvisioned(t *testing.T) {
	db := newTestDB(t)
	svc := NewAccessRequestService(db)
	ctx := context.Background()

	created, err := svc.CreateRequest(ctx, validInput())
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	requestID := created.ID
	expiresAt := time.Now().Add(7 * 24 * time.Hour).UTC()
	stale := &models.AccessGrant{
		ID:                 "01H00000000000000GRANTSTAL",
		RequestID:          &requestID,
		WorkspaceID:        created.WorkspaceID,
		UserID:             created.TargetUserID,
		ConnectorID:        created.ConnectorID,
		ResourceExternalID: created.ResourceExternalID,
		Role:               created.Role,
		GrantedAt:          time.Now().UTC(),
		ExpiresAt:          &expiresAt,
		CreatedAt:          time.Now().UTC(),
		UpdatedAt:          time.Now().UTC(),
	}
	if err := db.Create(stale).Error; err != nil {
		t.Fatalf("seed stale grant: %v", err)
	}

	got, err := svc.GetRequest(ctx, created.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Grant != nil {
		t.Fatalf("Grant = %+v; want nil because request is still in RequestStateRequested", got.Grant)
	}
}

// TestAccessRequestService_GetRequest_NoGrantStillReturnsDetail asserts
// the absence of a grant does not cause the endpoint to fail — the
// Admin UI needs to render the request + history even for requests
// that were never provisioned (denied, cancelled, still pending).
func TestAccessRequestService_GetRequest_NoGrantStillReturnsDetail(t *testing.T) {
	db := newTestDB(t)
	svc := NewAccessRequestService(db)
	ctx := context.Background()

	created, err := svc.CreateRequest(ctx, validInput())
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	got, err := svc.GetRequest(ctx, created.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Grant != nil {
		t.Fatalf("Grant = %+v; want nil for a request with no provisioned grant", got.Grant)
	}
	if got.Request.ID != created.ID {
		t.Fatalf("Request.ID = %q; want %q", got.Request.ID, created.ID)
	}
}
