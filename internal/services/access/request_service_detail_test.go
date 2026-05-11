package access

import (
	"context"
	"errors"
	"testing"
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
