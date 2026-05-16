package handlers

import (
	"context"
	"net/http"
	"testing"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
	"github.com/kennguy3n/cautious-fishstick/internal/services/pam"
)

// newPAMLeaseEngine wires a router with only the PAMLeaseService
// dependency bound. The lease service is constructed without an
// AccessRequestCreator or LeaseNotifier — the handler tests don't
// exercise those collaborators.
func newPAMLeaseEngine(t *testing.T) (http.Handler, *pam.PAMLeaseService) {
	t.Helper()
	db := newTestDB(t)
	svc := pam.NewPAMLeaseService(db, nil, nil)
	r := Router(Dependencies{PAMLeaseService: svc, DisableRateLimiter: true})
	return r, svc
}

func validRequestLeaseBody() map[string]interface{} {
	return map[string]interface{}{
		"workspace_id":     "ws-1",
		"user_id":          "user-1",
		"asset_id":         "asset-1",
		"account_id":       "account-1",
		"reason":           "incident response",
		"duration_minutes": 30,
	}
}

func TestPAMLeaseHandler_RequestLease_HappyPath(t *testing.T) {
	r, _ := newPAMLeaseEngine(t)
	w := doJSON(t, r, http.MethodPost, "/pam/leases", validRequestLeaseBody())
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d body=%s; want 201", w.Code, w.Body.String())
	}
	var got models.PAMLease
	decodeJSON(t, w, &got)
	if got.ID == "" {
		t.Fatal("returned lease has empty ID")
	}
	if got.GrantedAt != nil {
		t.Fatal("freshly-requested lease must NOT be granted")
	}
}

func TestPAMLeaseHandler_RequestLease_ValidationReturns400(t *testing.T) {
	r, _ := newPAMLeaseEngine(t)
	body := validRequestLeaseBody()
	delete(body, "duration_minutes")
	w := doJSON(t, r, http.MethodPost, "/pam/leases", body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s; want 400", w.Code, w.Body.String())
	}
}

func TestPAMLeaseHandler_ListLeases_HappyPath(t *testing.T) {
	r, svc := newPAMLeaseEngine(t)
	if _, err := svc.RequestLease(context.Background(), "ws-1", pam.RequestLeaseInput{
		UserID:          "u-1",
		AssetID:         "a-1",
		AccountID:       "acc-1",
		DurationMinutes: 30,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	w := doJSON(t, r, http.MethodGet, "/pam/leases?workspace_id=ws-1", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s; want 200", w.Code, w.Body.String())
	}
	var got []models.PAMLease
	decodeJSON(t, w, &got)
	if len(got) != 1 {
		t.Fatalf("leases = %d; want 1", len(got))
	}
}

func TestPAMLeaseHandler_ListLeases_MissingWorkspaceReturns400(t *testing.T) {
	r, _ := newPAMLeaseEngine(t)
	w := doJSON(t, r, http.MethodGet, "/pam/leases", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d; want 400", w.Code)
	}
}

func TestPAMLeaseHandler_ListLeases_FiltersByUser(t *testing.T) {
	r, svc := newPAMLeaseEngine(t)
	if _, err := svc.RequestLease(context.Background(), "ws-1", pam.RequestLeaseInput{
		UserID: "u-1", AssetID: "a-1", AccountID: "acc-1", DurationMinutes: 30,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := svc.RequestLease(context.Background(), "ws-1", pam.RequestLeaseInput{
		UserID: "u-2", AssetID: "a-1", AccountID: "acc-1", DurationMinutes: 30,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	w := doJSON(t, r, http.MethodGet, "/pam/leases?workspace_id=ws-1&user_id=u-1", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200", w.Code)
	}
	var got []models.PAMLease
	decodeJSON(t, w, &got)
	if len(got) != 1 {
		t.Fatalf("leases = %d; want 1", len(got))
	}
	if got[0].UserID != "u-1" {
		t.Fatalf("user_id = %q; want u-1", got[0].UserID)
	}
}

func TestPAMLeaseHandler_ApproveLease_HappyPath(t *testing.T) {
	r, svc := newPAMLeaseEngine(t)
	lease, err := svc.RequestLease(context.Background(), "ws-1", pam.RequestLeaseInput{
		UserID: "u-1", AssetID: "a-1", AccountID: "acc-1", DurationMinutes: 30,
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	body := map[string]interface{}{
		"approver_id":      "manager-1",
		"duration_minutes": 60,
	}
	w := doJSON(t, r, http.MethodPost, "/pam/leases/"+lease.ID+"/approve", body)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s; want 200", w.Code, w.Body.String())
	}
	var got models.PAMLease
	decodeJSON(t, w, &got)
	if got.GrantedAt == nil {
		t.Fatal("approve response did not set granted_at")
	}
	if got.ApprovedBy != "manager-1" {
		t.Fatalf("approved_by = %q; want manager-1", got.ApprovedBy)
	}
}

func TestPAMLeaseHandler_ApproveLease_NotFoundReturns404(t *testing.T) {
	r, _ := newPAMLeaseEngine(t)
	body := map[string]interface{}{"approver_id": "manager-1"}
	w := doJSON(t, r, http.MethodPost, "/pam/leases/nope/approve", body)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d body=%s; want 404", w.Code, w.Body.String())
	}
}

func TestPAMLeaseHandler_RevokeLease_HappyPath(t *testing.T) {
	r, svc := newPAMLeaseEngine(t)
	lease, err := svc.RequestLease(context.Background(), "ws-1", pam.RequestLeaseInput{
		UserID: "u-1", AssetID: "a-1", AccountID: "acc-1", DurationMinutes: 30,
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	body := map[string]interface{}{"reason": "incident closed"}
	w := doJSON(t, r, http.MethodPost, "/pam/leases/"+lease.ID+"/revoke", body)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s; want 200", w.Code, w.Body.String())
	}
	var got models.PAMLease
	decodeJSON(t, w, &got)
	if got.RevokedAt == nil {
		t.Fatal("revoke response did not set revoked_at")
	}
}

func TestPAMLeaseHandler_RevokeLease_NoBodyOK(t *testing.T) {
	// The handler tolerates a missing body — reason is optional.
	r, svc := newPAMLeaseEngine(t)
	lease, err := svc.RequestLease(context.Background(), "ws-1", pam.RequestLeaseInput{
		UserID: "u-1", AssetID: "a-1", AccountID: "acc-1", DurationMinutes: 30,
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	w := doJSON(t, r, http.MethodPost, "/pam/leases/"+lease.ID+"/revoke", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s; want 200", w.Code, w.Body.String())
	}
}

func TestPAMLeaseHandler_RevokeLease_NotFoundReturns404(t *testing.T) {
	r, _ := newPAMLeaseEngine(t)
	w := doJSON(t, r, http.MethodPost, "/pam/leases/nope/revoke", map[string]string{})
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d body=%s; want 404", w.Code, w.Body.String())
	}
}
