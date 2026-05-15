package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

// TestAccessRevoke_NilConnector_JobFailed verifies that when the
// resolver fails to find the AccessConnector, the worker handler
// marks the job failed rather than panicking.
func TestAccessRevoke_NilConnector_JobFailed(t *testing.T) {
	db := newHandlerDB(t)
	seedTestConnector(t, db, "01HCONNNILREVK00000000A", "test_provider")
	seedJob(t, db, "01HJOBNILREVK00000000001", "01HCONNNILREVK00000000A", models.AccessJobTypeRevokeAccess, revokeAccessPayload{
		UserExternalID:     "alice",
		ResourceExternalID: "r-1",
		Role:               "admin",
	})

	jc := JobContext{
		DB: db,
		Resolve: func(_ string) (access.AccessConnector, error) {
			return nil, access.ErrConnectorNotFound
		},
		LoadConn: DefaultLoadConnector,
		Now:      time.Now,
	}
	err := AccessRevoke(context.Background(), jc, "01HJOBNILREVK00000000001")
	if err == nil {
		t.Fatal("expected error for missing connector")
	}
	if !errors.Is(err, access.ErrConnectorNotFound) {
		t.Errorf("err = %v; want wraps ErrConnectorNotFound", err)
	}
	j := readJob(t, db, "01HJOBNILREVK00000000001")
	if j.Status != models.AccessJobStatusFailed {
		t.Errorf("status = %q; want failed", j.Status)
	}
}

// TestAccessRevoke_IdempotentReRevoke_BothComplete asserts the
// AccessConnector contract requirement that RevokeAccess is
// idempotent: a second job for the same grant after the first
// has completed must succeed. The handler does not enforce this
// itself; it relies on the connector contract. This test wires a
// real httptest upstream that treats every call as success and
// drives two back-to-back revoke jobs.
func TestAccessRevoke_IdempotentReRevoke_BothComplete(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)

	db := newHandlerDB(t)
	seedTestConnector(t, db, "01HCONNIDEMREVK0000000A", "test_provider")
	mock := &access.MockAccessConnector{
		FuncRevokeAccess: func(_ context.Context, _, _ map[string]interface{}, _ access.AccessGrant) error {
			resp, err := http.Get(srv.URL + "/revoke")
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			if resp.StatusCode/100 != 2 {
				return errors.New("non-2xx")
			}
			return nil
		},
	}

	for i, jobID := range []string{"01HJOBIDEMREVK0000000001", "01HJOBIDEMREVK0000000002"} {
		seedJob(t, db, jobID, "01HCONNIDEMREVK0000000A", models.AccessJobTypeRevokeAccess, revokeAccessPayload{
			UserExternalID:     "alice",
			ResourceExternalID: "r-1",
			Role:               "admin",
		})
		if err := AccessRevoke(context.Background(), newJC(db, mock), jobID); err != nil {
			t.Fatalf("AccessRevoke #%d: %v", i, err)
		}
		j := readJob(t, db, jobID)
		if j.Status != models.AccessJobStatusCompleted {
			t.Errorf("job %d status = %q; want completed", i, j.Status)
		}
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("upstream calls = %d; want 2 (one per job)", got)
	}
}

// TestAccessRevoke_Upstream500_JobFailed wires the handler against
// a real httptest upstream returning HTTP 500 and verifies the
// resulting connector error lands on access_jobs.last_error.
func TestAccessRevoke_Upstream500_JobFailed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"boom"}`))
	}))
	t.Cleanup(srv.Close)

	db := newHandlerDB(t)
	seedTestConnector(t, db, "01HCONNCONNERR0000000A", "test_provider")
	seedJob(t, db, "01HJOBCONNERR0000000001", "01HCONNCONNERR0000000A", models.AccessJobTypeRevokeAccess, revokeAccessPayload{
		UserExternalID:     "alice",
		ResourceExternalID: "r-1",
		Role:               "admin",
	})

	mock := &access.MockAccessConnector{
		FuncRevokeAccess: func(_ context.Context, _, _ map[string]interface{}, _ access.AccessGrant) error {
			resp, err := http.Get(srv.URL + "/revoke")
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			if resp.StatusCode >= 500 {
				return errors.New("test_provider: revoke: upstream 500")
			}
			return nil
		},
	}
	err := AccessRevoke(context.Background(), newJC(db, mock), "01HJOBCONNERR0000000001")
	if err == nil {
		t.Fatal("expected error from upstream 500")
	}
	j := readJob(t, db, "01HJOBCONNERR0000000001")
	if j.Status != models.AccessJobStatusFailed {
		t.Errorf("status = %q; want failed", j.Status)
	}
	if !strings.Contains(j.LastError, "upstream 500") {
		t.Errorf("last_error = %q; want to contain 'upstream 500'", j.LastError)
	}
}

// TestAccessRevoke_MissingGrant_PayloadFieldsAbsent verifies that
// even when the payload's UserExternalID/ResourceExternalID/Role
// are blank, the handler still dispatches to the connector — the
// connector's RevokeAccess contract treats a missing grant as
// idempotent success per docs/PROPOSAL §5.4. The handler must NOT
// short-circuit on missing fields; that policy lives at the
// connector layer.
func TestAccessRevoke_MissingGrant_HandlerDispatchesAnyway(t *testing.T) {
	db := newHandlerDB(t)
	seedTestConnector(t, db, "01HCONNMISSREVK0000000A", "test_provider")
	seedJob(t, db, "01HJOBMISSREVK0000000001", "01HCONNMISSREVK0000000A", models.AccessJobTypeRevokeAccess, revokeAccessPayload{})

	var captured access.AccessGrant
	called := false
	mock := &access.MockAccessConnector{
		FuncRevokeAccess: func(_ context.Context, _, _ map[string]interface{}, g access.AccessGrant) error {
			called = true
			captured = g
			// Connectors treat the empty grant as a no-op success;
			// any error mapping happens upstream.
			return nil
		},
	}
	if err := AccessRevoke(context.Background(), newJC(db, mock), "01HJOBMISSREVK0000000001"); err != nil {
		t.Fatalf("AccessRevoke: %v", err)
	}
	if !called {
		t.Fatal("expected connector RevokeAccess to be invoked")
	}
	if captured.UserExternalID != "" || captured.ResourceExternalID != "" || captured.Role != "" {
		t.Errorf("captured = %+v; want empty grant fields propagated", captured)
	}
	j := readJob(t, db, "01HJOBMISSREVK0000000001")
	if j.Status != models.AccessJobStatusCompleted {
		t.Errorf("status = %q; want completed (connector signalled idempotent success)", j.Status)
	}
}

// TestAccessRevoke_EmptyPayload_JobFailed asserts the same
// payload-required guard as access_provision: an entirely-missing
// payload blob is a job-level failure that should never reach the
// connector.
func TestAccessRevoke_EmptyPayload_JobFailed(t *testing.T) {
	db := newHandlerDB(t)
	seedTestConnector(t, db, "01HCONNEMPTYREVK000000A", "test_provider")
	seedJob(t, db, "01HJOBEMPTYREVK000000001", "01HCONNEMPTYREVK000000A", models.AccessJobTypeRevokeAccess, nil)

	mock := &access.MockAccessConnector{}
	err := AccessRevoke(context.Background(), newJC(db, mock), "01HJOBEMPTYREVK000000001")
	if err == nil {
		t.Fatal("expected error for empty payload")
	}
	if !strings.Contains(err.Error(), "payload is required") {
		t.Errorf("err = %v; want 'payload is required'", err)
	}
	j := readJob(t, db, "01HJOBEMPTYREVK000000001")
	if j.Status != models.AccessJobStatusFailed {
		t.Errorf("status = %q; want failed", j.Status)
	}
}
