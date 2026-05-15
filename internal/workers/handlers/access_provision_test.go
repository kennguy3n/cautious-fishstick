package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

// TestAccessProvision_NilConnector_JobFailed verifies that when the
// resolver cannot find an AccessConnector for the job's provider,
// the worker handler marks the job failed with a non-empty
// last_error rather than panicking.
func TestAccessProvision_NilConnector_JobFailed(t *testing.T) {
	db := newHandlerDB(t)
	seedTestConnector(t, db, "01HCONNNILPROV0000000000A", "test_provider")
	seedJob(t, db, "01HJOBNILPROV0000000000001", "01HCONNNILPROV0000000000A", models.AccessJobTypeProvisionAccess, provisionAccessPayload{
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
	err := AccessProvision(context.Background(), jc, "01HJOBNILPROV0000000000001")
	if err == nil {
		t.Fatal("expected error for missing connector")
	}
	if !errors.Is(err, access.ErrConnectorNotFound) {
		t.Errorf("err = %v; want wraps ErrConnectorNotFound", err)
	}
	j := readJob(t, db, "01HJOBNILPROV0000000000001")
	if j.Status != models.AccessJobStatusFailed {
		t.Errorf("status = %q; want failed", j.Status)
	}
	if j.LastError == "" {
		t.Error("last_error is empty; want connector-not-found message")
	}
}

// TestAccessProvision_4xxPermanent_JobFailed drives the worker
// handler against a connector that delegates to a real httptest
// upstream returning HTTP 403. The handler must mark the job
// failed and surface the connector error verbatim — a 4xx is a
// permanent failure, not a retryable one.
func TestAccessProvision_4xxPermanent_JobFailed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"forbidden"}`))
	}))
	t.Cleanup(srv.Close)

	db := newHandlerDB(t)
	seedTestConnector(t, db, "01HCONN4XXPROV0000000000A", "test_provider")
	seedJob(t, db, "01HJOB4XXPROV0000000000001", "01HCONN4XXPROV0000000000A", models.AccessJobTypeProvisionAccess, provisionAccessPayload{
		UserExternalID:     "alice",
		ResourceExternalID: "r-1",
		Role:               "admin",
	})

	mock := &access.MockAccessConnector{
		FuncProvisionAccess: func(ctx context.Context, _, _ map[string]interface{}, _ access.AccessGrant) error {
			resp, err := http.Get(srv.URL + "/provision")
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusForbidden {
				return errors.New("test_provider: provision: forbidden (permanent)")
			}
			return nil
		},
	}
	err := AccessProvision(context.Background(), newJC(db, mock), "01HJOB4XXPROV0000000000001")
	if err == nil {
		t.Fatal("expected permanent error from 4xx upstream")
	}
	j := readJob(t, db, "01HJOB4XXPROV0000000000001")
	if j.Status != models.AccessJobStatusFailed {
		t.Errorf("status = %q; want failed", j.Status)
	}
	if !strings.Contains(j.LastError, "forbidden") {
		t.Errorf("last_error = %q; want to contain 'forbidden'", j.LastError)
	}
}

// TestAccessProvision_5xxTransient_JobFailed exercises the
// retryable-failure surface area: the connector hits a real
// httptest upstream that returns HTTP 503, surfaces a transient
// error, and the worker handler must mark the job failed (so a
// future requeue retries it). The handler itself does NOT decide
// retry policy — that lives in the queue layer per
// docs/internal/PHASES.md Phase 6 — but it MUST preserve the upstream
// error verbatim.
func TestAccessProvision_5xxTransient_JobFailed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":"try again later"}`))
	}))
	t.Cleanup(srv.Close)

	db := newHandlerDB(t)
	seedTestConnector(t, db, "01HCONN5XXPROV0000000000A", "test_provider")
	seedJob(t, db, "01HJOB5XXPROV0000000000001", "01HCONN5XXPROV0000000000A", models.AccessJobTypeProvisionAccess, provisionAccessPayload{
		UserExternalID:     "bob",
		ResourceExternalID: "r-2",
		Role:               "viewer",
	})

	mock := &access.MockAccessConnector{
		FuncProvisionAccess: func(ctx context.Context, _, _ map[string]interface{}, _ access.AccessGrant) error {
			resp, err := http.Get(srv.URL + "/provision")
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			if resp.StatusCode >= 500 {
				return errors.New("test_provider: provision: service unavailable (transient)")
			}
			return nil
		},
	}
	err := AccessProvision(context.Background(), newJC(db, mock), "01HJOB5XXPROV0000000000001")
	if err == nil {
		t.Fatal("expected transient error from 5xx upstream")
	}
	j := readJob(t, db, "01HJOB5XXPROV0000000000001")
	if j.Status != models.AccessJobStatusFailed {
		t.Errorf("status = %q; want failed", j.Status)
	}
	if !strings.Contains(j.LastError, "service unavailable") {
		t.Errorf("last_error = %q; want to contain 'service unavailable'", j.LastError)
	}
}

// TestAccessProvision_HappyPath_HTTPTestUpstream wires the worker
// handler against a real httptest upstream that returns HTTP 200
// and asserts the persisted access_jobs row is completed and the
// grant payload reached the connector intact.
func TestAccessProvision_HappyPath_HTTPTestUpstream(t *testing.T) {
	var seenBody map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&seenBody)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(srv.Close)

	db := newHandlerDB(t)
	seedTestConnector(t, db, "01HCONNOKPROV00000000000A", "test_provider")
	seedJob(t, db, "01HJOBOKPROV00000000000001", "01HCONNOKPROV00000000000A", models.AccessJobTypeProvisionAccess, provisionAccessPayload{
		UserExternalID:     "carol",
		ResourceExternalID: "r-3",
		Role:               "admin",
		Scope:              map[string]interface{}{"region": "us-east-1"},
	})

	var captured access.AccessGrant
	mock := &access.MockAccessConnector{
		FuncProvisionAccess: func(_ context.Context, _, _ map[string]interface{}, g access.AccessGrant) error {
			captured = g
			body, _ := json.Marshal(map[string]interface{}{
				"user_id":     g.UserExternalID,
				"resource_id": g.ResourceExternalID,
			})
			resp, err := http.Post(srv.URL+"/provision", "application/json", strings.NewReader(string(body)))
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				return errors.New("non-200")
			}
			return nil
		},
	}
	if err := AccessProvision(context.Background(), newJC(db, mock), "01HJOBOKPROV00000000000001"); err != nil {
		t.Fatalf("AccessProvision: %v", err)
	}
	if captured.UserExternalID != "carol" || captured.ResourceExternalID != "r-3" || captured.Role != "admin" {
		t.Errorf("captured = %+v; want carol/r-3/admin", captured)
	}
	if seenBody["user_id"] != "carol" {
		t.Errorf("upstream saw user_id=%v; want carol", seenBody["user_id"])
	}
	j := readJob(t, db, "01HJOBOKPROV00000000000001")
	if j.Status != models.AccessJobStatusCompleted {
		t.Errorf("status = %q; want completed", j.Status)
	}
	if j.LastError != "" {
		t.Errorf("last_error = %q; want empty", j.LastError)
	}
}

// TestAccessProvision_EmptyPayload_JobFailed verifies that a job
// with an empty payload column surfaces a validation error from
// the handler rather than panicking inside the connector dispatch.
func TestAccessProvision_EmptyPayload_JobFailed(t *testing.T) {
	db := newHandlerDB(t)
	seedTestConnector(t, db, "01HCONNEMPTYPROV0000000A", "test_provider")
	seedJob(t, db, "01HJOBEMPTYPROV0000000001", "01HCONNEMPTYPROV0000000A", models.AccessJobTypeProvisionAccess, nil)

	mock := &access.MockAccessConnector{}
	err := AccessProvision(context.Background(), newJC(db, mock), "01HJOBEMPTYPROV0000000001")
	if err == nil {
		t.Fatal("expected error for empty payload")
	}
	if !strings.Contains(err.Error(), "payload is required") {
		t.Errorf("err = %v; want 'payload is required'", err)
	}
	j := readJob(t, db, "01HJOBEMPTYPROV0000000001")
	if j.Status != models.AccessJobStatusFailed {
		t.Errorf("status = %q; want failed", j.Status)
	}
}
