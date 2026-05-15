//go:build integration

// anomaly_scanner_integration_test.go drives the
// AnomalyScanner → AnomalyDetectionService → AnomalyDetector
// pipeline end-to-end against an in-memory SQLite seeded with a
// realistic mix of active grants, then asserts each documented
// anomaly Kind (geo_unusual, time_unusual, frequency_spike,
// scope_expansion, stale_grant) propagates from the AI mock all
// the way out to the AnomalyScanResult the cron loop persists.
//
// The non-integration anomaly_scanner_test.go exercises the cron
// dispatcher (workspace enumeration, scan-error continuity, soft-
// deleted-connector filtering). This file complements it by
// drilling into the actual detection-result shape — the
// "did the geographic-outlier kind survive the round trip" check
// that the cron-level test doesn't make.
package cron

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
	"github.com/kennguy3n/cautious-fishstick/internal/pkg/aiclient"
	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

// stubAnomalyDetector returns the supplied per-grant anomaly list and
// records every grant it was asked about. ok defaults to true; tests
// can flip ok to false on a specific grant to exercise the
// "AI is down for this grant" fallback path.
type stubAnomalyDetector struct {
	byGrant map[string][]aiclient.AnomalyEvent
	calls   []string
	skipFor map[string]bool
}

func (d *stubAnomalyDetector) DetectAnomalies(_ context.Context, grantID string, _ map[string]interface{}) ([]aiclient.AnomalyEvent, bool) {
	d.calls = append(d.calls, grantID)
	if d.skipFor[grantID] {
		return nil, false
	}
	return d.byGrant[grantID], true
}

// newAnomalyIntegrationDB returns a fresh in-memory SQLite DB with
// the access_connectors + access_grants tables migrated.
func newAnomalyIntegrationDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&models.AccessConnector{}, &models.AccessGrant{}); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}
	return db
}

func seedActiveGrant(t *testing.T, db *gorm.DB, id, workspaceID, role, resourceExtID string, granted time.Time) {
	t.Helper()
	g := &models.AccessGrant{
		ID:                 id,
		WorkspaceID:        workspaceID,
		Role:               role,
		ResourceExternalID: resourceExtID,
		GrantedAt:          granted,
		CreatedAt:          time.Now(),
		UpdatedAt:          time.Now(),
	}
	if err := db.Create(g).Error; err != nil {
		t.Fatalf("seed grant %s: %v", id, err)
	}
}

// TestIntegration_AnomalyScanner_PropagatesEveryKind seeds one
// active grant per documented anomaly Kind, runs the full
// AnomalyScanner → AnomalyDetectionService pipeline, and asserts
// each Kind shows up in the persisted AnomalyScanResult with the
// matching GrantID.
//
// This guards against silent regressions where, e.g., a future
// refactor drops the Kind field on its way from
// aiclient.AnomalyEvent → access.AnomalyObservation.
func TestIntegration_AnomalyScanner_PropagatesEveryKind(t *testing.T) {
	db := newAnomalyIntegrationDB(t)
	ws := "01HWS00000ANOMALYINT00000"
	seedConnector(t, db, "01HCONN00ANOMINT00000000001", ws, "okta")

	// Seed one grant per documented anomaly Kind.
	now := time.Now().UTC()
	const (
		idGeo       = "01HGRANT0GEO000000000000001"
		idTime      = "01HGRANT0TIME0000000000001"
		idFrequency = "01HGRANT0FREQ0000000000001"
		idScope     = "01HGRANT0SCOPE000000000001"
		idStale     = "01HGRANT0STALE000000000001"
	)
	seedActiveGrant(t, db, idGeo, ws, "viewer", "saas-app-1", now.Add(-30*24*time.Hour))
	seedActiveGrant(t, db, idTime, ws, "viewer", "saas-app-2", now.Add(-30*24*time.Hour))
	seedActiveGrant(t, db, idFrequency, ws, "editor", "saas-app-3", now.Add(-30*24*time.Hour))
	seedActiveGrant(t, db, idScope, ws, "admin", "saas-app-4", now.Add(-7*24*time.Hour))
	seedActiveGrant(t, db, idStale, ws, "viewer", "saas-app-5", now.Add(-180*24*time.Hour))

	detector := &stubAnomalyDetector{
		byGrant: map[string][]aiclient.AnomalyEvent{
			idGeo:       {{Kind: "geo_unusual", Severity: "high", Confidence: 0.91, Reason: "grant used from unusual region"}},
			idTime:      {{Kind: "time_unusual", Severity: "medium", Confidence: 0.84, Reason: "off-hours activity"}},
			idFrequency: {{Kind: "frequency_spike", Severity: "high", Confidence: 0.88, Reason: "usage 5x baseline"}},
			idScope:     {{Kind: "scope_expansion", Severity: "high", Confidence: 0.95, Reason: "unused high-privilege grant"}},
			idStale:     {{Kind: "stale_grant", Severity: "low", Confidence: 0.72, Reason: "no usage for 180 days"}},
		},
	}
	svc := access.NewAnomalyDetectionService(db, detector)
	svc.SetNow(func() time.Time { return now })

	scanner := NewAnomalyScanner(db, svc)
	if err := scanner.Run(context.Background()); err != nil {
		t.Fatalf("scanner.Run: %v", err)
	}

	// Re-invoke ScanWorkspace directly so the test can assert on the
	// AnomalyScanResult shape — the cron scanner.Run does not return
	// the result to callers; it logs the summary.
	result, err := svc.ScanWorkspace(context.Background(), ws)
	if err != nil {
		t.Fatalf("ScanWorkspace: %v", err)
	}
	if result.GrantsScanned != 5 {
		t.Errorf("GrantsScanned = %d; want 5", result.GrantsScanned)
	}
	wantKinds := map[string]string{
		idGeo:       "geo_unusual",
		idTime:      "time_unusual",
		idFrequency: "frequency_spike",
		idScope:     "scope_expansion",
		idStale:     "stale_grant",
	}
	gotByGrant := map[string]string{}
	for _, obs := range result.Observations {
		gotByGrant[obs.GrantID] = obs.Kind
	}
	for gid, want := range wantKinds {
		if got := gotByGrant[gid]; got != want {
			t.Errorf("Observations[%s].Kind = %q; want %q", gid, got, want)
		}
	}
	// The observed_at timestamp must be the pinned "now" — regression
	// guards against future moves to time.Now() in the service layer
	// breaking deterministic admin-UI rendering.
	for _, obs := range result.Observations {
		if !obs.ObservedAt.Equal(now) {
			t.Errorf("Observations[%s].ObservedAt = %v; want %v", obs.GrantID, obs.ObservedAt, now)
		}
	}
}

// TestIntegration_AnomalyScanner_AIFallbackDegradesPerGrant asserts
// the documented per-grant fallback: when the AI agent is
// unreachable for one grant (ok=false), that grant is counted in
// Skipped and its Kind never reaches the observations slice. Other
// grants in the same workspace continue to produce anomalies.
func TestIntegration_AnomalyScanner_AIFallbackDegradesPerGrant(t *testing.T) {
	db := newAnomalyIntegrationDB(t)
	ws := "01HWS00000ANOMALYFB000000"
	seedConnector(t, db, "01HCONN00ANOMFB000000000001", ws, "okta")

	now := time.Now().UTC()
	const (
		idA = "01HGRANT0AIFAIL00000000001"
		idB = "01HGRANT0AIOK0000000000001"
	)
	seedActiveGrant(t, db, idA, ws, "editor", "saas-app-A", now.Add(-30*24*time.Hour))
	seedActiveGrant(t, db, idB, ws, "viewer", "saas-app-B", now.Add(-30*24*time.Hour))

	detector := &stubAnomalyDetector{
		byGrant: map[string][]aiclient.AnomalyEvent{
			idB: {{Kind: "frequency_spike", Severity: "high", Confidence: 0.88}},
		},
		skipFor: map[string]bool{idA: true},
	}
	svc := access.NewAnomalyDetectionService(db, detector)
	svc.SetNow(func() time.Time { return now })

	result, err := svc.ScanWorkspace(context.Background(), ws)
	if err != nil {
		t.Fatalf("ScanWorkspace: %v", err)
	}
	if result.GrantsScanned != 2 {
		t.Errorf("GrantsScanned = %d; want 2", result.GrantsScanned)
	}
	if result.Skipped != 1 {
		t.Errorf("Skipped = %d; want 1", result.Skipped)
	}
	if len(result.Observations) != 1 || result.Observations[0].GrantID != idB {
		t.Errorf("Observations = %+v; want one observation for grant %s", result.Observations, idB)
	}
}

// TestIntegration_AnomalyScanner_NoDetectorIsNoop asserts the
// service-level contract: a nil AnomalyDetector returns an empty
// scan with no error so dev binaries without AI configured stay
// healthy. The matching cron-level test exists in
// anomaly_scanner_test.go; this integration variant exercises the
// service layer directly.
func TestIntegration_AnomalyScanner_NoDetectorIsNoop(t *testing.T) {
	db := newAnomalyIntegrationDB(t)
	ws := "01HWS00000ANOMNONE00000000"
	seedConnector(t, db, "01HCONN00ANOMNONE000000001", ws, "okta")
	seedActiveGrant(t, db, "01HGRANT0NONE00000000000001", ws, "viewer", "x", time.Now().Add(-1*time.Hour))

	svc := access.NewAnomalyDetectionService(db, nil)
	result, err := svc.ScanWorkspace(context.Background(), ws)
	if err != nil {
		t.Fatalf("ScanWorkspace: %v", err)
	}
	if result == nil {
		t.Fatal("ScanWorkspace returned nil result; want empty result")
	}
	if len(result.Observations) != 0 {
		t.Errorf("Observations = %+v; want empty", result.Observations)
	}
}

// TestIntegration_AnomalyScanner_RejectsEmptyWorkspaceID asserts
// the documented validation guard: an empty workspace ID returns
// ErrValidation so callers can surface a 400 instead of a 500.
func TestIntegration_AnomalyScanner_RejectsEmptyWorkspaceID(t *testing.T) {
	db := newAnomalyIntegrationDB(t)
	svc := access.NewAnomalyDetectionService(db, &stubAnomalyDetector{})
	_, err := svc.ScanWorkspace(context.Background(), "")
	if err == nil || !strings.Contains(err.Error(), "workspace_id") {
		t.Errorf("err = %v; want validation error mentioning workspace_id", err)
	}
}
