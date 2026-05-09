package access

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
	"github.com/kennguy3n/cautious-fishstick/internal/pkg/aiclient"
)

// stubAnomalyDetector is a deterministic AnomalyDetector for the
// AnomalyDetectionService tests. The Calls slice records each
// (grantID, usage) tuple so tests assert what was scanned.
type stubAnomalyDetector struct {
	OK       bool
	Anomalies map[string][]aiclient.AnomalyEvent
	Calls    []anomalyCall
}

type anomalyCall struct {
	GrantID string
	Usage   map[string]interface{}
}

func (s *stubAnomalyDetector) DetectAnomalies(_ context.Context, grantID string, usage map[string]interface{}) ([]aiclient.AnomalyEvent, bool) {
	s.Calls = append(s.Calls, anomalyCall{GrantID: grantID, Usage: usage})
	if !s.OK {
		return nil, false
	}
	return s.Anomalies[grantID], true
}

// newAnomalyTestDB returns an in-memory SQLite DB with the
// access_grants table migrated.
func newAnomalyTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&models.AccessGrant{}); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}
	return db
}

// seedActiveGrant inserts one active grant at the supplied id.
func seedActiveAnomalyGrant(t *testing.T, db *gorm.DB, id string) *models.AccessGrant {
	t.Helper()
	now := time.Now().Add(-7 * 24 * time.Hour)
	g := &models.AccessGrant{
		ID:                 id,
		WorkspaceID:        "01H000000000000000WORKSPACE",
		UserID:             "01H00000000000000ANOUSER001",
		ConnectorID:        "01H000000000000000CONNECTOR",
		ResourceExternalID: "projects/foo",
		Role:               "viewer",
		GrantedAt:          now,
		CreatedAt:          now,
		UpdatedAt:          now,
	}
	if err := db.Create(g).Error; err != nil {
		t.Fatalf("seed grant: %v", err)
	}
	return g
}

// TestAnomalyService_ScanWorkspace_HappyPath asserts the scan
// dispatches one DetectAnomalies call per active grant and
// aggregates the surfaced anomalies into a single result.
func TestAnomalyService_ScanWorkspace_HappyPath(t *testing.T) {
	t.Parallel()
	db := newAnomalyTestDB(t)
	g1 := seedActiveAnomalyGrant(t, db, "01H000000000000000GRANT01ANO")
	g2 := seedActiveAnomalyGrant(t, db, "01H000000000000000GRANT02ANO")

	stub := &stubAnomalyDetector{
		OK: true,
		Anomalies: map[string][]aiclient.AnomalyEvent{
			g1.ID: {{Kind: "geo_unusual", Severity: "medium", Confidence: 0.8}},
			g2.ID: {
				{Kind: "frequency_spike", Severity: "high", Confidence: 0.9},
				{Kind: "stale_grant", Severity: "low", Confidence: 0.6},
			},
		},
	}
	svc := NewAnomalyDetectionService(db, stub)

	res, err := svc.ScanWorkspace(context.Background(), "01H000000000000000WORKSPACE")
	if err != nil {
		t.Fatalf("ScanWorkspace: %v", err)
	}
	if got, want := res.GrantsScanned, 2; got != want {
		t.Errorf("GrantsScanned = %d; want %d", got, want)
	}
	if got, want := len(res.Observations), 3; got != want {
		t.Errorf("Observations = %d; want %d", got, want)
	}
	if got, want := res.Skipped, 0; got != want {
		t.Errorf("Skipped = %d; want %d", got, want)
	}
	if got, want := len(stub.Calls), 2; got != want {
		t.Errorf("DetectAnomalies calls = %d; want %d", got, want)
	}
}

// TestAnomalyService_ScanWorkspace_AIDownIsSkipped asserts a
// detector that returns ok=false on every grant surfaces 0
// observations and Skipped equals the grant count.
func TestAnomalyService_ScanWorkspace_AIDownIsSkipped(t *testing.T) {
	t.Parallel()
	db := newAnomalyTestDB(t)
	seedActiveAnomalyGrant(t, db, "01H000000000000000GRANT01ADV")
	seedActiveAnomalyGrant(t, db, "01H000000000000000GRANT02ADV")

	stub := &stubAnomalyDetector{OK: false}
	svc := NewAnomalyDetectionService(db, stub)

	res, err := svc.ScanWorkspace(context.Background(), "01H000000000000000WORKSPACE")
	if err != nil {
		t.Fatalf("ScanWorkspace: %v", err)
	}
	if res.Skipped != 2 {
		t.Errorf("Skipped = %d; want 2", res.Skipped)
	}
	if len(res.Observations) != 0 {
		t.Errorf("Observations = %v; want empty", res.Observations)
	}
}

// TestAnomalyService_ScanWorkspace_NilDetectorIsNoop asserts the
// service constructed without a detector returns an empty result
// rather than panicking.
func TestAnomalyService_ScanWorkspace_NilDetectorIsNoop(t *testing.T) {
	t.Parallel()
	db := newAnomalyTestDB(t)
	seedActiveAnomalyGrant(t, db, "01H000000000000000GRANT01NIL")
	svc := NewAnomalyDetectionService(db, nil)

	res, err := svc.ScanWorkspace(context.Background(), "01H000000000000000WORKSPACE")
	if err != nil {
		t.Fatalf("ScanWorkspace: %v", err)
	}
	if res == nil {
		t.Fatalf("nil result; want empty AnomalyScanResult")
	}
	if res.GrantsScanned != 0 {
		t.Errorf("GrantsScanned = %d; want 0 (detector is nil → service should not load grants)", res.GrantsScanned)
	}
}

// TestAnomalyService_ScanWorkspace_RevokedAndExpiredAreSkipped
// asserts revoked / expired grants are NOT scanned.
func TestAnomalyService_ScanWorkspace_RevokedAndExpiredAreSkipped(t *testing.T) {
	t.Parallel()
	db := newAnomalyTestDB(t)

	now := time.Now()
	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)

	active := &models.AccessGrant{
		ID: "01H000000000000000ANOACTIVE", WorkspaceID: "ws", UserID: "u", ConnectorID: "c",
		ResourceExternalID: "r", Role: "viewer", GrantedAt: past, ExpiresAt: &future,
		CreatedAt: past, UpdatedAt: past,
	}
	revoked := &models.AccessGrant{
		ID: "01H000000000000000ANOREVOKED", WorkspaceID: "ws", UserID: "u", ConnectorID: "c",
		ResourceExternalID: "r", Role: "viewer", GrantedAt: past, RevokedAt: &past,
		CreatedAt: past, UpdatedAt: past,
	}
	expired := &models.AccessGrant{
		ID: "01H000000000000000ANOEXPIRED", WorkspaceID: "ws", UserID: "u", ConnectorID: "c",
		ResourceExternalID: "r", Role: "viewer", GrantedAt: past, ExpiresAt: &past,
		CreatedAt: past, UpdatedAt: past,
	}
	for _, g := range []*models.AccessGrant{active, revoked, expired} {
		if err := db.Create(g).Error; err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	stub := &stubAnomalyDetector{OK: true}
	svc := NewAnomalyDetectionService(db, stub)
	svc.SetNow(func() time.Time { return now })

	res, err := svc.ScanWorkspace(context.Background(), "ws")
	if err != nil {
		t.Fatalf("ScanWorkspace: %v", err)
	}
	if res.GrantsScanned != 1 {
		t.Errorf("GrantsScanned = %d; want 1 (only active grant is in scope)", res.GrantsScanned)
	}
	if len(stub.Calls) != 1 || stub.Calls[0].GrantID != active.ID {
		t.Errorf("scanned grants = %+v; want [%s]", stub.Calls, active.ID)
	}
}

// TestAnomalyService_ScanWorkspace_EmptyWorkspaceErrors asserts a
// missing workspace_id surfaces ErrValidation.
func TestAnomalyService_ScanWorkspace_EmptyWorkspaceErrors(t *testing.T) {
	t.Parallel()
	svc := NewAnomalyDetectionService(newAnomalyTestDB(t), &stubAnomalyDetector{OK: true})
	_, err := svc.ScanWorkspace(context.Background(), "")
	if !errors.Is(err, ErrValidation) {
		t.Errorf("err = %v; want errors.Is(err, ErrValidation)", err)
	}
}
