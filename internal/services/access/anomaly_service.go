package access

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
	"github.com/kennguy3n/cautious-fishstick/internal/pkg/aiclient"
)

// AnomalyDetector is the narrow contract the AnomalyDetectionService
// expects from the AI agent. The aiclient.AIClient + the
// DetectAnomaliesWithFallback wrapper satisfy it; tests stub it
// directly without spinning up an HTTP server.
//
// The two-return-tuple is the same shape as RiskAssessor — anomalies
// are the returned slice (possibly empty) and ok signals whether the
// AI agent was reachable. Callers MUST treat ok=false as "AI is
// down; surface no anomalies and continue".
type AnomalyDetector interface {
	DetectAnomalies(ctx context.Context, grantID string, usageData map[string]interface{}) (anomalies []aiclient.AnomalyEvent, ok bool)
}

// AnomalyObservation is the persisted summary the
// AnomalyDetectionService records for each anomaly the AI agent
// surfaces. The struct is intentionally small so an admin UI can
// render the full list in a single page; the AI agent's structured
// reasoning lives in the AnomalyEvent slice on the wire.
type AnomalyObservation struct {
	GrantID    string                 `json:"grant_id"`
	Kind       string                 `json:"kind"`
	Severity   string                 `json:"severity,omitempty"`
	Confidence float64                `json:"confidence,omitempty"`
	Reason     string                 `json:"reason,omitempty"`
	ObservedAt time.Time              `json:"observed_at"`
	Raw        map[string]interface{} `json:"raw,omitempty"`
}

// AnomalyDetectionService scans active access grants for anomalous
// usage and (Phase 6 stub) records the surfaced anomalies for
// admin review. The service is intentionally read-only against the
// grants table — the actual review-suggestion plumbing lives in
// AccessReviewService and is wired up by ScanWorkspace's caller.
//
// Per docs/architecture.md §9 the service is one of the AI
// integration points. Failure modes follow PROPOSAL §5.3 — an
// unreachable AI agent must NOT block the scan; the service logs
// and returns an empty anomaly list for that grant.
type AnomalyDetectionService struct {
	db       *gorm.DB
	detector AnomalyDetector

	// now is overridable so tests can pin "current time" without
	// reaching into time.Now. Defaults to time.Now in
	// NewAnomalyDetectionService.
	now func() time.Time
}

// NewAnomalyDetectionService returns a service backed by db that
// dispatches anomaly checks through detector. detector may be nil —
// in that case ScanWorkspace logs a single warning and returns an
// empty result so dev / test binaries stay healthy without an AI
// agent wired up.
func NewAnomalyDetectionService(db *gorm.DB, detector AnomalyDetector) *AnomalyDetectionService {
	return &AnomalyDetectionService{
		db:       db,
		detector: detector,
		now:      time.Now,
	}
}

// SetNow overrides the time hook. Tests use this to pin "current
// time" so observation timestamps are deterministic.
func (s *AnomalyDetectionService) SetNow(fn func() time.Time) {
	if fn != nil {
		s.now = fn
	}
}

// AnomalyScanResult is the per-scan summary AnomalyDetectionService
// returns. The Observations slice is the full deduplicated list of
// anomalies the AI agent surfaced; the Skipped counter tracks the
// number of grants that hit the AI fallback (so the admin dashboard
// can flag "AI is down — anomaly detection degraded").
type AnomalyScanResult struct {
	Observations []AnomalyObservation `json:"observations"`
	Skipped      int                  `json:"skipped"`
	GrantsScanned int                 `json:"grants_scanned"`
}

// ScanWorkspace walks every active grant in workspaceID, dispatches
// each one through detector.DetectAnomalies, and aggregates the
// results into a single AnomalyScanResult. The service does NOT
// transition any grant or open any review — that is the caller's
// responsibility (e.g. the access-review scheduler invokes
// ScanWorkspace and then calls AccessReviewService.StartCampaign
// when Observations is non-empty).
//
// Active is defined the same way as on AccessGrant.IsActive: not
// revoked AND (no expiry OR expiry in the future).
func (s *AnomalyDetectionService) ScanWorkspace(ctx context.Context, workspaceID string) (*AnomalyScanResult, error) {
	if workspaceID == "" {
		return nil, fmt.Errorf("%w: workspace_id is required", ErrValidation)
	}
	if s.detector == nil {
		log.Printf("anomaly: detector is nil; returning empty scan for workspace %s", workspaceID)
		return &AnomalyScanResult{}, nil
	}

	now := s.now()
	var grants []models.AccessGrant
	if err := s.db.WithContext(ctx).
		Where("workspace_id = ? AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > ?)", workspaceID, now).
		Find(&grants).Error; err != nil {
		return nil, fmt.Errorf("anomaly: load active grants: %w", err)
	}

	out := &AnomalyScanResult{GrantsScanned: len(grants)}
	for _, g := range grants {
		usage := snapshotGrantUsage(g, now)
		anomalies, ok := s.detector.DetectAnomalies(ctx, g.ID, usage)
		if !ok {
			out.Skipped++
			continue
		}
		for _, ev := range anomalies {
			out.Observations = append(out.Observations, AnomalyObservation{
				GrantID:    g.ID,
				Kind:       ev.Kind,
				Severity:   ev.Severity,
				Confidence: ev.Confidence,
				Reason:     ev.Reason,
				ObservedAt: now,
			})
		}
	}
	return out, nil
}

// snapshotGrantUsage assembles the recent-usage observations the AI
// agent reasons over for one grant. Phase 6 stub: we surface the
// grant's own metadata + a "days since last use" derived signal.
// Phase 7 will fold in cross-grant histograms (geo, time-of-day)
// once the access_audit_logs pipeline lands.
func snapshotGrantUsage(g models.AccessGrant, now time.Time) map[string]interface{} {
	usage := map[string]interface{}{
		"role":                 g.Role,
		"resource_external_id": g.ResourceExternalID,
		"granted_at":           g.GrantedAt.Format(time.RFC3339),
	}
	if g.LastUsedAt != nil {
		usage["last_used_at"] = g.LastUsedAt.Format(time.RFC3339)
		usage["days_since_last_use"] = int(now.Sub(*g.LastUsedAt).Hours() / 24)
	} else {
		usage["last_used_at"] = nil
		usage["days_since_last_use"] = int(now.Sub(g.GrantedAt).Hours() / 24)
	}
	if g.ExpiresAt != nil {
		usage["expires_at"] = g.ExpiresAt.Format(time.RFC3339)
	}
	return usage
}

// AnomalyDetectorAdapter wraps *aiclient.AIClient so the
// AnomalyDetectionService can depend on the narrow AnomalyDetector
// contract without importing aiclient directly. The adapter
// composes DetectAnomaliesWithFallback so the scan loop gets the
// PROPOSAL §5.3 fallback for free.
type AnomalyDetectorAdapter struct {
	Inner *aiclient.AIClient
}

// DetectAnomalies satisfies AnomalyDetector by forwarding to
// aiclient.DetectAnomaliesWithFallback.
func (a *AnomalyDetectorAdapter) DetectAnomalies(ctx context.Context, grantID string, usageData map[string]interface{}) ([]aiclient.AnomalyEvent, bool) {
	if a == nil {
		return nil, false
	}
	return aiclient.DetectAnomaliesWithFallback(ctx, a.Inner, grantID, usageData)
}

// ErrAnomalyDetectorMissing is the sentinel returned when a call
// site requires an AnomalyDetector but the service was constructed
// without one. Callers that pass a non-nil detector never see this.
var ErrAnomalyDetectorMissing = errors.New("anomaly: detector not configured")
