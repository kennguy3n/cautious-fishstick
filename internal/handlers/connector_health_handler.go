package handlers

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// ConnectorHealthReader returns the operational health view of an
// access connector. It is implemented by *ConnectorHealthService
// (this package) but exposed as an interface so tests can supply a
// lightweight in-memory backend.
type ConnectorHealthReader interface {
	GetConnectorHealth(ctx context.Context, connectorID string) (*ConnectorHealth, error)
}

// ConnectorHealth is the JSON shape returned by
// GET /access/connectors/:id/health.
//
// Fields:
//
//   - ConnectorID, Provider, Status, CredentialExpiredTime mirror
//     the access_connectors row.
//   - LastSyncTimes maps each sync kind ("identity"/"group"/"audit")
//     to the UpdatedAt timestamp from access_sync_state. Missing kinds
//     are omitted (the connector has never run that pipeline).
//   - StaleAudit is true when the audit cursor has not advanced in
//     >24h, which is the Phase 7 operator alert threshold.
//
// Operator UIs render the credential-expiry countdown directly from
// CredentialExpiredTime; the platform never re-derives "expires in
// X hours" server-side because the cluster clock is the wrong frame
// of reference for the customer's tenant.
type ConnectorHealth struct {
	ConnectorID           string               `json:"connector_id"`
	Provider              string               `json:"provider"`
	ConnectorType         string               `json:"connector_type"`
	Status                string               `json:"status"`
	AccessMode            string               `json:"access_mode"`
	CredentialExpiredTime *time.Time           `json:"credential_expired_time,omitempty"`
	LastSyncTimes         map[string]time.Time `json:"last_sync_times"`
	StaleAudit            bool                 `json:"stale_audit"`
	// SSOEnforcementStatus reports whether the SaaS app behind
	// this connector enforces SSO-only sign-in. Values:
	//   - "enforced"      : password sign-in is disabled upstream.
	//   - "not_enforced"  : password sign-in is still allowed.
	//   - "unknown"       : the probe failed (auth, transport, etc.).
	//   - "not_applicable": the connector does not implement
	//                       SSOEnforcementChecker (e.g. tunnel-mode
	//                       private resource, generic API connector).
	SSOEnforcementStatus  string `json:"sso_enforcement_status,omitempty"`
	SSOEnforcementDetails string `json:"sso_enforcement_details,omitempty"`
}

// ConnectorHealthService is the production-backed implementation of
// ConnectorHealthReader. It executes two SELECTs against GORM (no
// raw SQL per the cross-cutting rules in docs/PHASES.md): one on
// access_connectors and one on access_sync_state. Both are bounded
// by the supplied context.
type ConnectorHealthService struct {
	DB *gorm.DB
	// SSOEnforcement is the optional probe used to populate
	// ConnectorHealth.SSOEnforcementStatus. Production wires it to
	// a probe that loads credentials and calls SSOEnforcementChecker
	// on the connector; tests can leave it nil and the response
	// reports "not_applicable".
	SSOEnforcement SSOEnforcementProbe
}

// NewConnectorHealthService returns a service bound to db. db may
// be nil; callers should not register the handler in that case.
func NewConnectorHealthService(db *gorm.DB) *ConnectorHealthService {
	return &ConnectorHealthService{DB: db}
}

// staleAuditWindow is the threshold beyond which we flag the audit
// cursor as stalled. Per docs/PHASES.md Phase 7 the operator alert
// fires at 24h; we surface the same threshold here so the UI does
// not have to re-derive it.
const staleAuditWindow = 24 * time.Hour

// GetConnectorHealth assembles the per-connector health view by
// joining access_connectors and access_sync_state in two simple
// reads. Returns gorm.ErrRecordNotFound for an unknown connector
// so callers can map it to 404.
func (s *ConnectorHealthService) GetConnectorHealth(ctx context.Context, connectorID string) (*ConnectorHealth, error) {
	if s == nil || s.DB == nil {
		return nil, errors.New("connector health service not configured")
	}
	if connectorID == "" {
		return nil, errors.New("connector id required")
	}
	var connector models.AccessConnector
	if err := s.DB.WithContext(ctx).
		Where("id = ?", connectorID).
		First(&connector).Error; err != nil {
		return nil, err
	}
	var states []models.AccessSyncState
	if err := s.DB.WithContext(ctx).
		Where("connector_id = ?", connectorID).
		Find(&states).Error; err != nil {
		return nil, err
	}
	lastSync := make(map[string]time.Time, len(states))
	for _, st := range states {
		if existing, ok := lastSync[st.Kind]; !ok || st.UpdatedAt.After(existing) {
			lastSync[st.Kind] = st.UpdatedAt
		}
	}
	stale := false
	if auditAt, ok := lastSync[models.SyncStateKindAudit]; ok {
		if time.Since(auditAt) > staleAuditWindow {
			stale = true
		}
	}
	return &ConnectorHealth{
		ConnectorID:           connector.ID,
		Provider:              connector.Provider,
		ConnectorType:         connector.ConnectorType,
		Status:                connector.Status,
		AccessMode:            connector.AccessMode,
		CredentialExpiredTime: connector.CredentialExpiredTime,
		LastSyncTimes:         lastSync,
		StaleAudit:            stale,
		SSOEnforcementStatus:  ssoEnforcementStatusFor(ctx, s.SSOEnforcement, &connector),
	}, nil
}

// SSOEnforcementProbe is the optional dependency that resolves the
// upstream SSO-enforcement status for a connector. ConnectorHealthService
// calls it when wired; a nil probe yields "not_applicable".
type SSOEnforcementProbe func(ctx context.Context, conn *models.AccessConnector) (status, details string)

// ssoEnforcementStatusFor dispatches to the supplied probe, mapping
// a nil probe to "not_applicable" so the JSON payload always has a
// concrete enum value rather than an empty string.
func ssoEnforcementStatusFor(ctx context.Context, probe SSOEnforcementProbe, conn *models.AccessConnector) string {
	if probe == nil {
		return "not_applicable"
	}
	status, _ := probe(ctx, conn)
	if status == "" {
		return "not_applicable"
	}
	return status
}

// ConnectorHealthHandler exposes GET /access/connectors/:id/health,
// the Phase 7 exit criterion for per-connector last-sync,
// error-count, and credential-expiry observability.
type ConnectorHealthHandler struct {
	reader ConnectorHealthReader
}

// NewConnectorHealthHandler returns a handler bound to the supplied
// reader. reader must not be nil.
func NewConnectorHealthHandler(reader ConnectorHealthReader) *ConnectorHealthHandler {
	return &ConnectorHealthHandler{reader: reader}
}

// Register wires the route onto r.
func (h *ConnectorHealthHandler) Register(r *gin.Engine) {
	r.GET("/access/connectors/:id/health", h.GetHealth)
	r.POST("/access/connectors/batch-status", h.PostBatchStatus)
}

// batchStatusRequest is the JSON body accepted by
// POST /access/connectors/batch-status.
type batchStatusRequest struct {
	ConnectorIDs []string `json:"connector_ids"`
}

// BatchStatusEntry is the per-connector health result. NotFound is
// true when the row was deleted between the caller's last list call
// and this batch lookup; the entry's Health field is nil in that
// case so admins can grey out the row.
type BatchStatusEntry struct {
	ConnectorID string           `json:"connector_id"`
	NotFound    bool             `json:"not_found,omitempty"`
	Health      *ConnectorHealth `json:"health,omitempty"`
	Error       string           `json:"error,omitempty"`
}

// batchStatusResponse is the JSON shape returned by
// POST /access/connectors/batch-status.
type batchStatusResponse struct {
	Entries []BatchStatusEntry `json:"entries"`
}

// maxBatchStatusIDs caps the number of IDs a single request may
// list. The Admin UI's connector list page surfaces at most ~100 per
// page, so 200 is a comfortable ceiling that still bounds the
// per-request cost.
const maxBatchStatusIDs = 200

// PostBatchStatus handles POST /access/connectors/batch-status. It
// accepts an array of connector IDs and returns each connector's
// health view in a single response so the Admin UI list page can
// avoid an N+1 fan-out. Returns 400 for missing / oversized bodies,
// 503 when the service is unconfigured. Per-entry errors (e.g. one
// of the listed connectors was deleted) are returned 200 with the
// row's Error field populated so the rest of the batch isn't lost.
func (h *ConnectorHealthHandler) PostBatchStatus(c *gin.Context) {
	var req batchStatusRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, errorEnvelope{
			Error:   "invalid request body",
			Code:    "validation_failed",
			Message: err.Error(),
		})
		return
	}
	if len(req.ConnectorIDs) == 0 {
		c.AbortWithStatusJSON(http.StatusBadRequest, errorEnvelope{
			Error:   "connector_ids is required",
			Code:    "validation_failed",
			Message: "connector_ids must contain at least one id",
		})
		return
	}
	if len(req.ConnectorIDs) > maxBatchStatusIDs {
		c.AbortWithStatusJSON(http.StatusBadRequest, errorEnvelope{
			Error:   "too many connector_ids",
			Code:    "validation_failed",
			Message: "connector_ids exceeds the per-request limit",
		})
		return
	}

	// Dedupe while preserving the caller's order so the response
	// indexes match what the UI sent.
	seen := make(map[string]struct{}, len(req.ConnectorIDs))
	ordered := make([]string, 0, len(req.ConnectorIDs))
	for _, id := range req.ConnectorIDs {
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		ordered = append(ordered, id)
	}
	if len(ordered) == 0 {
		c.AbortWithStatusJSON(http.StatusBadRequest, errorEnvelope{
			Error:   "connector_ids must contain at least one non-empty id",
			Code:    "validation_failed",
			Message: "connector_ids must contain at least one non-empty id",
		})
		return
	}

	entries := make([]BatchStatusEntry, 0, len(ordered))
	for _, id := range ordered {
		entry := BatchStatusEntry{ConnectorID: id}
		out, err := h.reader.GetConnectorHealth(c.Request.Context(), id)
		switch {
		case err == nil:
			entry.Health = out
		case errors.Is(err, gorm.ErrRecordNotFound):
			entry.NotFound = true
		default:
			entry.Error = err.Error()
		}
		entries = append(entries, entry)
	}
	c.JSON(http.StatusOK, batchStatusResponse{Entries: entries})
}

// GetHealth handles GET /access/connectors/:id/health. Returns 200
// with the connector's health summary, 400 when :id is missing,
// 404 for unknown connectors, 503 when the service is unconfigured.
func (h *ConnectorHealthHandler) GetHealth(c *gin.Context) {
	id := GetStringParam(c, "id")
	if id == "" {
		c.AbortWithStatusJSON(http.StatusBadRequest, errorEnvelope{
			Error:   "connector id is required",
			Code:    "validation_failed",
			Message: "connector id is required",
		})
		return
	}
	out, err := h.reader.GetConnectorHealth(c.Request.Context(), id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.AbortWithStatusJSON(http.StatusNotFound, errorEnvelope{
				Error:   "connector not found",
				Code:    "not_found",
				Message: "connector not found",
			})
			return
		}
		writeError(c, http.StatusInternalServerError, err)
		return
	}
	c.JSON(http.StatusOK, out)
}
