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
	CredentialExpiredTime *time.Time           `json:"credential_expired_time,omitempty"`
	LastSyncTimes         map[string]time.Time `json:"last_sync_times"`
	StaleAudit            bool                 `json:"stale_audit"`
}

// ConnectorHealthService is the production-backed implementation of
// ConnectorHealthReader. It executes two SELECTs against GORM (no
// raw SQL per the cross-cutting rules in docs/PHASES.md): one on
// access_connectors and one on access_sync_state. Both are bounded
// by the supplied context.
type ConnectorHealthService struct {
	DB *gorm.DB
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
		CredentialExpiredTime: connector.CredentialExpiredTime,
		LastSyncTimes:         lastSync,
		StaleAudit:            stale,
	}, nil
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
