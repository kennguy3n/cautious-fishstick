package access

import (
	"context"
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// ConnectorSummary is the read-only listing shape returned by
// AccessConnectorListService.ListConnectors. One row per
// access_connectors row, with capability flags derived from the
// process-global access connector registry so the operator UI can
// show which connectors expose `sso_federation`, `get_access_log`,
// etc. without re-running the connector contract test suite.
//
// The struct is JSON-tagged so the GET /access/connectors handler
// can pass it straight to c.JSON.
type ConnectorSummary struct {
	ID                    string               `json:"id"`
	WorkspaceID           string               `json:"workspace_id"`
	Provider              string               `json:"provider"`
	ConnectorType         string               `json:"connector_type"`
	Status                string               `json:"status"`
	CredentialExpiredTime *time.Time           `json:"credential_expired_time,omitempty"`
	LastSyncTimes         map[string]time.Time `json:"last_sync_times"`
	Capabilities          ConnectorCapabilities `json:"capabilities"`
	CreatedAt             time.Time            `json:"created_at"`
	UpdatedAt             time.Time            `json:"updated_at"`
}

// ConnectorCapabilities is the per-connector capability snapshot. The
// flags are derived at registry-lookup time, not stored on the row,
// so the column never drifts away from the actual code shipped in
// the binary. A connector that is not present in the registry
// (missing blank-import) gets Registered=false and every other flag
// is false — exactly what the operator UI needs to surface "wire
// this connector".
//
// SSOFederation is not surfaced here because determining federation
// capability requires calling GetSSOMetadata with a live tenant
// config; the per-workspace capability matrix in docs/PROGRESS.md §1
// is the source of truth for that dimension.
type ConnectorCapabilities struct {
	Registered   bool `json:"registered"`
	GetAccessLog bool `json:"get_access_log"`
}

// ListConnectorsQuery is the input contract for
// AccessConnectorListService.ListConnectors. WorkspaceID is required
// so the handler never serves an unbounded list across tenants.
// Status (optional) filters access_connectors.status server-side so
// the UI doesn't have to download every row to render "only show
// errored connectors".
type ListConnectorsQuery struct {
	WorkspaceID string
	Status      *string
}

// AccessConnectorListService is the read-only service that backs
// GET /access/connectors. Production wiring lives in cmd/ztna-api;
// tests substitute a fake at the handler interface boundary.
type AccessConnectorListService struct {
	db *gorm.DB
}

// NewAccessConnectorListService returns a service bound to db. db
// must not be nil. The connector registry is read through the
// process-global GetAccessConnector / GetOptionalAccessAuditor
// helpers, not injected, because re-injection per request would
// invite drift between the binary's blank-imports and the surface
// the handler advertises.
func NewAccessConnectorListService(db *gorm.DB) *AccessConnectorListService {
	return &AccessConnectorListService{db: db}
}

// ListConnectors returns the per-connector summary rows for the
// workspace in q. Filters on Status when supplied. The
// LastSyncTimes map is keyed by sync kind ("identity" / "group" /
// "audit"); missing kinds are omitted. Empty result set returns
// (nil, nil); a DB error returns the wrapped error.
func (s *AccessConnectorListService) ListConnectors(ctx context.Context, q ListConnectorsQuery) ([]ConnectorSummary, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("access: connector list service not configured")
	}
	if q.WorkspaceID == "" {
		return nil, fmt.Errorf("%w: workspace_id is required", ErrValidation)
	}
	tx := s.db.WithContext(ctx).Where("workspace_id = ?", q.WorkspaceID)
	if q.Status != nil {
		tx = tx.Where("status = ?", *q.Status)
	}
	var rows []models.AccessConnector
	if err := tx.Order("provider asc, connector_type asc").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("access: list access_connectors: %w", err)
	}
	if len(rows) == 0 {
		return nil, nil
	}
	ids := make([]string, 0, len(rows))
	for i := range rows {
		ids = append(ids, rows[i].ID)
	}
	var states []models.AccessSyncState
	if err := s.db.WithContext(ctx).
		Where("connector_id IN ?", ids).
		Find(&states).Error; err != nil {
		return nil, fmt.Errorf("access: list access_sync_state: %w", err)
	}
	perConnector := make(map[string]map[string]time.Time, len(rows))
	for _, st := range states {
		m := perConnector[st.ConnectorID]
		if m == nil {
			m = make(map[string]time.Time, 3)
			perConnector[st.ConnectorID] = m
		}
		if existing, ok := m[st.Kind]; !ok || st.UpdatedAt.After(existing) {
			m[st.Kind] = st.UpdatedAt
		}
	}
	out := make([]ConnectorSummary, 0, len(rows))
	for i := range rows {
		row := rows[i]
		caps := connectorCapabilitiesForProvider(row.Provider)
		last := perConnector[row.ID]
		if last == nil {
			last = map[string]time.Time{}
		}
		out = append(out, ConnectorSummary{
			ID:                    row.ID,
			WorkspaceID:           row.WorkspaceID,
			Provider:              row.Provider,
			ConnectorType:         row.ConnectorType,
			Status:                row.Status,
			CredentialExpiredTime: row.CredentialExpiredTime,
			LastSyncTimes:         last,
			Capabilities:          caps,
			CreatedAt:             row.CreatedAt,
			UpdatedAt:             row.UpdatedAt,
		})
	}
	return out, nil
}

// connectorCapabilitiesForProvider derives the capability flags for
// the registered connector under provider. A missing blank-import
// (the connector package's init() never ran) returns Registered=false
// and every other flag is false. Tests cover this branch by leaving
// the registry empty.
func connectorCapabilitiesForProvider(provider string) ConnectorCapabilities {
	caps := ConnectorCapabilities{}
	conn, err := GetAccessConnector(provider)
	if err != nil || conn == nil {
		return caps
	}
	caps.Registered = true
	if _, ok := conn.(AccessAuditor); ok {
		caps.GetAccessLog = true
	}
	return caps
}
