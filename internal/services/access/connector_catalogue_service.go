package access

import (
	"context"
	"fmt"
	"sort"

	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// ConnectorCatalogueEntry is one row in the response to
// GET /access/connectors/catalogue. It pairs the static, registry-
// derived snapshot of a connector (which capabilities the binary
// exposes for that provider) with the workspace-scoped connection
// state (whether the operator has actually connected this provider
// to the workspace yet).
//
// The shape is deliberately wider than ConnectorSummary because the
// catalogue endpoint is what the Admin UI's "available integrations"
// grid renders — it has to show every provider the binary ships,
// not just the ones that already have an access_connectors row.
//
// JSON tags use snake_case to match the rest of the access surface.
type ConnectorCatalogueEntry struct {
	Provider     string                       `json:"provider"`
	Capabilities ConnectorCatalogueCapabilities `json:"capabilities"`
	Connected    bool                         `json:"connected"`
	// ConnectorID is the access_connectors.id for the workspace's
	// existing connection, when Connected is true. Empty otherwise.
	// Surfaced so the Admin UI can deep-link from the catalogue
	// tile into the connector detail page without a second query.
	ConnectorID string `json:"connector_id,omitempty"`
	// Status mirrors access_connectors.status for the workspace's
	// existing row when Connected is true. Empty otherwise.
	Status string `json:"status,omitempty"`
}

// ConnectorCatalogueCapabilities is the per-provider capability
// snapshot reported by the catalogue. The flags are derived at
// registry-lookup time via type-assertion against the connector's
// optional interfaces (GroupSyncer, IdentityDeltaSyncer, AccessAuditor,
// SCIMProvisioner) so the catalogue can never drift away from the
// code actually shipped in the binary.
type ConnectorCatalogueCapabilities struct {
	Registered          bool `json:"registered"`
	GetAccessLog        bool `json:"get_access_log"`
	SyncGroups          bool `json:"sync_groups"`
	SyncIdentitiesDelta bool `json:"sync_identities_delta"`
	SCIMProvisioning    bool `json:"scim_provisioning"`
}

// ConnectorCatalogueQuery is the input contract for
// AccessConnectorCatalogueService.ListCatalogue. WorkspaceID is
// required so the Connected / ConnectorID / Status enrichment can
// be scoped to one workspace; the catalogue is not multi-tenant
// across workspaces because the "is this provider connected?"
// answer is per-workspace.
type ConnectorCatalogueQuery struct {
	WorkspaceID string
}

// AccessConnectorCatalogueService backs GET /access/connectors/catalogue.
// The service enumerates the process-global registry (ListRegisteredProviders)
// rather than reading a separate static catalogue file because the
// registry is the single source of truth for "which connectors does
// this binary actually ship?". A separate static catalogue would
// invite drift between docs and code, exactly what the SDK contract
// tests are designed to prevent.
type AccessConnectorCatalogueService struct {
	db *gorm.DB
}

// NewAccessConnectorCatalogueService returns a service bound to db.
// db may be nil — in that case the service still enumerates the
// registry but every entry comes back with Connected=false and the
// workspace enrichment is skipped. This keeps dev binaries (and the
// Admin-UI integration tests) functional without a DB.
func NewAccessConnectorCatalogueService(db *gorm.DB) *AccessConnectorCatalogueService {
	return &AccessConnectorCatalogueService{db: db}
}

// ListCatalogue returns one entry per provider currently registered
// in the process. Entries are sorted by provider key. When
// q.WorkspaceID is non-empty and the service has a DB, the entries
// for providers the workspace has connected are enriched with the
// matching access_connectors row's id + status.
//
// A workspace with multiple connector rows for the same provider
// (e.g. two AWS accounts) is collapsed onto a single catalogue
// entry. The entry's ConnectorID / Status come from the most-recently-
// updated row so the Admin UI's deep-link points at the row the
// operator is most likely thinking about. Surfacing multi-connector
// metadata is a future Admin-UI feature; the catalogue endpoint
// intentionally only carries one row per provider.
func (s *AccessConnectorCatalogueService) ListCatalogue(ctx context.Context, q ConnectorCatalogueQuery) ([]ConnectorCatalogueEntry, error) {
	if q.WorkspaceID == "" {
		return nil, fmt.Errorf("%w: workspace_id is required", ErrValidation)
	}

	providers := ListRegisteredProviders()
	out := make([]ConnectorCatalogueEntry, 0, len(providers))
	for _, p := range providers {
		out = append(out, ConnectorCatalogueEntry{
			Provider:     p,
			Capabilities: catalogueCapabilitiesForProvider(p),
		})
	}

	if s == nil || s.db == nil {
		sort.Slice(out, func(i, j int) bool { return out[i].Provider < out[j].Provider })
		return out, nil
	}

	var rows []models.AccessConnector
	if err := s.db.WithContext(ctx).
		Where("workspace_id = ?", q.WorkspaceID).
		Order("provider asc, updated_at desc").
		Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("access: list access_connectors for catalogue: %w", err)
	}

	connected := make(map[string]models.AccessConnector, len(rows))
	for i := range rows {
		row := rows[i]
		// Order is "provider asc, updated_at desc" so the first
		// row per provider is the freshest; subsequent rows for
		// the same provider are ignored for catalogue purposes.
		if _, exists := connected[row.Provider]; exists {
			continue
		}
		connected[row.Provider] = row
	}

	for i := range out {
		if row, ok := connected[out[i].Provider]; ok {
			out[i].Connected = true
			out[i].ConnectorID = row.ID
			out[i].Status = row.Status
		}
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Provider < out[j].Provider })
	return out, nil
}

// catalogueCapabilitiesForProvider returns the capability flags for
// the connector registered under provider. A missing connector (the
// blank-import never ran) returns Registered=false and every other
// flag is false. The flags are derived by type-asserting the
// registered connector against the optional interfaces declared in
// optional_interfaces.go.
func catalogueCapabilitiesForProvider(provider string) ConnectorCatalogueCapabilities {
	caps := ConnectorCatalogueCapabilities{}
	conn, err := GetAccessConnector(provider)
	if err != nil || conn == nil {
		return caps
	}
	caps.Registered = true
	if _, ok := conn.(AccessAuditor); ok {
		caps.GetAccessLog = true
	}
	if _, ok := conn.(GroupSyncer); ok {
		caps.SyncGroups = true
	}
	if _, ok := conn.(IdentityDeltaSyncer); ok {
		caps.SyncIdentitiesDelta = true
	}
	if _, ok := conn.(SCIMProvisioner); ok {
		caps.SCIMProvisioning = true
	}
	return caps
}


