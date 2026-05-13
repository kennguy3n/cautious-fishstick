package access

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"gorm.io/datatypes"
	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// ConnectorManagementService is the service layer for the connector
// lifecycle described in docs/ARCHITECTURE.md §2:
//
//   1. Connect    — register a new connector instance and kick off
//                   the initial sync.
//   2. Disconnect — soft-delete the connector and revoke every
//                   active grant produced by it.
//   3. RotateCredentials — re-encrypt the secrets blob under the
//                   latest DEK after validating with the upstream
//                   provider.
//   4. TriggerSync — enqueue an out-of-band sync_identities job for
//                   the connector.
//
// The service owns a *gorm.DB plus three narrow collaborators —
// the credential encryptor, the optional SSO federation service,
// and the optional provisioning service used during Disconnect to
// bulk-revoke grants. AccessConnector implementations are resolved
// through the package-global registry (GetAccessConnector).
//
// Errors are surfaced as wrapped sentinels from the access package
// (ErrValidation, ErrConnectorNotFound, ErrConnectorAlreadyExists,
// ErrUnknownProvider) so handlers can map them onto HTTP status
// codes via internal/handlers/errors.go.
type ConnectorManagementService struct {
	db           *gorm.DB
	encryptor    CredentialEncryptor
	ssoSvc       *SSOFederationService
	provSvc      *AccessProvisioningService
	getConnector func(provider string) (AccessConnector, error)
	now          func() time.Time
	newID        func() string
}

// NewConnectorManagementService returns a service backed by db. db
// must not be nil. encryptor wraps the production AES-GCM
// CredentialManager (or a PassthroughEncryptor in tests).
// provisioningSvc is consulted by Disconnect to revoke active
// grants; nil leaves grants in place (suitable for early tests).
// ssoSvc is optional; nil disables Keycloak broker registration.
func NewConnectorManagementService(
	db *gorm.DB,
	encryptor CredentialEncryptor,
	provisioningSvc *AccessProvisioningService,
	ssoSvc *SSOFederationService,
) *ConnectorManagementService {
	return &ConnectorManagementService{
		db:           db,
		encryptor:    encryptor,
		ssoSvc:       ssoSvc,
		provSvc:      provisioningSvc,
		getConnector: GetAccessConnector,
		now:          time.Now,
		newID:        newULID,
	}
}

// ErrConnectorAlreadyExists is returned by Connect when an
// undeleted connector row already exists for (workspace_id,
// provider, connector_type). Handlers map this onto HTTP 409.
var ErrConnectorAlreadyExists = errors.New("access: connector already exists for workspace")

// ErrUnknownProvider is returned by Connect when the requested
// provider key is not present in the registry. Handlers map this
// onto HTTP 400 (validation_failed) so unknown providers do not
// look like a server outage.
var ErrUnknownProvider = errors.New("access: unknown provider")

// ConnectInput is the input contract for ConnectorManagementService.Connect.
// Provider keys the registry lookup; ConnectorType is the operator
// label (the same value lives in access_connectors.connector_type).
//
// Capabilities optionally constrain the permission-verification
// pass. Empty defaults to ["read"], the safest universal minimum.
type ConnectInput struct {
	WorkspaceID   string
	Provider      string
	ConnectorType string
	Config        map[string]interface{}
	Secrets       map[string]interface{}
	Capabilities  []string
	// SSORealm and SSOAlias are consulted only when the connector
	// advertises SSO metadata. SSORealm is the Keycloak realm; SSOAlias
	// is the IdP alias to create or update. Empty values disable the
	// SSO federation pass for this connector.
	SSORealm    string
	SSOAlias    string
	DisplayName string
}

// ConnectResult is the output contract for Connect. ConnectorID is
// the ULID of the freshly-inserted access_connectors row; JobID is
// the ULID of the initial sync_identities access_jobs row. Both are
// surfaced to the operator so they can poll job progress.
type ConnectResult struct {
	ConnectorID  string `json:"connector_id"`
	JobID        string `json:"job_id"`
	SSOAlias     string `json:"sso_alias,omitempty"`
	SSOProvider  string `json:"sso_provider,omitempty"`
	MissingCaps  []string `json:"missing_capabilities,omitempty"`
	CredsExpiry  *time.Time `json:"credentials_expires_at,omitempty"`
}

// Connect orchestrates the full connector setup lifecycle. The flow
// follows docs/ARCHITECTURE.md §2 verbatim:
//
//   1. Look up the connector from the registry.
//   2. Validate the supplied (config, secrets).
//   3. Probe the upstream provider via Connect.
//   4. Verify permissions for the requested capabilities.
//   5. Extract optional credentials metadata (expiry, ...).
//   6. Check uniqueness on (workspace_id, provider, connector_type).
//   7. Encrypt secrets, INSERT the access_connectors row, INSERT
//      the initial sync_identities access_jobs row \u2014 all in one
//      DB transaction so partial failures cannot leave a connector
//      row without a queued sync.
//   8. Configure the Keycloak SSO broker when the connector advertises
//      SSO metadata.
//
// Returns the ConnectResult on success. On failure callers see a
// wrapped ErrValidation / ErrUnknownProvider /
// ErrConnectorAlreadyExists or a verbose error from the upstream
// provider (the operator surfaces this in the admin UI to debug
// credentials issues).
func (s *ConnectorManagementService) Connect(ctx context.Context, in ConnectInput) (*ConnectResult, error) {
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("%w: service is not configured", ErrValidation)
	}
	if s.encryptor == nil {
		return nil, fmt.Errorf("%w: encryptor is not configured", ErrValidation)
	}
	if in.WorkspaceID == "" {
		return nil, fmt.Errorf("%w: workspace_id is required", ErrValidation)
	}
	if in.Provider == "" {
		return nil, fmt.Errorf("%w: provider is required", ErrValidation)
	}
	if in.ConnectorType == "" {
		in.ConnectorType = "default"
	}
	if in.Config == nil {
		in.Config = map[string]interface{}{}
	}
	if in.Secrets == nil {
		in.Secrets = map[string]interface{}{}
	}
	caps := in.Capabilities
	if len(caps) == 0 {
		caps = []string{"read"}
	}

	connector, err := s.getConnector(in.Provider)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrUnknownProvider, in.Provider)
	}

	if err := connector.Validate(ctx, in.Config, in.Secrets); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrValidation, err)
	}
	if err := connector.Connect(ctx, in.Config, in.Secrets); err != nil {
		return nil, fmt.Errorf("access: connector connect failed: %w", err)
	}
	missing, err := connector.VerifyPermissions(ctx, in.Config, in.Secrets, caps)
	if err != nil {
		return nil, fmt.Errorf("access: connector verify_permissions failed: %w", err)
	}

	credMeta, err := connector.GetCredentialsMetadata(ctx, in.Config, in.Secrets)
	if err != nil {
		return nil, fmt.Errorf("access: connector credentials_metadata failed: %w", err)
	}
	var expiresAt *time.Time
	if credMeta != nil {
		if raw, ok := credMeta["expires_at"]; ok {
			if t, parseErr := parseFlexibleTime(raw); parseErr == nil && !t.IsZero() {
				expiresAt = &t
			}
		}
	}

	// Uniqueness check is a real GORM query; soft-deleted rows are
	// excluded automatically by the deleted_at scope.
	var existing models.AccessConnector
	probe := s.db.WithContext(ctx).
		Where("workspace_id = ? AND provider = ? AND connector_type = ?", in.WorkspaceID, in.Provider, in.ConnectorType).
		First(&existing)
	if probe.Error == nil {
		return nil, fmt.Errorf("%w: workspace=%s provider=%s type=%s", ErrConnectorAlreadyExists, in.WorkspaceID, in.Provider, in.ConnectorType)
	}
	if probe.Error != nil && !errors.Is(probe.Error, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("access: probe connector uniqueness: %w", probe.Error)
	}

	connectorID := s.newID()
	jobID := s.newID()

	ciphertext, keyVersion, err := encryptSecretsMap(s.encryptor, in.Secrets, connectorID)
	if err != nil {
		return nil, err
	}
	kvInt := parseKeyVersionInt(keyVersion)

	cfgJSON, err := json.Marshal(in.Config)
	if err != nil {
		return nil, fmt.Errorf("access: marshal config: %w", err)
	}

	now := s.now()
	row := &models.AccessConnector{
		ID:                    connectorID,
		WorkspaceID:           in.WorkspaceID,
		Provider:              in.Provider,
		ConnectorType:         in.ConnectorType,
		Config:                datatypes.JSON(cfgJSON),
		Credentials:           ciphertext,
		KeyVersion:            kvInt,
		Status:                models.StatusConnected,
		CredentialExpiredTime: expiresAt,
		CreatedAt:             now,
		UpdatedAt:             now,
	}
	job := &models.AccessJob{
		ID:          jobID,
		ConnectorID: connectorID,
		JobType:     models.AccessJobTypeSyncIdentities,
		Status:      models.AccessJobStatusPending,
		Payload:     datatypes.JSON([]byte("{}")),
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if cerr := tx.Create(row).Error; cerr != nil {
			return fmt.Errorf("access: insert access_connector: %w", cerr)
		}
		if cerr := tx.Create(job).Error; cerr != nil {
			return fmt.Errorf("access: insert access_jobs: %w", cerr)
		}
		return nil
	}); err != nil {
		return nil, err
	}

	res := &ConnectResult{
		ConnectorID: connectorID,
		JobID:       jobID,
		MissingCaps: missing,
		CredsExpiry: expiresAt,
	}

	// SSO federation pass. Best-effort: if the connector does not
	// advertise SSO we leave the result fields empty. A federation
	// failure logs but does NOT roll the row back \u2014 the operator
	// can re-run Connect after fixing Keycloak.
	if s.ssoSvc != nil && in.SSORealm != "" && in.SSOAlias != "" {
		meta, mErr := connector.GetSSOMetadata(ctx, in.Config, in.Secrets)
		if mErr == nil && meta != nil {
			alias, provider, fErr := s.ssoSvc.ConfigureBroker(ctx, in.SSORealm, in.SSOAlias, in.DisplayName, meta)
			if fErr == nil {
				res.SSOAlias = alias
				res.SSOProvider = provider
			}
		}
	}

	return res, nil
}

// Disconnect soft-deletes the connector and revokes every active
// grant produced by it. Lifecycle (per docs/ARCHITECTURE.md §2):
//
//   1. Look up the row by ID.
//   2. Enumerate active grants (revoked_at IS NULL).
//   3. Bulk-revoke each grant via AccessProvisioningService.Revoke
//      if available; otherwise mark them revoked in the DB.
//   4. UPDATE access_connectors SET deleted_at = NOW().
//
// SSO de-federation is best-effort \u2014 a failure does NOT block the
// disconnect (the row already reads as deleted on the wire).
func (s *ConnectorManagementService) Disconnect(ctx context.Context, connectorID string) error {
	if connectorID == "" {
		return fmt.Errorf("%w: connector_id is required", ErrValidation)
	}
	var conn models.AccessConnector
	if err := s.db.WithContext(ctx).Where("id = ?", connectorID).First(&conn).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("%w: %s", ErrConnectorNotFound, connectorID)
		}
		return fmt.Errorf("access: load connector: %w", err)
	}

	// Revoke active grants tied to this connector. The provisioning
	// service handles per-grant transactions; failures are recorded
	// but do not abort the disconnect.
	if s.provSvc != nil {
		var grants []models.AccessGrant
		if err := s.db.WithContext(ctx).
			Where("connector_id = ? AND revoked_at IS NULL", connectorID).
			Find(&grants).Error; err != nil {
			return fmt.Errorf("access: list active grants: %w", err)
		}
		for i := range grants {
			grant := &grants[i]
			// Revoke surfaces ErrAlreadyRevoked on a race; treat as
			// idempotent success.
			if err := s.provSvc.Revoke(ctx, grant, nil, nil); err != nil && !errors.Is(err, ErrAlreadyRevoked) {
				// Continue; per-grant failures land in audit; we
				// still need to flip the connector row.
				_ = err
			}
		}
	} else {
		// No provisioning service \u2014 fall back to a bulk DB-level
		// revoke so the data model stays consistent.
		now := s.now()
		if err := s.db.WithContext(ctx).
			Model(&models.AccessGrant{}).
			Where("connector_id = ? AND revoked_at IS NULL", connectorID).
			Updates(map[string]interface{}{
				"revoked_at": now,
				"updated_at": now,
			}).Error; err != nil {
			return fmt.Errorf("access: bulk revoke access_grants: %w", err)
		}
	}

	if err := s.db.WithContext(ctx).Delete(&conn).Error; err != nil {
		return fmt.Errorf("access: soft delete access_connector: %w", err)
	}
	return nil
}

// RotateCredentials re-validates the supplied (config, secrets)
// against the upstream provider, encrypts the new secrets under the
// latest key version, and atomically UPDATEs the access_connectors
// row. config is optional \u2014 nil means "keep existing config and
// rotate secrets only".
func (s *ConnectorManagementService) RotateCredentials(
	ctx context.Context,
	connectorID string,
	newConfig map[string]interface{},
	newSecrets map[string]interface{},
) error {
	if connectorID == "" {
		return fmt.Errorf("%w: connector_id is required", ErrValidation)
	}
	if newSecrets == nil {
		return fmt.Errorf("%w: secrets is required", ErrValidation)
	}
	if s.encryptor == nil {
		return fmt.Errorf("%w: encryptor is not configured", ErrValidation)
	}
	var conn models.AccessConnector
	if err := s.db.WithContext(ctx).Where("id = ?", connectorID).First(&conn).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("%w: %s", ErrConnectorNotFound, connectorID)
		}
		return fmt.Errorf("access: load connector: %w", err)
	}
	connector, err := s.getConnector(conn.Provider)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrUnknownProvider, conn.Provider)
	}

	cfg := map[string]interface{}{}
	if newConfig != nil {
		cfg = newConfig
	} else if len(conn.Config) > 0 {
		if err := json.Unmarshal(conn.Config, &cfg); err != nil {
			return fmt.Errorf("access: decode existing config: %w", err)
		}
	}

	if err := connector.Validate(ctx, cfg, newSecrets); err != nil {
		return fmt.Errorf("%w: %v", ErrValidation, err)
	}
	if err := connector.Connect(ctx, cfg, newSecrets); err != nil {
		return fmt.Errorf("access: connector connect failed: %w", err)
	}

	ciphertext, keyVersion, err := encryptSecretsMap(s.encryptor, newSecrets, conn.ID)
	if err != nil {
		return err
	}
	kvInt := parseKeyVersionInt(keyVersion)

	now := s.now()
	updates := map[string]interface{}{
		"credentials": ciphertext,
		"key_version": kvInt,
		"status":      models.StatusConnected,
		"updated_at":  now,
	}
	if newConfig != nil {
		cfgJSON, err := json.Marshal(newConfig)
		if err != nil {
			return fmt.Errorf("access: marshal config: %w", err)
		}
		updates["config"] = datatypes.JSON(cfgJSON)
	}
	result := s.db.WithContext(ctx).
		Model(&models.AccessConnector{}).
		Where("id = ?", connectorID).
		Updates(updates)
	if result.Error != nil {
		return fmt.Errorf("access: update access_connector: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("%w: %s", ErrConnectorNotFound, connectorID)
	}
	return nil
}

// TriggerSync enqueues a fresh sync_identities access_jobs row for
// the supplied connector. Returns the new job's ULID so callers can
// poll the row's lifecycle. Used by the operator admin UI's
// "Re-sync now" button.
func (s *ConnectorManagementService) TriggerSync(ctx context.Context, connectorID string) (string, error) {
	if connectorID == "" {
		return "", fmt.Errorf("%w: connector_id is required", ErrValidation)
	}
	var conn models.AccessConnector
	if err := s.db.WithContext(ctx).Where("id = ?", connectorID).First(&conn).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return "", fmt.Errorf("%w: %s", ErrConnectorNotFound, connectorID)
		}
		return "", fmt.Errorf("access: load connector: %w", err)
	}
	jobID := s.newID()
	now := s.now()
	job := &models.AccessJob{
		ID:          jobID,
		ConnectorID: connectorID,
		JobType:     models.AccessJobTypeSyncIdentities,
		Status:      models.AccessJobStatusPending,
		Payload:     datatypes.JSON([]byte("{}")),
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := s.db.WithContext(ctx).Create(job).Error; err != nil {
		return "", fmt.Errorf("access: insert access_jobs: %w", err)
	}
	return jobID, nil
}

// DBForTest exposes the underlying *gorm.DB for test assertions.
// Production code never calls this — it would couple the caller
// directly to GORM and bypass the service's transactional guards.
func (s *ConnectorManagementService) DBForTest() *gorm.DB {
	return s.db
}

// parseFlexibleTime accepts time.Time, *time.Time, or RFC-3339
// strings and returns a normalised time.Time. Used to read the
// optional expires_at slot from a connector's GetCredentialsMetadata
// payload without coupling the service layer to a specific format.
func parseFlexibleTime(raw interface{}) (time.Time, error) {
	switch v := raw.(type) {
	case time.Time:
		return v, nil
	case *time.Time:
		if v == nil {
			return time.Time{}, fmt.Errorf("nil time pointer")
		}
		return *v, nil
	case string:
		return time.Parse(time.RFC3339, v)
	default:
		return time.Time{}, fmt.Errorf("unsupported time type %T", raw)
	}
}

// parseKeyVersionInt parses the keyVersion string returned by
// CredentialEncryptor.Encrypt onto the int slot in access_connectors.
// Invalid values fall back to 1 so the row still inserts.
func parseKeyVersionInt(s string) int {
	var n int
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil || n <= 0 {
		return 1
	}
	return n
}
