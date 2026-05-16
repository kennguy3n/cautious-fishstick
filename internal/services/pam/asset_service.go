// Package pam hosts the service layer for the Privileged Access
// Management module per docs/pam/architecture.md. The package owns
// CRUD over the pam_assets / pam_accounts inventory, the
// SecretBrokerService (vault / reveal / rotate), and the
// PAMLeaseService (JIT lease lifecycle integrated with the existing
// AccessRequestService state machine).
//
// Conventions (per docs/architecture.md cross-cutting criteria):
//
//   - All primary keys are 26-char Crockford-base32 ULIDs generated
//     via ulid.MustNew(ulid.Now(), rand.Reader). Tests may override
//     the ID hook through the service constructor.
//   - No FOREIGN KEY constraints — referential integrity to the
//     workspaces / users / access_connectors / access_requests tables
//     is enforced at this layer.
//   - Every multi-write path is wrapped in a *gorm.DB.Transaction so
//     a partial failure leaves no orphaned rows.
package pam

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"github.com/oklog/ulid/v2"
	"gorm.io/datatypes"
	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// Sentinel errors for the PAM service layer. Wrapped with fmt.Errorf
// so callers can errors.Is them without depending on the message
// format. Mapped to HTTP status codes by the handler layer.
var (
	// ErrValidation is returned when input validation fails (missing
	// required field, invalid enum, port out of range, ...).
	ErrValidation = errors.New("pam: validation failed")

	// ErrAssetNotFound is returned when the supplied asset ID does
	// not match a row scoped by workspace.
	ErrAssetNotFound = errors.New("pam: asset not found")

	// ErrAccountNotFound is returned when the supplied account ID
	// does not match a row scoped by asset.
	ErrAccountNotFound = errors.New("pam: account not found")
)

// PAMAssetService backs the /pam/assets/* HTTP surface and owns CRUD
// over pam_assets + pam_accounts. The service does not directly
// vault secrets — that responsibility belongs to SecretBrokerService.
//
// Validation lives at this layer (not the model) so the handler can
// return the canonical ErrValidation envelope without the model
// package depending on the service-layer error sentinels.
type PAMAssetService struct {
	db *gorm.DB
	// now is overridable in tests so we can pin CreatedAt
	// timestamps in assertions. Defaults to time.Now in
	// NewPAMAssetService.
	now func() time.Time
	// newID is overridable in tests so we can pin generated IDs.
	// Defaults to a Crockford-base32 ULID in NewPAMAssetService.
	newID func() string
}

// NewPAMAssetService returns a new service backed by db. db must not
// be nil — passing nil panics on first use; the constructor does not
// pre-validate because tests sometimes want to substitute a no-op DB.
func NewPAMAssetService(db *gorm.DB) *PAMAssetService {
	return &PAMAssetService{
		db:    db,
		now:   time.Now,
		newID: NewULID,
	}
}

// NewULID is the package-level ULID generator. Exported so the cron
// + handler layers can produce IDs without depending on a service
// instance.
func NewULID() string {
	return ulid.MustNew(ulid.Now(), rand.Reader).String()
}

// CreateAssetInput is the input contract for CreateAsset. All
// string fields except OwnerUserID + Config are required.
type CreateAssetInput struct {
	Name        string
	Protocol    string
	Host        string
	Port        int
	Criticality string
	OwnerUserID string
	Config      datatypes.JSON
}

// validateCreateAsset rejects missing required fields and invalid
// enums. Wrapped errors stay errors.Is-compatible with ErrValidation
// so the handler layer can map them to 400.
func validateCreateAsset(in CreateAssetInput) error {
	if in.Name == "" {
		return fmt.Errorf("%w: name is required", ErrValidation)
	}
	if in.Host == "" {
		return fmt.Errorf("%w: host is required", ErrValidation)
	}
	if in.Port <= 0 || in.Port >= 65536 {
		return fmt.Errorf("%w: port must be between 1 and 65535", ErrValidation)
	}
	if !models.IsValidPAMProtocol(in.Protocol) {
		return fmt.Errorf("%w: protocol %q is not one of ssh/rdp/k8s/postgres/mysql", ErrValidation, in.Protocol)
	}
	if in.Criticality != "" && !models.IsValidPAMCriticality(in.Criticality) {
		return fmt.Errorf("%w: criticality %q is not one of low/medium/high/critical", ErrValidation, in.Criticality)
	}
	return nil
}

// CreateAsset validates input, generates a ULID, and persists a new
// pam_assets row in status=active. workspaceID is required and is
// the only "outer" scope check the service performs — the caller
// (handler) is responsible for authorising the workspace.
func (s *PAMAssetService) CreateAsset(ctx context.Context, workspaceID string, in CreateAssetInput) (*models.PAMAsset, error) {
	if workspaceID == "" {
		return nil, fmt.Errorf("%w: workspace_id is required", ErrValidation)
	}
	if err := validateCreateAsset(in); err != nil {
		return nil, err
	}
	criticality := in.Criticality
	if criticality == "" {
		criticality = models.PAMCriticalityMedium
	}
	now := s.now().UTC()
	asset := &models.PAMAsset{
		ID:          s.newID(),
		WorkspaceID: workspaceID,
		Name:        in.Name,
		Protocol:    in.Protocol,
		Host:        in.Host,
		Port:        in.Port,
		Criticality: criticality,
		OwnerUserID: in.OwnerUserID,
		Config:      in.Config,
		Status:      models.PAMAssetStatusActive,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := s.db.WithContext(ctx).Create(asset).Error; err != nil {
		return nil, fmt.Errorf("pam: insert pam_asset: %w", err)
	}
	return asset, nil
}

// GetAsset loads a single asset by ULID scoped to workspaceID. Both
// arguments are required. Returns ErrAssetNotFound (wrapped) when no
// row matches.
func (s *PAMAssetService) GetAsset(ctx context.Context, workspaceID, assetID string) (*models.PAMAsset, error) {
	if workspaceID == "" {
		return nil, fmt.Errorf("%w: workspace_id is required", ErrValidation)
	}
	if assetID == "" {
		return nil, fmt.Errorf("%w: asset id is required", ErrValidation)
	}
	var asset models.PAMAsset
	err := s.db.WithContext(ctx).
		Where("workspace_id = ? AND id = ?", workspaceID, assetID).
		First(&asset).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("%w: %s", ErrAssetNotFound, assetID)
		}
		return nil, fmt.Errorf("pam: get pam_asset: %w", err)
	}
	return &asset, nil
}

// ListAssetsFilters lets callers narrow ListAssets without growing
// the method signature each release. Empty / nil fields mean "no
// filter on this dimension".
type ListAssetsFilters struct {
	Protocol    string
	Status      string
	Criticality string
	Limit       int
	Offset      int
}

// ListAssets returns the pam_assets rows matching filters scoped to
// workspaceID. Results are ordered by created_at descending so the
// admin UI shows newest assets first. Soft-deleted (DeletedAt non-
// nil) rows are excluded by GORM's default scope; archived rows
// remain visible unless Status is supplied.
func (s *PAMAssetService) ListAssets(ctx context.Context, workspaceID string, filters ListAssetsFilters) ([]models.PAMAsset, error) {
	if workspaceID == "" {
		return nil, fmt.Errorf("%w: workspace_id is required", ErrValidation)
	}
	tx := s.db.WithContext(ctx).Where("workspace_id = ?", workspaceID)
	if filters.Protocol != "" {
		tx = tx.Where("protocol = ?", filters.Protocol)
	}
	if filters.Status != "" {
		tx = tx.Where("status = ?", filters.Status)
	}
	if filters.Criticality != "" {
		tx = tx.Where("criticality = ?", filters.Criticality)
	}
	if filters.Limit > 0 {
		tx = tx.Limit(filters.Limit)
	}
	if filters.Offset > 0 {
		tx = tx.Offset(filters.Offset)
	}
	var out []models.PAMAsset
	if err := tx.Order("created_at desc").Find(&out).Error; err != nil {
		return nil, fmt.Errorf("pam: list pam_assets: %w", err)
	}
	return out, nil
}

// UpdateAssetInput captures the partial-update payload accepted by
// UpdateAsset. All fields are optional; a nil pointer / empty string
// leaves the column untouched.
type UpdateAssetInput struct {
	Name        *string
	Host        *string
	Port        *int
	Criticality *string
	OwnerUserID *string
	Config      *datatypes.JSON
	Status      *string
}

// UpdateAsset applies a partial update to an existing row. Validation
// runs against the supplied fields only — an absent field is left
// unchanged. Returns the post-update row.
func (s *PAMAssetService) UpdateAsset(ctx context.Context, workspaceID, assetID string, in UpdateAssetInput) (*models.PAMAsset, error) {
	asset, err := s.GetAsset(ctx, workspaceID, assetID)
	if err != nil {
		return nil, err
	}
	updates := map[string]interface{}{}
	if in.Name != nil {
		if *in.Name == "" {
			return nil, fmt.Errorf("%w: name cannot be empty", ErrValidation)
		}
		updates["name"] = *in.Name
	}
	if in.Host != nil {
		if *in.Host == "" {
			return nil, fmt.Errorf("%w: host cannot be empty", ErrValidation)
		}
		updates["host"] = *in.Host
	}
	if in.Port != nil {
		if *in.Port <= 0 || *in.Port >= 65536 {
			return nil, fmt.Errorf("%w: port must be between 1 and 65535", ErrValidation)
		}
		updates["port"] = *in.Port
	}
	if in.Criticality != nil {
		if !models.IsValidPAMCriticality(*in.Criticality) {
			return nil, fmt.Errorf("%w: criticality %q is not one of low/medium/high/critical", ErrValidation, *in.Criticality)
		}
		updates["criticality"] = *in.Criticality
	}
	if in.OwnerUserID != nil {
		updates["owner_user_id"] = *in.OwnerUserID
	}
	if in.Config != nil {
		updates["config"] = *in.Config
	}
	if in.Status != nil {
		if !models.IsValidPAMAssetStatus(*in.Status) {
			return nil, fmt.Errorf("%w: status %q is not one of active/inactive/archived", ErrValidation, *in.Status)
		}
		updates["status"] = *in.Status
	}
	if len(updates) == 0 {
		return asset, nil
	}
	updates["updated_at"] = s.now().UTC()
	if err := s.db.WithContext(ctx).
		Model(&models.PAMAsset{}).
		Where("workspace_id = ? AND id = ?", workspaceID, assetID).
		Updates(updates).Error; err != nil {
		return nil, fmt.Errorf("pam: update pam_asset: %w", err)
	}
	return s.GetAsset(ctx, workspaceID, assetID)
}

// DeleteAsset soft-deletes an asset by setting its Status to
// archived. We deliberately avoid a hard delete so historical
// pam_sessions / pam_leases pointing at the asset stay
// reconcilable in audit views. The row remains queryable via
// ListAssets when filters.Status="archived".
func (s *PAMAssetService) DeleteAsset(ctx context.Context, workspaceID, assetID string) error {
	asset, err := s.GetAsset(ctx, workspaceID, assetID)
	if err != nil {
		return err
	}
	if asset.Status == models.PAMAssetStatusArchived {
		return nil
	}
	now := s.now().UTC()
	if err := s.db.WithContext(ctx).
		Model(&models.PAMAsset{}).
		Where("workspace_id = ? AND id = ?", workspaceID, assetID).
		Updates(map[string]interface{}{
			"status":     models.PAMAssetStatusArchived,
			"updated_at": now,
		}).Error; err != nil {
		return fmt.Errorf("pam: archive pam_asset: %w", err)
	}
	return nil
}

// CreateAccountInput is the input contract for CreateAccount.
type CreateAccountInput struct {
	Username    string
	AccountType string
	SecretID    *string
	IsDefault   bool
}

// validateCreateAccount enforces required fields + enum membership.
func validateCreateAccount(in CreateAccountInput) error {
	if in.Username == "" {
		return fmt.Errorf("%w: username is required", ErrValidation)
	}
	if in.AccountType == "" {
		return fmt.Errorf("%w: account_type is required", ErrValidation)
	}
	if !models.IsValidPAMAccountType(in.AccountType) {
		return fmt.Errorf("%w: account_type %q is not one of shared/personal/service", ErrValidation, in.AccountType)
	}
	return nil
}

// CreateAccount validates input, confirms the asset exists AND is
// owned by workspaceID, and persists a new pam_accounts row. The
// workspace check is enforced at the service layer (not just the
// handler) so a future caller cannot accidentally bypass tenancy
// isolation by passing only an asset ULID from another workspace.
func (s *PAMAssetService) CreateAccount(ctx context.Context, workspaceID, assetID string, in CreateAccountInput) (*models.PAMAccount, error) {
	if workspaceID == "" {
		return nil, fmt.Errorf("%w: workspace_id is required", ErrValidation)
	}
	if assetID == "" {
		return nil, fmt.Errorf("%w: asset_id is required", ErrValidation)
	}
	if err := validateCreateAccount(in); err != nil {
		return nil, err
	}
	// Probe the asset row scoped to the calling workspace — a
	// match in another workspace must surface as NotFound so the
	// caller cannot infer which workspace owns the asset.
	var asset models.PAMAsset
	if err := s.db.WithContext(ctx).
		Where("workspace_id = ? AND id = ?", workspaceID, assetID).
		First(&asset).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("%w: %s", ErrAssetNotFound, assetID)
		}
		return nil, fmt.Errorf("pam: probe asset for account create: %w", err)
	}
	now := s.now().UTC()
	account := &models.PAMAccount{
		ID:          s.newID(),
		AssetID:     assetID,
		Username:    in.Username,
		AccountType: in.AccountType,
		SecretID:    in.SecretID,
		IsDefault:   in.IsDefault,
		Status:      models.PAMAccountStatusActive,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := s.db.WithContext(ctx).Create(account).Error; err != nil {
		return nil, fmt.Errorf("pam: insert pam_account: %w", err)
	}
	return account, nil
}

// ListAccounts returns the pam_accounts rows attached to assetID
// ordered by created_at ascending so the "default" account renders
// near the top in admin UIs.
func (s *PAMAssetService) ListAccounts(ctx context.Context, assetID string) ([]models.PAMAccount, error) {
	if assetID == "" {
		return nil, fmt.Errorf("%w: asset_id is required", ErrValidation)
	}
	var out []models.PAMAccount
	if err := s.db.WithContext(ctx).
		Where("asset_id = ?", assetID).
		Order("created_at asc").
		Find(&out).Error; err != nil {
		return nil, fmt.Errorf("pam: list pam_accounts: %w", err)
	}
	return out, nil
}
