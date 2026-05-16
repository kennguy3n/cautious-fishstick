package pam

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

// Sentinel errors for the lease service. Mapped to HTTP status
// codes by the handler layer.
var (
	// ErrLeaseNotFound is returned when the supplied lease ID does
	// not match a row.
	ErrLeaseNotFound = errors.New("pam: lease not found")

	// ErrLeaseAlreadyTerminal is returned when a transition is
	// requested on a lease that is already revoked or expired.
	ErrLeaseAlreadyTerminal = errors.New("pam: lease is already terminal")
)

// AccessRequestCreator is the narrow contract PAMLeaseService uses
// to create the underlying access_requests row that backs a JIT
// lease. The production implementation is *access.AccessRequestService;
// tests substitute a stub that captures the input without touching
// the DB.
//
// The interface is intentionally tiny so the PAM module never
// imports the full AccessRequestService surface — we only need
// CreateRequest.
type AccessRequestCreator interface {
	CreateRequest(ctx context.Context, input access.CreateAccessRequestInput) (*models.AccessRequest, error)
}

// LeaseNotifier is the optional hook PAMLeaseService calls to
// surface lease approvals + revocations + expiries to the affected
// user. The interface is narrow + best-effort — a failed notify
// must NOT roll back the lease transition.
type LeaseNotifier interface {
	// NotifyLeaseApproved fires when a lease moves into the
	// granted state.
	NotifyLeaseApproved(ctx context.Context, lease *models.PAMLease) error
	// NotifyLeaseRevoked fires when a lease is revoked before
	// its natural expiry.
	NotifyLeaseRevoked(ctx context.Context, lease *models.PAMLease, reason string) error
	// NotifyLeaseExpired fires when the expiry cron sweeps a
	// lease past its expires_at.
	NotifyLeaseExpired(ctx context.Context, lease *models.PAMLease) error
}

// PAMLeaseService backs the /pam/leases/* HTTP surface and owns the
// JIT lease lifecycle: request → approve → revoke / expire. Each
// lease is paired with an access_requests row via RequestID so the
// existing approval state machine + audit trail participate.
type PAMLeaseService struct {
	db             *gorm.DB
	requestCreator AccessRequestCreator
	notifier       LeaseNotifier
	now            func() time.Time
	newID          func() string
}

// NewPAMLeaseService returns a service backed by db. requestCreator
// may be nil for dev / test wiring; RequestLease degrades gracefully
// when it is unset (the access_requests row is simply not created).
// notifier may also be nil.
func NewPAMLeaseService(db *gorm.DB, requestCreator AccessRequestCreator, notifier LeaseNotifier) *PAMLeaseService {
	return &PAMLeaseService{
		db:             db,
		requestCreator: requestCreator,
		notifier:       notifier,
		now:            time.Now,
		newID:          NewULID,
	}
}

// RequestLeaseInput is the input contract for RequestLease.
type RequestLeaseInput struct {
	UserID          string
	AssetID         string
	AccountID       string
	Reason          string
	DurationMinutes int
}

// validateRequestLease enforces required fields + sensible bounds.
func validateRequestLease(in RequestLeaseInput) error {
	if in.UserID == "" {
		return fmt.Errorf("%w: user_id is required", ErrValidation)
	}
	if in.AssetID == "" {
		return fmt.Errorf("%w: asset_id is required", ErrValidation)
	}
	if in.AccountID == "" {
		return fmt.Errorf("%w: account_id is required", ErrValidation)
	}
	if in.DurationMinutes <= 0 {
		return fmt.Errorf("%w: duration_minutes must be > 0", ErrValidation)
	}
	if in.DurationMinutes > 24*60 {
		return fmt.Errorf("%w: duration_minutes must be <= 1440 (24h)", ErrValidation)
	}
	return nil
}

// RequestLease validates input, creates an access_requests row via
// the wired requestCreator (when present), and persists a new
// pam_leases row in the requested state (GrantedAt nil).
//
// The lease's RequestID is linked to the access_requests row so the
// approval workflow can transition the request through approve →
// approved, and the lease moves to "granted" via ApproveLease which
// looks the access_requests row up by RequestID for context.
func (s *PAMLeaseService) RequestLease(ctx context.Context, workspaceID string, in RequestLeaseInput) (*models.PAMLease, error) {
	if workspaceID == "" {
		return nil, fmt.Errorf("%w: workspace_id is required", ErrValidation)
	}
	if err := validateRequestLease(in); err != nil {
		return nil, err
	}
	var requestID string
	if s.requestCreator != nil {
		req, err := s.requestCreator.CreateRequest(ctx, access.CreateAccessRequestInput{
			WorkspaceID:        workspaceID,
			RequesterUserID:    in.UserID,
			TargetUserID:       in.UserID,
			ConnectorID:        in.AssetID,
			ResourceExternalID: in.AccountID,
			Role:               "pam_session",
			Justification:      in.Reason,
		})
		if err != nil {
			return nil, fmt.Errorf("pam: create underlying access request: %w", err)
		}
		requestID = req.ID
	}
	now := s.now().UTC()
	lease := &models.PAMLease{
		ID:          s.newID(),
		WorkspaceID: workspaceID,
		UserID:      in.UserID,
		AssetID:     in.AssetID,
		AccountID:   in.AccountID,
		RequestID:   requestID,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := s.db.WithContext(ctx).Create(lease).Error; err != nil {
		return nil, fmt.Errorf("pam: insert pam_lease: %w", err)
	}
	return lease, nil
}

// ApproveLease transitions a requested lease into the granted state.
// The expiry window is derived from the original
// RequestLeaseInput.DurationMinutes when the call site supplies it;
// callers that only have a leaseID pass durationMinutes=0 and the
// service falls back to a 60m default.
//
// approverID is recorded for the audit trail.
func (s *PAMLeaseService) ApproveLease(ctx context.Context, leaseID, approverID string, durationMinutes int) (*models.PAMLease, error) {
	if leaseID == "" {
		return nil, fmt.Errorf("%w: lease_id is required", ErrValidation)
	}
	if approverID == "" {
		return nil, fmt.Errorf("%w: approver_id is required", ErrValidation)
	}
	if durationMinutes <= 0 {
		durationMinutes = 60
	}
	var lease models.PAMLease
	err := s.db.WithContext(ctx).Where("id = ?", leaseID).First(&lease).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("%w: %s", ErrLeaseNotFound, leaseID)
		}
		return nil, fmt.Errorf("pam: get pam_lease: %w", err)
	}
	if lease.RevokedAt != nil {
		return nil, fmt.Errorf("%w: lease %s is revoked", ErrLeaseAlreadyTerminal, leaseID)
	}
	if lease.GrantedAt != nil {
		return &lease, nil
	}
	now := s.now().UTC()
	expiry := now.Add(time.Duration(durationMinutes) * time.Minute)
	updates := map[string]interface{}{
		"granted_at":  now,
		"expires_at":  expiry,
		"approved_by": approverID,
		"updated_at":  now,
	}
	if err := s.db.WithContext(ctx).
		Model(&models.PAMLease{}).
		Where("id = ?", leaseID).
		Updates(updates).Error; err != nil {
		return nil, fmt.Errorf("pam: approve pam_lease: %w", err)
	}
	lease.GrantedAt = &now
	lease.ExpiresAt = &expiry
	lease.ApprovedBy = approverID
	lease.UpdatedAt = now
	if s.notifier != nil {
		if err := s.notifier.NotifyLeaseApproved(ctx, &lease); err != nil {
			log.Printf("pam: lease approved notify failed: %v", err)
		}
	}
	return &lease, nil
}

// RevokeLease sets RevokedAt on the lease and (best-effort) notifies
// the holder. Revoking an already-revoked lease is a no-op.
func (s *PAMLeaseService) RevokeLease(ctx context.Context, leaseID, reason string) (*models.PAMLease, error) {
	if leaseID == "" {
		return nil, fmt.Errorf("%w: lease_id is required", ErrValidation)
	}
	var lease models.PAMLease
	err := s.db.WithContext(ctx).Where("id = ?", leaseID).First(&lease).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("%w: %s", ErrLeaseNotFound, leaseID)
		}
		return nil, fmt.Errorf("pam: get pam_lease: %w", err)
	}
	if lease.RevokedAt != nil {
		return &lease, nil
	}
	now := s.now().UTC()
	if err := s.db.WithContext(ctx).
		Model(&models.PAMLease{}).
		Where("id = ?", leaseID).
		Updates(map[string]interface{}{
			"revoked_at": now,
			"updated_at": now,
		}).Error; err != nil {
		return nil, fmt.Errorf("pam: revoke pam_lease: %w", err)
	}
	lease.RevokedAt = &now
	lease.UpdatedAt = now
	if s.notifier != nil {
		if err := s.notifier.NotifyLeaseRevoked(ctx, &lease, reason); err != nil {
			log.Printf("pam: lease revoked notify failed: %v", err)
		}
	}
	return &lease, nil
}

// GetLease loads a single lease by ULID scoped to workspaceID.
func (s *PAMLeaseService) GetLease(ctx context.Context, workspaceID, leaseID string) (*models.PAMLease, error) {
	if workspaceID == "" {
		return nil, fmt.Errorf("%w: workspace_id is required", ErrValidation)
	}
	if leaseID == "" {
		return nil, fmt.Errorf("%w: lease_id is required", ErrValidation)
	}
	var lease models.PAMLease
	err := s.db.WithContext(ctx).
		Where("workspace_id = ? AND id = ?", workspaceID, leaseID).
		First(&lease).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("%w: %s", ErrLeaseNotFound, leaseID)
		}
		return nil, fmt.Errorf("pam: get pam_lease: %w", err)
	}
	return &lease, nil
}

// ListLeasesFilters narrows ListLeases without growing the method
// signature each release.
type ListLeasesFilters struct {
	UserID     string
	AssetID    string
	ActiveOnly bool
	Limit      int
	Offset     int
}

// ListLeases returns the pam_leases rows scoped to workspaceID
// matching the supplied filters. When ActiveOnly is true the result
// is filtered to leases that have been granted, not revoked, and
// not yet expired.
func (s *PAMLeaseService) ListLeases(ctx context.Context, workspaceID string, filters ListLeasesFilters) ([]models.PAMLease, error) {
	if workspaceID == "" {
		return nil, fmt.Errorf("%w: workspace_id is required", ErrValidation)
	}
	tx := s.db.WithContext(ctx).Where("workspace_id = ?", workspaceID)
	if filters.UserID != "" {
		tx = tx.Where("user_id = ?", filters.UserID)
	}
	if filters.AssetID != "" {
		tx = tx.Where("asset_id = ?", filters.AssetID)
	}
	if filters.ActiveOnly {
		tx = tx.Where("granted_at IS NOT NULL AND revoked_at IS NULL AND expires_at > ?", s.now().UTC())
	}
	if filters.Limit > 0 {
		tx = tx.Limit(filters.Limit)
	}
	if filters.Offset > 0 {
		tx = tx.Offset(filters.Offset)
	}
	var out []models.PAMLease
	if err := tx.Order("created_at desc").Find(&out).Error; err != nil {
		return nil, fmt.Errorf("pam: list pam_leases: %w", err)
	}
	return out, nil
}

// ListActiveLeases is a convenience over ListLeases that pins
// ActiveOnly=true.
func (s *PAMLeaseService) ListActiveLeases(ctx context.Context, workspaceID string) ([]models.PAMLease, error) {
	return s.ListLeases(ctx, workspaceID, ListLeasesFilters{ActiveOnly: true})
}

// ExpireLeases bulk-expires every lease whose expires_at has passed
// and which has not already been revoked. Returns the count of rows
// updated. The cron job calls this once per tick; the operation is
// idempotent so concurrent ticks do not double-count.
//
// Implementation: the bulk UPDATE sets RevokedAt=now on matching
// rows. A separate "expired" terminal state would be more precise
// but requires a column migration we defer to a follow-up — for
// now the revoked_at column doubles as the terminal-state marker
// for both the manual revoke + the expiry sweep.
func (s *PAMLeaseService) ExpireLeases(ctx context.Context) (int, error) {
	now := s.now().UTC()
	res := s.db.WithContext(ctx).
		Model(&models.PAMLease{}).
		Where("revoked_at IS NULL AND expires_at IS NOT NULL AND expires_at <= ?", now).
		Updates(map[string]interface{}{
			"revoked_at": now,
			"updated_at": now,
		})
	if res.Error != nil {
		return 0, fmt.Errorf("pam: expire pam_leases: %w", res.Error)
	}
	return int(res.RowsAffected), nil
}

// ExpiredLeases returns the leases that the next ExpireLeases tick
// would sweep. Exposed so the cron can drive per-lease notifications
// before flipping the state.
func (s *PAMLeaseService) ExpiredLeases(ctx context.Context, batchSize int) ([]models.PAMLease, error) {
	if batchSize <= 0 {
		batchSize = 100
	}
	now := s.now().UTC()
	var out []models.PAMLease
	if err := s.db.WithContext(ctx).
		Where("revoked_at IS NULL AND expires_at IS NOT NULL AND expires_at <= ?", now).
		Limit(batchSize).
		Find(&out).Error; err != nil {
		return nil, fmt.Errorf("pam: list expired pam_leases: %w", err)
	}
	return out, nil
}

// NotifyExpired is a convenience for the cron — fires
// NotifyLeaseExpired through the wired notifier (when present) for
// each lease in the supplied slice. Errors are logged + swallowed.
func (s *PAMLeaseService) NotifyExpired(ctx context.Context, leases []models.PAMLease) {
	if s.notifier == nil {
		return
	}
	for i := range leases {
		l := leases[i]
		if err := s.notifier.NotifyLeaseExpired(ctx, &l); err != nil {
			log.Printf("pam: lease expired notify failed for %s: %v", l.ID, err)
		}
	}
}
